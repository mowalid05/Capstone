"""
udp_detector.py - Slot B2 Capstone (Defensive Tool)

Scapy-based UDP rate anomaly detector with three independent patterns
(flood, spray, burst-rolling-average) tracked per source IP.

Designed to run inside the b2_detector container, which shares the
b2_target container's network namespace (network_mode: "service:target"
in docker-compose.yml) so that all unicast UDP arriving at the target
is visible on the sniffed interface.

Run example (inside container):
    python3 udp_detector.py \\
        --interface eth0 \\
        --flood-threshold 50 \\
        --port-threshold 20 \\
        --burst-multiplier 3 \\
        --window 30 \\
        --log /app/udp_alerts.log
"""

import argparse
import json
import signal
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Scapy is a hard dependency for sniffing, but we defer the failure so
# this module can still be imported (for unit tests / linting) on a host
# that doesn't have scapy installed.
try:
    from scapy.all import sniff, UDP, IP  # type: ignore
    _SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - only triggered outside Docker
    sniff = None  # type: ignore
    UDP = None  # type: ignore
    IP = None  # type: ignore
    _SCAPY_AVAILABLE = False


# How long (seconds) to silence repeat alerts for the same (src, pattern)
# pair so the log doesn't get spammed once a threshold is exceeded.
ALERT_COOLDOWN_S = 5.0

# SourceState entries with no traffic for this long are garbage-collected
# by the background GC thread (multi-threading justification).
STATE_TTL_S = 300.0

# Sniffer status heartbeat every N seconds (visible in docker logs).
HEARTBEAT_S = 10.0


# ======================================================================
# SECTION 1 - Sniffer, per-IP state, flood + spray detection
# ======================================================================

@dataclass
class SourceState:
    """
    Per-source-IP rolling state.

    `packets` is the authoritative sliding-window store: a deque of
    (timestamp, dport) tuples covering the last `args.window` seconds.
    Flood and spray checks derive everything from it. The burst detector
    uses a separate per-second BurstWindow because rolling-average math
    is cheaper on bucketed counts than on raw timestamps.
    """
    packets: deque = field(default_factory=deque)
    last_seen: float = 0.0
    burst_window: "BurstWindow | None" = None
    last_alert_ts: dict = field(default_factory=dict)  # pattern -> epoch


def is_whitelisted(src_ip: str, whitelist: set) -> bool:
    """Exact-match IP whitelist. CIDR support is a future enhancement."""
    return src_ip in whitelist


def update_state(state: SourceState, dport: int, now: float, args) -> None:
    """
    Append the new packet and evict anything older than the long window.

    Also forwards the (now, 1) tick to the per-source BurstWindow so the
    burst detector's per-second buckets stay in sync with the raw store.
    """
    state.packets.append((now, dport))

    cutoff = now - args.window
    while state.packets and state.packets[0][0] < cutoff:
        state.packets.popleft()

    state.last_seen = now

    if state.burst_window is not None:
        state.burst_window.add(now, 1)


def _now_iso() -> str:
    """ISO8601 UTC with millisecond precision (matches flooder stats log)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _should_emit(state: SourceState, pattern: str, now: float) -> bool:
    """Cooldown gate: only emit one alert per (src, pattern) per ALERT_COOLDOWN_S."""
    last = state.last_alert_ts.get(pattern, 0.0)
    if now - last < ALERT_COOLDOWN_S:
        return False
    state.last_alert_ts[pattern] = now
    return True


def packet_callback(pkt, state_table, args, alert_logger):
    """
    Scapy `prn` hook. Runs once per sniffed packet on the sniffer thread.

    Single-threaded by design: scapy.sniff() invokes prn serially, so
    state_table mutations need no lock. The background GC thread takes
    the same dict but only deletes idle keys, which dict tolerates here
    because we don't iterate-and-mutate concurrently.
    """
    if not _SCAPY_AVAILABLE:
        return
    if IP not in pkt or UDP not in pkt:
        return

    src = pkt[IP].src
    dport = int(pkt[UDP].dport)

    if is_whitelisted(src, args.whitelist):
        return

    now = time.time()

    state = state_table.get(src)
    if state is None:
        state = SourceState()
        state.burst_window = BurstWindow(args.window, args.burst_multiplier)
        state_table[src] = state

    update_state(state, dport, now, args)

    for check in (check_flood, check_spray, check_burst):
        fired, evidence = check(state, args)
        if not fired:
            continue
        pattern = check.__name__.replace("check_", "")
        if _should_emit(state, pattern, now):
            alert_logger.emit(src, pattern, evidence)


def start_sniffer(args, state_table, alert_logger) -> None:
    """
    Kick off scapy.sniff() with a BPF UDP filter so the kernel drops
    non-UDP traffic before we ever see it. `store=False` keeps memory
    flat regardless of how long the detector runs.
    """
    if not _SCAPY_AVAILABLE:
        raise RuntimeError(
            "scapy is required to run the detector. "
            "Install it inside the detector container (the docker-compose "
            "command already does `pip install scapy`)."
        )
    sniff(
        iface=args.interface,
        filter="udp",
        prn=lambda p: packet_callback(p, state_table, args, alert_logger),
        store=False,
    )


def check_flood(state: SourceState, args):
    """
    Flood: any (src, dport) pair averages more than `flood_threshold`
    packets/sec over the long window.

    Tally per-dport counts across the sliding store, divide by the window
    width to get pps, fire if any dport's pps clears the threshold.
    """
    counts = defaultdict(int)
    for _, dport in state.packets:
        counts[dport] += 1

    for dport, count in counts.items():
        pps = count / float(args.window)
        if pps > args.flood_threshold:
            return True, {
                "dport": dport,
                "measured_pps": round(pps, 2),
                "threshold_pps": args.flood_threshold,
                "window_s": args.window,
                "packets_in_window": count,
            }
    return False, {}


def check_spray(state: SourceState, args):
    """
    Spray: distinct destination ports observed within the window exceed
    `port_threshold`. This is the one detector that benefits directly
    from sliding-window eviction in update_state.
    """
    unique = {dport for _, dport in state.packets}
    n = len(unique)
    if n > args.port_threshold:
        return True, {
            "unique_dports": n,
            "threshold_unique_dports": args.port_threshold,
            "window_s": args.window,
        }
    return False, {}


# ======================================================================
# SECTION 2 - Burst rolling-average detector, CLI, alert logging
# ======================================================================

class BurstWindow:
    """
    Rolling-average burst detector.

    Maintains per-second buckets of packet counts spanning the long
    window. On each update:

        short_rate = sum(counts in last SHORT_S seconds) / SHORT_S
        long_rate  = sum(counts in window) / window_s
        fired      = short_rate > multiplier * max(long_rate, FLOOR_PPS)

    The FLOOR_PPS guard prevents cold-start divide-by-very-small noise
    where one stray packet during an otherwise-idle window would make
    long_rate ~0 and trip the detector on legitimate traffic.

    Why this catches burst-then-pause floods:
      - A naive per-second threshold misses bursts that average below it.
      - A rolling average over a 30s window also stays low (pauses bring
        the avg down). But the RATIO of short-window peak to long-window
        average stays high during bursts -> that ratio is what we watch.
    """

    SHORT_S = 2
    FLOOR_PPS = 1.0

    def __init__(self, window_s: int, multiplier: float):
        self.window_s = int(window_s)
        self.multiplier = float(multiplier)
        # Each bucket is a mutable [ts_int, count] so we can bump in place.
        self.buckets: deque = deque()

    def add(self, ts: float, count: int = 1) -> None:
        ts_int = int(ts)
        if self.buckets and self.buckets[-1][0] == ts_int:
            self.buckets[-1][1] += count
        else:
            self.buckets.append([ts_int, count])

        cutoff = ts_int - self.window_s
        while self.buckets and self.buckets[0][0] < cutoff:
            self.buckets.popleft()

    def short_rate(self) -> float:
        if not self.buckets:
            return 0.0
        latest = self.buckets[-1][0]
        cutoff = latest - self.SHORT_S + 1
        total = sum(c for t, c in self.buckets if t >= cutoff)
        return total / float(self.SHORT_S)

    def long_rate(self) -> float:
        if not self.buckets:
            return 0.0
        total = sum(c for _, c in self.buckets)
        return total / float(self.window_s)

    def fired(self):
        sr = self.short_rate()
        lr_raw = self.long_rate()
        lr = max(lr_raw, self.FLOOR_PPS)
        if sr > self.multiplier * lr:
            return True, {
                "short_rate_pps": round(sr, 2),
                "long_rate_pps": round(lr_raw, 2),
                "long_rate_floor_pps": self.FLOOR_PPS,
                "multiplier": self.multiplier,
                "threshold_pps": round(self.multiplier * lr, 2),
                "short_window_s": self.SHORT_S,
                "long_window_s": self.window_s,
            }
        return False, {}


def check_burst(state: SourceState, args):
    """
    Thin wrapper so packet_callback can iterate uniformly over the three
    check_* functions. The heavy lifting lives in BurstWindow.fired().
    """
    if state.burst_window is None:
        return False, {}
    return state.burst_window.fired()


def _parse_whitelist(raw: str) -> set:
    """argparse type for --whitelist: comma-separated IPs -> set[str]."""
    if not raw:
        return set()
    return {p.strip() for p in raw.split(",") if p.strip()}


def build_argparser() -> argparse.ArgumentParser:
    """All seven CLI flags from the deliverable, plus sensible defaults."""
    p = argparse.ArgumentParser(
        description="UDP rate anomaly detector (flood / spray / burst).",
    )
    p.add_argument("--interface", required=True,
                   help="Network interface to sniff (e.g. eth0).")
    p.add_argument("--flood-threshold", type=float, default=50.0,
                   help="Max avg packets/sec from one source to one "
                        "destination port over --window before flood fires "
                        "(default: 50).")
    p.add_argument("--port-threshold", type=int, default=20,
                   help="Max unique destination ports per source within "
                        "--window before spray fires (default: 20).")
    p.add_argument("--burst-multiplier", type=float, default=3.0,
                   help="Burst fires when short_rate > multiplier * "
                        "long_rate (default: 3.0).")
    p.add_argument("--window", type=int, default=30,
                   help="Long rolling-average window, seconds (default: 30).")
    p.add_argument("--whitelist", type=_parse_whitelist, default=set(),
                   help="Comma-separated source IPs to ignore "
                        "(e.g. the target's own IP if it echoes).")
    p.add_argument("--log", required=True, type=Path,
                   help="Path to the JSON-lines alert log.")
    return p


class JsonAlertLogger:
    """
    Append-only JSON-lines logger. Line-buffered + explicit flush so
    `tail -f` shows alerts the instant they fire, which matters for the
    live demo. A small lock makes emit() safe to call from any thread
    (the sniffer thread today, but cheap insurance if we add more).
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fp = open(self.path, "a", buffering=1, encoding="utf-8")
        self._lock = threading.Lock()

    def emit(self, src_ip: str, pattern: str, evidence: dict) -> None:
        measured, threshold = self._split_evidence(pattern, evidence)
        record = {
            "ts": _now_iso(),
            "src_ip": src_ip,
            "pattern": pattern,
            "measured": measured,
            "threshold": threshold,
            "evidence": evidence,
        }
        line = json.dumps(record, separators=(",", ":"))
        with self._lock:
            self._fp.write(line + "\n")
            self._fp.flush()

        # Echo to stderr so `docker logs b2_detector` shows alerts live
        # without needing a second tail pane.
        print(
            f"[ALERT] {record['ts']} src={src_ip} pattern={pattern} "
            f"measured={measured} threshold={threshold}",
            file=sys.stderr, flush=True,
        )

    @staticmethod
    def _split_evidence(pattern: str, evidence: dict):
        """
        Promote the most useful field to `measured` / `threshold` per
        pattern so consumers don't have to know each detector's schema.
        """
        if pattern == "flood":
            return (
                {"pps": evidence.get("measured_pps"),
                 "dport": evidence.get("dport")},
                {"pps": evidence.get("threshold_pps")},
            )
        if pattern == "spray":
            return (
                {"unique_dports": evidence.get("unique_dports")},
                {"unique_dports": evidence.get("threshold_unique_dports")},
            )
        if pattern == "burst":
            return (
                {"short_rate_pps": evidence.get("short_rate_pps"),
                 "long_rate_pps": evidence.get("long_rate_pps")},
                {"pps": evidence.get("threshold_pps"),
                 "multiplier": evidence.get("multiplier")},
            )
        return evidence, {}

    def close(self) -> None:
        try:
            self._fp.close()
        except Exception:
            pass


def baseline_tuner(state_table, args) -> dict:
    """
    Pre-demo helper: scan whatever state_table holds after a clean-traffic
    run and recommend threshold floors that won't false-positive.

    Recommended values pad the observed maxima with margin so normal
    fluctuation doesn't trip an alert.
    """
    flood_observed = 0.0
    spray_observed = 0
    burst_long_observed = 0.0

    for state in state_table.values():
        counts = defaultdict(int)
        for _, dport in state.packets:
            counts[dport] += 1
        for c in counts.values():
            pps = c / float(args.window)
            if pps > flood_observed:
                flood_observed = pps

        unique = {d for _, d in state.packets}
        if len(unique) > spray_observed:
            spray_observed = len(unique)

        if state.burst_window is not None:
            lr = state.burst_window.long_rate()
            if lr > burst_long_observed:
                burst_long_observed = lr

    return {
        "observed_max_flood_pps": round(flood_observed, 2),
        "observed_max_unique_dports": spray_observed,
        "observed_max_long_rate_pps": round(burst_long_observed, 2),
        "recommended_flood_threshold": round(flood_observed * 3.0 + 5.0, 2),
        "recommended_port_threshold": int(spray_observed * 3 + 5),
        "recommended_burst_floor_pps": round(
            max(burst_long_observed * 1.5, 1.0), 2
        ),
    }


# ======================================================================
# Background workers: GC + heartbeat (multi-threading justification)
# ======================================================================

def _state_gc_loop(state_table: dict, stop_event: threading.Event) -> None:
    """
    Periodically drop SourceState entries we haven't heard from in
    STATE_TTL_S seconds, otherwise the state_table grows unboundedly
    on a long-running detector (e.g. one spammer per probed source).
    """
    while not stop_event.wait(timeout=30.0):
        now = time.time()
        stale = [ip for ip, s in state_table.items()
                 if now - s.last_seen > STATE_TTL_S]
        for ip in stale:
            state_table.pop(ip, None)


def _heartbeat_loop(state_table: dict, stop_event: threading.Event) -> None:
    """
    Print a one-line status to stderr every HEARTBEAT_S seconds so the
    demo audience can tell the detector is alive even when no alerts
    are firing (a clean-baseline scenario should look quiet, not dead).
    """
    while not stop_event.wait(timeout=HEARTBEAT_S):
        tracked = len(state_table)
        total_pkts = sum(len(s.packets) for s in state_table.values())
        print(
            f"[detector] alive, tracking {tracked} source(s), "
            f"{total_pkts} packet(s) in active windows",
            file=sys.stderr, flush=True,
        )


# ======================================================================
# MAIN
# ======================================================================

def main():
    args = build_argparser().parse_args()
    alert_logger = JsonAlertLogger(args.log)
    state_table: dict = {}

    stop_event = threading.Event()
    workers = [
        threading.Thread(target=_state_gc_loop,
                         args=(state_table, stop_event),
                         name="state-gc", daemon=True),
        threading.Thread(target=_heartbeat_loop,
                         args=(state_table, stop_event),
                         name="heartbeat", daemon=True),
    ]
    for t in workers:
        t.start()

    def _shutdown(*_):
        stop_event.set()
        alert_logger.close()
        print("\n[detector] shutdown signal received, exiting.",
              file=sys.stderr, flush=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    whitelist_repr = (
        ",".join(sorted(args.whitelist)) if args.whitelist else "(none)"
    )
    print(
        f"[detector] sniffing iface={args.interface} window={args.window}s "
        f"flood>{args.flood_threshold}pps spray>{args.port_threshold}ports "
        f"burst>{args.burst_multiplier}x avg | whitelist={whitelist_repr} "
        f"| alerts -> {args.log}",
        file=sys.stderr, flush=True,
    )

    try:
        start_sniffer(args, state_table, alert_logger)
    finally:
        stop_event.set()
        alert_logger.close()


if __name__ == "__main__":
    main()
