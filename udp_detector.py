"""
udp_detector.py — Slot B2 Capstone (Defensive Tool)

Scapy-based UDP rate anomaly detector with three independent patterns
(flood, spray, burst-rolling-average) tracked per source IP.

OWNERSHIP — DEFENSIVE TEAM (2 members)
======================================
D1 — Sniffer / Per-IP state / Flood + Spray detection
    SourceState, packet_callback, start_sniffer,
    check_flood, check_spray, is_whitelisted,
    main() wiring

D2 — Burst rolling-average / CLI / Alert logging / Baseline tuning
    BurstWindow, check_burst, build_argparser,
    JsonAlertLogger, baseline_tuner

Integration owner: D1 (wires main()).
Cross-team liaison with flooder team: D2.
"""

import argparse
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# scapy is installed by the detector container at start (see docker-compose.yml).
from scapy.all import sniff, UDP, IP


# ======================================================================
# SECTION 1 — Sniffer, per-IP state, flood + spray     (Owner: D1)
# ======================================================================

@dataclass
class SourceState:
    """
    Per-source-IP rolling state. Owner: D1.

    - packets_per_dport: count of packets to each destination port
                         within the current sliding window (flood signal)
    - unique_dports:     set of destination ports seen in the window
                         (spray signal)
    - per_second_counts: deque[(epoch_second_int, count)]
                         — fed into D2's BurstWindow
    - last_seen:         epoch seconds, for state expiry / GC
    """
    packets_per_dport: dict = field(
        default_factory=lambda: defaultdict(int)
    )
    unique_dports: set = field(default_factory=set)
    per_second_counts: deque = field(default_factory=deque)
    last_seen: float = 0.0
    # Hold the D2 BurstWindow instance once D2 wires it in:
    burst_window: object = None
    # D1 addition: per-packet log for accurate sliding-window eviction
    packet_log: deque = field(default_factory=deque)  # stores (timestamp, dport)


def is_whitelisted(src_ip: str, whitelist: set) -> bool:
    """Owner: D1. Exact-match for v1; consider CIDR later if needed."""
    return src_ip in whitelist


def update_state(state: SourceState, dport: int, now: float, args) -> None:
    """Owner: D1."""

    # Log this packet with its timestamp
    state.packet_log.append((now, dport))

    # Evict packets outside the sliding window
    cutoff = now - args.window
    while state.packet_log and state.packet_log[0][0] < cutoff:
        state.packet_log.popleft()

    # Rebuild packets_per_dport and unique_dports from what remains in window
    state.packets_per_dport = defaultdict(int)
    state.unique_dports = set()
    for ts, dp in state.packet_log:
        state.packets_per_dport[dp] += 1
        state.unique_dports.add(dp)

    # Update per_second_counts (used by D2's BurstWindow)
    second = int(now)
    if state.per_second_counts and state.per_second_counts[-1][0] == second:
        # tuples are immutable — pop and re-append with bumped count
        ts, cnt = state.per_second_counts.pop()
        state.per_second_counts.append((ts, cnt + 1))
    else:
        state.per_second_counts.append((second, 1))

    # Evict old seconds from per_second_counts
    while state.per_second_counts and state.per_second_counts[0][0] < cutoff:
        state.per_second_counts.popleft()

    # Update last_seen
    state.last_seen = now


def packet_callback(pkt, state_table, args, alert_logger):
    """Scapy prn hook. Owner: D1."""

    # Only process IP/UDP packets
    if not (IP in pkt and UDP in pkt):
        return

    src   = pkt[IP].src
    dport = pkt[UDP].dport
    now   = time.time()

    # Skip whitelisted IPs
    if is_whitelisted(src, args.whitelist):
        return

    # Create state entry on first packet from this source
    if src not in state_table:
        state_table[src] = SourceState()
        # Attach D2's BurstWindow (guarded so code works before D2 merges)
        try:
            state_table[src].burst_window = BurstWindow(
                args.window, args.burst_multiplier
            )
        except Exception:
            pass

    state = state_table[src]

    # Update sliding-window state
    update_state(state, dport, now, args)

    # Feed the BurstWindow if it exists
    if state.burst_window is not None:
        try:
            state.burst_window.add(now)
        except Exception:
            pass

    # Run all three detectors; emit alert on any hit
    for check in (check_flood, check_spray, check_burst):
        try:
            fired, evidence = check(state, args)
            if fired:
                alert_logger.emit(src, check.__name__, evidence)
        except NotImplementedError:
            pass  # D2's check_burst not done yet — skip gracefully


def start_sniffer(args, state_table, alert_logger) -> None:
    """Run scapy.sniff() on args.interface. Owner: D1."""
    print(f"[*] Sniffing UDP on interface '{args.interface}' — Ctrl+C to stop.")
    sniff(
        iface=args.interface,
        filter="udp",
        prn=lambda pkt: packet_callback(pkt, state_table, args, alert_logger),
        store=False,
    )


def check_flood(state: SourceState, args) -> tuple[bool, dict]:
    """Owner: D1. Fires if any single port's avg rate exceeds threshold."""
    for dport, count in state.packets_per_dport.items():
        rate = count / args.window
        if rate > args.flood_threshold:
            return True, {
                "dport": dport,
                "measured": round(rate, 2),
                "threshold": args.flood_threshold,
            }
    return False, {}


def check_spray(state: SourceState, args) -> tuple[bool, dict]:
    """Owner: D1. Fires if unique port count exceeds threshold in window."""
    unique_count = len(state.unique_dports)
    if unique_count > args.port_threshold:
        return True, {
            "measured": unique_count,
            "threshold": args.port_threshold,
        }
    return False, {}


# ======================================================================
# SECTION 2 — Burst rolling-average, CLI, alerts        (Owner: D2)
# ======================================================================

class BurstWindow:
    """
    Rolling-average burst detector. Owner: D2.

    Maintains a deque of (timestamp, packet_count) tuples spanning the
    long window. On every update it computes:

        short_rate = sum(counts in last SHORT_S seconds)     / SHORT_S
        long_rate  = sum(counts in last args.window seconds) / args.window

    Fires when short_rate > multiplier * max(long_rate, FLOOR).
    FLOOR avoids cold-start divide-by-zero false-positives.

    This is the detector that MUST catch the flooder's --mode burst
    behaviour — see the deliverable's integration point #1.
    """

    SHORT_S = 2     # short-window seconds; tune in baseline phase
    FLOOR_PPS = 1.0  # min long_rate denominator; tune in baseline phase

    def __init__(self, window_s: int, multiplier: float):
        raise NotImplementedError("D2: implement.")

    def add(self, ts: float, count: int = 1) -> None:
        """Append/merge (ts, count); evict entries older than window_s."""
        raise NotImplementedError("D2: implement.")

    def short_rate(self) -> float:
        raise NotImplementedError("D2: implement.")

    def long_rate(self) -> float:
        raise NotImplementedError("D2: implement.")

    def fired(self) -> tuple[bool, dict]:
        """
        Return (True, {"short_rate": ..., "long_rate": ...,
                       "multiplier": ...}) on hit, else (False, {}).
        """
        raise NotImplementedError("D2: implement.")


def check_burst(state: SourceState, args) -> tuple[bool, dict]:
    """
    Owner: D2. Reads from state.burst_window (D1 attached it).
    Returns (fired, evidence).
    """
    raise NotImplementedError("D2: implement.")


def build_argparser() -> argparse.ArgumentParser:
    """
    CLI flags from the deliverable. Owner: D2.

    Required: --interface --flood-threshold --port-threshold
              --burst-multiplier --window --whitelist --log
    --whitelist accepts a comma-separated list of IPs.
    """
    raise NotImplementedError("D2: implement.")


class JsonAlertLogger:
    """
    Append-only JSON-lines alert logger. Owner: D2.

    Record schema (one line per alert):
      {"ts": <ISO8601>, "src_ip": "...", "pattern": "flood|spray|burst",
       "measured": <number or object>, "threshold": <number or object>}
    """

    def __init__(self, path: Path):
        raise NotImplementedError("D2: implement.")

    def emit(self, src_ip: str, pattern: str, evidence: dict) -> None:
        """
        Pull `measured` and `threshold` out of `evidence` (the dict
        produced by check_flood/check_spray/check_burst) and write
        one JSON line + flush.
        """
        raise NotImplementedError("D2: implement.")

    def close(self) -> None:
        raise NotImplementedError("D2: implement.")


def baseline_tuner(state_table, args) -> dict:
    """
    Owner: D2.

    Run before the live demo against a clean-baseline trace (echo server
    plus an occasional benign client) and emit recommended floor values
    for --flood-threshold, --port-threshold, and BurstWindow.FLOOR_PPS
    so we don't false-positive in front of the examiner.

    Returns a dict you can paste into demo prep notes.
    """
    raise NotImplementedError("D2: implement.")


# ======================================================================
# MAIN                                                  (Owner: D1)
# ======================================================================

def main():
    """Integration glue. Owner: D1."""
    import signal

    # Step 1 — parse CLI (D2 provides build_argparser)
    parser = build_argparser()
    args = parser.parse_args()

    # Convert whitelist comma-separated string → set
    args.whitelist = set(args.whitelist.split(",")) if args.whitelist else set()

    # Step 2 — create alert logger (D2 provides JsonAlertLogger)
    logger = JsonAlertLogger(args.log)

    # Step 3 — empty per-source state table
    state_table: dict[str, SourceState] = {}

    # Step 4 — handle Ctrl+C cleanly
    def _shutdown(sig, frame):
        print("\n[*] Shutting down — closing log.")
        logger.close()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _shutdown)

    # Step 5 — start sniffing (blocks until Ctrl+C)
    start_sniffer(args, state_table, logger)


if __name__ == "__main__":
    main()
