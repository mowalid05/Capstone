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


def is_whitelisted(src_ip: str, whitelist: set) -> bool:
    """Owner: D1. Exact-match for v1; consider CIDR later if needed."""
    raise NotImplementedError("D1: implement.")


def update_state(state: SourceState, dport: int, now: float, args) -> None:
    """
    Owner: D1.

    1. state.packets_per_dport[dport] += 1
    2. state.unique_dports.add(dport)
    3. Append (int(now), 1) to per_second_counts, or bump the tail
       if the last tuple is for the same second.
    4. Evict entries older than args.window seconds from all three
       structures (this is what makes them sliding-window).
    5. state.last_seen = now
    """
    raise NotImplementedError("D1: implement.")


def packet_callback(pkt, state_table, args, alert_logger):
    """
    Scapy `prn` hook. Owner: D1.

    1. If not (IP in pkt and UDP in pkt): return.
    2. src = pkt[IP].src ; dport = pkt[UDP].dport
    3. If is_whitelisted(src, args.whitelist): return.
    4. state = state_table[src] (create if missing; attach D2 BurstWindow).
    5. update_state(state, dport, now, args)
    6. For check in (check_flood, check_spray, check_burst):
           fired, evidence = check(state, args)
           if fired: alert_logger.emit(src, check.__name__, evidence)
    """
    raise NotImplementedError("D1: implement.")


def start_sniffer(args, state_table, alert_logger) -> None:
    """
    Run scapy.sniff() on args.interface. Owner: D1.

    BPF filter: "udp" — cheap and avoids parsing non-UDP traffic.
    Pass `store=False` so memory doesn't grow.
    """
    raise NotImplementedError("D1: implement.")


def check_flood(state: SourceState, args) -> tuple[bool, dict]:
    """
    Flood: any (src, dport) pair exceeds args.flood_threshold packets
    per second on average over the window. Owner: D1.

    Returns (fired, evidence). evidence has the schema
    JsonAlertLogger expects in `measured` and `threshold`.
    """
    raise NotImplementedError("D1: implement.")


def check_spray(state: SourceState, args) -> tuple[bool, dict]:
    """
    Spray: |state.unique_dports| exceeds args.port_threshold within
    args.window seconds. Owner: D1.
    """
    raise NotImplementedError("D1: implement.")


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
    """
    Integration glue. Owner: D1.

    Steps:
      1. parser = build_argparser(); args = parser.parse_args()      (D2)
      2. logger = JsonAlertLogger(args.log)                           (D2)
      3. state_table: dict[str, SourceState] = {}                     (D1)
      4. start_sniffer(args, state_table, logger)                     (D1)
      5. On SIGINT: logger.close().

    Note: SourceState entries lazily attach a BurstWindow on first
    packet via packet_callback. Keep it that way so D2's class stays
    self-contained.
    """
    raise NotImplementedError("D1: wire main().")


if __name__ == "__main__":
    main()
