# Slot B2 — Task Assignments

Five members, split **3 offensive + 2 defensive**. Owners are placeholders (A1–A3, D1–D2); replace with real names before kickoff.

## Why this split

The attack tool has three independent modes plus the echo server — that splits naturally three ways with low coupling. The detector has three detectors but they share the sniffer, state table, and alert path; two tight collaborators ship that faster than three. Both teams have comparable depth, which the rubric requires (Shared Requirement #8).

If the strongest devs are on the defensive side, flip to 2 offensive + 3 defensive by moving A2's burst-mode work onto A1 (it already piggybacks on flood mode) and splitting D2 into "burst" and "CLI + logging + baseline."

---

## Offensive team — `udp_flooder.py` + `udp_echo_server.py`

### A1 — Core sender, threading, flood mode, main()
- `ThreadStats`, `send_udp_packet`, `rate_limit_sleep`
- `sender_worker` — the worker loop everyone else's modes plug into
- `run_flood_mode`
- `main()` wiring (calls A3's argparser, A3's logger, then dispatches)
- **Owns integration this week.** Everyone else's code lands in branches that A1 merges.

### A2 — Spray mode, burst mode, scheduling
- `pick_random_port`, `run_spray_mode`
- `BurstScheduler` (on/off envelope — this is the evasion the rubric grades)
- `run_burst_mode`
- Decide whether burst wraps flood only or also spray; document in the report.

### A3 — Evasion, CLI, JSON stats, echo server
- `random_payload`, `choose_source_port` (the other half of evasion)
- `build_argparser` (all 10 flags from the deliverable)
- `JsonStatsLogger`, `write_stats_snapshot` + the 1-second reporter thread
- **Owns `udp_echo_server.py` end-to-end.**
- **Cross-team liaison with detector team** — make sure stats log timestamps match alert log timestamps so the report timeline lines up.

---

## Defensive team — `udp_detector.py`

### D1 — Sniffer, per-IP state, flood + spray, main()
- `SourceState`, `is_whitelisted`, `update_state`
- `packet_callback`, `start_sniffer`
- `check_flood`, `check_spray`
- `main()` wiring
- **Owns integration this week.**

### D2 — Burst rolling-average, CLI, alerts, baseline
- `BurstWindow` (this is the rubric's centerpiece — rolling-average detection)
- `check_burst`
- `build_argparser` (all 7 flags from the deliverable)
- `JsonAlertLogger`
- `baseline_tuner` — run before demo against clean traffic, lock in thresholds
- **Cross-team liaison with flooder team** — coordinate with A3 on timestamp formats and on demo timing so burst-on / burst-off durations beat the per-second flood threshold.

---

## Integration points (read these before writing code)

1. **`A3` and `D2`: agree on timestamp format.** ISO8601 UTC with millisecond precision in both logs. The report needs a timeline that interleaves stats lines with alert lines.
2. **`A2` and `D2`: agree on burst parameters.** A2's `--burst-on` / `--burst-off` and the rate during bursts must be chosen so that:
   - per-second average < `--flood-threshold` (so flood detector misses it)
   - peak during burst > `multiplier × long-window average` (so burst detector catches it)
   Default suggestion: `--burst-on 3 --burst-off 5 --rate 100` against `--flood-threshold 50 --burst-multiplier 3 --window 30`. Tune in the baseline phase.
3. **`A1` and `D1`: agree on the demo script.** One terminal per container: detector first (logs visible), then attacker, then a third pane tailing both logs side by side.

---

## Suggested week-by-week split

| Period | A1 | A2 | A3 | D1 | D2 |
|---|---|---|---|---|---|
| Days 1–2 | Repo + Docker sanity check | Read RFC 768 + sniff own traffic with tcpdump | Echo server + argparser skeleton | Scapy hello-world on `eth0` | BurstWindow design doc (one page) |
| Days 3–5 | flood mode + worker loop | spray mode + BurstScheduler | random_payload + JsonStatsLogger + reporter thread | packet_callback + state + flood/spray checks | BurstWindow + check_burst + alert logger |
| Days 6–8 | burst mode integration with A2 | Tune burst params with D2 | Wire `main()` with A1 | Wire `main()` + whitelist | baseline_tuner against clean traffic |
| Before May 29 | Demo rehearsal #1, #2, #3 — everyone | | | | |

---

## Submission checklist (from the deliverable)

Code package due Friday, May 29, 2026:

- [ ] `udp_flooder.py`
- [ ] `udp_echo_server.py`
- [ ] `udp_detector.py`
- [ ] `docker-compose.yml` (already provided — don't change subnet)
- [ ] `README.md`
- [ ] Sample JSON log files (one stats log, one alert log, both from a clean run + a burst run)
- [ ] Presentation slides (PDF or PPTX)

Demo & presentation: Monday, June 1, 2026.
Final technical report: Thursday, June 4, 2026.
