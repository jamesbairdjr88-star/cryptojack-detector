# Cryptojacking Detector

A host-based tool that detects **unauthorized crypto miners** (cryptojacking) on a
machine you own or are authorized to monitor. It is **read-only** — it scores and
reports suspicious processes and persistence entries; it never kills anything.
A human decides what to do.

This is the defender's side of crypto mining: the skill security teams actually hire for.

## Results

On a labeled adversarial test set (miners including a throttled miner and an
off-CPU GPU-style miner, plus benign look-alikes): **Precision 1.00 / Recall 1.00 / F1 1.00**.
`test_detector.py` reproduces a green run (exit code 0) on any 2+ core Linux box.

## How it works

It combines several independent signals and scores by *strength*, not just count.
**Strong** signals (a miner name/arg signature, a mining-pool connection) are specific
to miners; **weak** signals (sustained CPU, suspicious path, GPU compute) are tripped by
legitimate software too. A finding is escalated to **HIGH** only when a strong signal is
present — two weak signals alone never escalate. That single rule is what keeps false
positives near zero.

Signals implemented:

- Sustained CPU with an **adaptive, contention-aware floor** (no magic threshold; scales with core count and load)
- Known miner **name / argument signatures**
- **Mining-pool** port connections
- **Suspicious binary paths** (`/tmp`, `/dev/shm`, `/var/tmp`, hidden dot-binaries)
- **GPU compute** via `nvidia-smi pmon` (catches off-CPU GPU miners)
- **Persistence enumeration** (cron, systemd, desktop autostart, shell rc)
- **Trusted-app allowlist** (compilers, ffmpeg, node, ...) — only when run from a trusted install dir

## Quickstart

```bash
pip install -r requirements.txt      # psutil
python cryptojack_detect.py          # one-shot scan, prints a ranked table
python test_detector.py              # reproducible eval: asserts P/R/F1 == 1.00
```

Continuous monitoring with rate-limited alerts:

```python
import cryptojack_detect as cj
# scan on a loop; each distinct finding alerts at most once per `cooldown`
cj.run_daemon(interval=60, cooldown=3600, webhook_url="https://hooks.slack.com/...")
```

Output formats: ranked table, JSON Lines (for a SIEM), syslog-style line, and a
Slack/PagerDuty-shaped webhook (HIGH-only by default, tunable).

## Files

- `cryptojack_detect.py` — the detector: collectors, scoring engine, output/alerting, and the daemon
- `test_detector.py` — reproducible precision/recall harness (spawns a labeled process set)
- `SPEC.md` — full project spec: design, phased build, evaluations, and two debugging write-ups
- `requirements.txt`, `LICENSE`

## Engineering highlights (for reviewers)

Two debugging stories are written up in `SPEC.md`:

1. **Load-dependent CPU threshold.** Recall dropped to 0.33 on a 2-core box because a
   fixed 70%-of-one-core threshold missed miners that were throttled by contention.
   Root-caused by instrumenting the sampler, then replaced with an adaptive fair-share
   floor → recall recovered to 1.00 with precision held at 1.00.
2. **Silent-sensor bug.** The GPU collector swallowed `FileNotFoundError` / exec errors,
   so a *broken* sensor looked identical to "no GPU present." Fixed to fail loudly with a
   `CRYPTOJACK_NVIDIA_SMI` override. A security sensor that fails silently is worse than
   one that fails loudly.

## Scope & ethics

Run this only on systems you own or are authorized to monitor. It is read-only by
design: it reports and scores, and never terminates processes or edits configuration.

## License

MIT — see `LICENSE`.
