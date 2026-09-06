# Cryptojacking Detector

[![CI](https://github.com/jamesbairdjr88-star/cryptojack-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/jamesbairdjr88-star/cryptojack-detector/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A host-based tool that detects **unauthorized crypto miners** (cryptojacking) on a
machine you own or are authorized to monitor. It is **read-only** — it scores and
reports suspicious processes and persistence entries; it never kills anything.
A human decides what to do.

This is the defender's side of crypto mining: the skill security teams actually hire for.

## Results

On a labeled adversarial test set (miners including a throttled miner and an
off-CPU GPU-style miner, plus benign look-alikes): **Precision 1.00 / Recall 1.00 / F1 1.00**.
`test_detector.py` reproduces a green run (exit code 0) on any 2+ core Linux box.

## Install

```bash
pip install .                 # from a clone; installs the `cryptojack-detect` command
# or run without installing:
pip install -r requirements.txt
python cryptojack_detect.py --help
```

Requires Python 3.8+ and `psutil`. The optional GPU signal uses `nvidia-smi` if present.

## Usage

```bash
cryptojack-detect scan                 # one scan; ranked table of suspects
cryptojack-detect scan --json          # JSON Lines (for a SIEM)
cryptojack-detect scan --log           # syslog-style lines
cryptojack-detect scan --persistence   # also enumerate autostart entries
cryptojack-detect persistence          # scan cron/systemd/autostart/rc only
cryptojack-detect watch                # run continuously as a rate-limited daemon
cryptojack-detect --version
```

**Alerting.** Any command that produces findings can POST them to a webhook
(Slack/PagerDuty/generic), HIGH-only by default:

```bash
cryptojack-detect scan  --webhook https://hooks.slack.com/services/XXX
cryptojack-detect watch --webhook https://hooks.slack.com/services/XXX --interval 300 --cooldown 3600
```

**Exit codes** (so it drops into cron / CI / monitoring):

| Code | Meaning |
|------|---------|
| `0`  | no HIGH findings (clean) |
| `1`  | at least one HIGH finding — a likely miner |
| `2`  | usage error |

Use `scan --exit-zero` if you want alerts via webhook but always a 0 exit.

**Tuning.** `--windows` / `--window-seconds` control CPU sampling; `--nvidia-smi PATH`
(or the `CRYPTOJACK_NVIDIA_SMI` env var) points at a non-standard `nvidia-smi`.

## Run it as a service

A hardened systemd unit is included:

```bash
sudo cp deploy/cryptojack-detect.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cryptojack-detect
journalctl -u cryptojack-detect -f      # watch alerts
```

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

## Files

- `cryptojack_detect.py` — the detector + CLI: collectors, scoring engine, output/alerting, daemon
- `test_detector.py` — reproducible precision/recall harness (spawns a labeled process set)
- `SPEC.md` — full project spec: design, phased build, evaluations, and two debugging write-ups
- `pyproject.toml` — packaging; installs the `cryptojack-detect` command
- `deploy/cryptojack-detect.service` — hardened systemd unit for the daemon
- `requirements.txt`, `LICENSE`, `.gitignore`

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
