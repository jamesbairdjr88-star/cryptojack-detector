# Cryptojacking Detector — Project Spec

A buildable cybersecurity project: a host-based tool that detects **unauthorized crypto miners** (cryptojacking) running on a machine. This is the career-relevant flip side of mining — defenders get paid to find this, and it's strong portfolio/résumé material for a cybersecurity path.

**Scope guardrail:** this runs only on machines **you own or are authorized to monitor**. It is read-only — it reports and scores; it never kills processes. A human decides what to do.

**Status:** Complete. All four phases plus the continuous daemon are built and tested — adaptive CPU floor, trusted-app allowlist, strength-weighted scoring, GPU sensor, persistence enumeration, JSON/syslog/webhook alerting, and a rate-limited monitoring loop. Adversarial eval: **Precision 1.00 / Recall 1.00 / F1 1.00** (3 miners incl. throttled + GPU, 3 benign look-alikes).

---

## What cryptojacking looks like (the signals to detect)

A hidden miner has a recognizable fingerprint. Good detection combines several weak signals into one strong verdict — no single signal is trustworthy alone.

| # | Signal | Why it indicates mining | Weakness (false positives) |
|---|--------|------------------------|----------------------------|
| 1 | **Sustained high CPU/GPU** | Mining pins a core near 100% for long stretches | Video encoding, compiling, games, science apps also do this |
| 2 | **Known miner signatures** | Names/args like `xmrig`, `minerd`, `--stratum`, `randomx` | Easily renamed; also matches text *about* miners (like this doc) |
| 3 | **Mining-pool connections** | Outbound to stratum ports (3333, 4444, 5555, 14444...) or known pool domains | Ports can be changed; needs a current pool list |
| 4 | **Runs from odd locations** | Malware hides in `/tmp`, `%TEMP%`, browser cache, hidden dirs | Some legit tools use temp dirs |
| 5 | **Persistence** | Cron jobs, systemd units, scheduled tasks, autostart entries that relaunch it | Lots of legit software persists too |
| 6 | **Throttle-and-hide behavior** | Some miners drop CPU when you open Task Manager / move the mouse | Harder to measure; advanced |
| 7 | **Browser-based (drive-by)** | A tab pegs CPU via WebAssembly (Coinhive-style) | Detected differently — per-tab, not per-process |

**Core design principle:** score, don't accuse. Weight each signal *by strength* and flag by band (LOW / MED / HIGH). A **strong** signal (miner signature or pool connection) plus corroboration escalates to HIGH; two **weak** signals alone (CPU, suspicious path) never do — that's what kills false positives. See the Adversarial evaluation for why signal *strength*, not just count, is the right rule.

---

## Architecture

```
+------------------+     +------------------+     +------------------+
|  Collectors      | --> |  Scoring engine  | --> |  Reporter        |
|  (gather signals)|     |  (weight + sum)  |     |  (rank, alert)   |
+------------------+     +------------------+     +------------------+
   process CPU              per-process             ranked table
   process name/path        risk score              JSON / log line
   network connections      + reasons               optional webhook
   binary path
```

- **Collectors** — one function per signal, each returns evidence for a process. Keep them independent so you can add/remove signals easily.
- **Scoring engine** — turns evidence into a number with human-readable *reasons*. Reasons matter as much as the score; an alert nobody can interpret gets ignored.
- **Reporter** — ranks findings, prints a table, and (optionally) emits JSON for a SIEM or a webhook alert.

---

## Signals and scoring (as implemented)

Each collector is independent and returns evidence for a process; the scoring engine fires a named signal per piece of evidence, sums a risk score, and classifies the band.

```python
STRONG_SIGNALS = {"signature", "pool"}   # specific to miners
WEAK_SIGNALS   = {"cpu", "path", "gpu"}  # ambiguous - ML/games/transcode also use GPU

def classify(fired):
    """HIGH needs a strong signal, not just two weak ones."""
    strong = len(fired & STRONG_SIGNALS); total = len(fired)
    if strong >= 2 or (strong >= 1 and total >= 2):
        return "HIGH"
    return "MED"
```

Signal collectors implemented in `cryptojack_detect.py`:

- **Sustained CPU** — multi-sample (hot in >=3 of 4 windows) against an **adaptive floor** (below), not a fixed threshold. Weak.
- **Miner signature** — executable name/basename against a miner list, plus a small set of distinctive command-line arg tokens (`stratum+tcp`, `--randomx`, ...). Strong.
- **Mining-pool connection** — an outbound connection whose remote port is a known stratum port. Strong.
- **Suspicious path** — executable under `/tmp`, `/dev/shm`, `/var/tmp`, or a hidden dot-binary. Weak.
- **GPU compute** — per-process GPU utilization from `nvidia-smi pmon`. Weak.

Two anti-false-positive rules from the first prototype: match on the executable **name/path** (not the whole command line, which can contain text *about* miners), and **self-exclude** the detector's own process tree.

### Adaptive, contention-aware CPU floor

A miner consumes as much CPU as it can *get*, so the right bar is a fraction of each process's fair share of the cores — it shrinks under load and grows on an idle or many-core box, so there is no machine-specific magic number:

```python
FLOOR_MAX  = 70.0   # cap: on an idle box a miner nearly maxes one core
FLOOR_FRAC = 0.75   # a miner sits near its fair share; flag at 75% of it
ACTIVE_MIN = 20.0   # a process "competes for CPU" above this

def adaptive_floor(n_active, cores):
    fair_share = cores * 100.0 / max(1, n_active)   # % of one core each active proc can get
    return min(FLOOR_MAX, FLOOR_FRAC * fair_share)
```

### Trusted-app allowlist

Compute-heavy programs (ffmpeg, compilers, Blender, node) trip the CPU signal legitimately. They are allowlisted — but **only** when they run from a trusted install directory, so a fake `ffmpeg` in `/tmp` or one talking to a pool is still caught by the other signals:

```python
ALLOWLIST_NAMES = {"ffmpeg","x264","x265","handbrakecli","blender",
    "gcc","cc1","cc1plus","clang","make","cargo","rustc","node","java","dockerd"}
TRUSTED_DIRS = ("/usr/bin/","/usr/local/bin/","/bin/","/opt/","/usr/lib/")
```

---

## Evaluation — measuring precision & recall

A demo that catches one planted miner proves nothing about the false-alarm rate. The harness (`test_detector.py`) spawns a **labeled** set of processes, runs `scan()`, and scores the result as a confusion matrix. **Precision** = TP/(TP+FP) (how many HIGH alerts were real). **Recall** = TP/(TP+FN) (how many real miners we caught). **F1** = harmonic mean.

### A real bug the harness surfaced

The first eval scored **Precision 1.00 / Recall 0.33** — two of three miners slipped through. Root cause, confirmed by instrumenting the sampler: the test box has **2 cores**, and four CPU-hungry processes each got throttled to ~50% of a core — below the then-fixed 70%-of-one-core threshold. The CPU signal fired for *nobody*, so the two miners that needed CPU as their second signal dropped to a single signal.

**The insight:** a fixed "70% of one core" threshold is load-dependent. A miner consumes as much CPU as it can get; under contention that is its fair share, not 100%. The fix is the **adaptive floor** above — recall recovered to 1.00 with precision held at 1.00.

This build -> measure -> find-failure -> root-cause -> fix -> re-measure loop is the single most valuable thing to talk through in an interview.

---

## Adversarial evaluation (robustness)

The first eval used easy cases. A real test throws evasion and look-alikes at the detector: a **throttled** miner (drops CPU to hide), a **GPU-style** miner (mines off-CPU, so CPU stays low), a legitimate build tool running from `/tmp`, and a dev server on port 8888.

### Round 1 — exposed

```
Precision=0.50  Recall=0.67  F1=0.57
```

Two separate failures: precision collapsed because two *weak* signals (CPU + suspicious-path) were treated as enough, flagging the legit `/tmp` build; and 8888 was wrongly in the pool-port list, flagging the dev server. Recall lagged because the GPU miner tripped only one signal.

### The fix — rank signals by strength, trim the port list

The `classify()` rule above (HIGH requires a strong signal, never just two weak ones) plus removing 7777/8888/9999 from the pool-port set recovered **Precision 1.00 / Recall 0.67**: both false positives dropped to MED, and throttling stopped being an escape (a throttled miner still shows its signature and path). The one remaining miss was the off-CPU GPU miner — closed by the GPU sensor below.

---

## GPU sensor + persistence enumeration

**1. GPU sensor (closes the recall gap).** Serious miners run on the GPU, keeping CPU low. The collector parses per-process GPU compute % from `nvidia-smi pmon`; GPU is a *weak* signal, so it escalates only alongside a strong one:

```python
GPU_SM_HIGH = 30   # per-process GPU compute utilization % considered "busy"

def gpu_busy_pids(sm_threshold=GPU_SM_HIGH):
    """Parse `nvidia-smi pmon -c 1` for per-process GPU compute %. Empty if no GPU."""
    try:
        binary = os.environ.get("CRYPTOJACK_NVIDIA_SMI", "nvidia-smi")
        out = subprocess.run([binary,"pmon","-c","1"], capture_output=True, text=True, timeout=5).stdout
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return {}   # no GPU / no nvidia-smi -> signal simply doesn't fire
    ...
```

With the GPU sensor live, the off-CPU GPU miner is caught (pool *strong* + GPU *weak* -> HIGH) and the adversarial set reaches **Precision 1.00 / Recall 1.00 / F1 1.00**.

> Field note: demoed with a stand-in `nvidia-smi` (the sandbox has no GPU). Getting there surfaced a genuine plumbing bug — the collector silently swallowed `FileNotFoundError` / exec errors, so a broken sensor looked identical to "no GPU present." The fix added an explicit `CRYPTOJACK_NVIDIA_SMI` override. Lesson: a security sensor that fails **silently** is worse than one that fails loudly — in production the GPU collector should log when `nvidia-smi` is expected but unreachable.

**2. Persistence enumeration.** Miners re-launch themselves after a kill or reboot via cron, systemd, desktop autostart, or shell rc files. `scan_persistence()` reads those autostart vectors and flags any entry that references a miner name (**HIGH**) or a suspicious launch path (**MED**). It finds a miner even when it is **not currently running** — the config that would relaunch it is enough. Demo caught a malicious cron line and a malicious systemd unit, and left a benign nginx unit alone.

---

## Output + alerting

All outputs derive from the same `scan()` results (which carry each process's `exe`, so alerts include the full binary path):

- **`emit_json`** — JSON Lines, one object per finding, for a SIEM (Elastic / Splunk).
- **`emit_log`** — syslog-style single line per finding.
- **`post_webhook`** — POSTs qualifying findings (HIGH by default, tunable to MED) to a Slack/PagerDuty/generic webhook. The `text` field is human-shaped; the `finding` object carries the full structured record for automation. Demonstrated end-to-end against a local listener.

That closes the loop — **detect -> score -> alert** — in formats real tooling ingests.

---

## Optional daemon — continuous monitoring with rate-limited alerts

Running the scan once is a spot check; in production it runs on a loop. The thing that must be right is **alert rate-limiting** — a loop that re-alerts on the same miner every cycle produces the alert fatigue that gets detectors muted. Each distinct finding alerts at most once per `cooldown`, keyed on the executable path (so a miner that restarts with a new PID does not reset the cooldown and spam you):

```python
def run_daemon(interval=60, cooldown=3600, webhook_url=None, iterations=None,
               include_persistence=True, persistence_extra=None, verbose=False):
    seen = {}   # dedup key -> last-alert timestamp
    ...
    for f in [r for r in scan() if r[0]]:            # HIGH process findings
        key = ("proc", f[4] or f[3])                 # dedup on exe (survives PID change)
        if now - seen.get(key, -1e18) >= cooldown:
            seen[key] = now
            if webhook_url: post_webhook([f], webhook_url)
            print("ALERT " + emit_log([f]))
```

Demo (miner running continuously, `interval=0.2s`, `cooldown=3s`): one alert, several suppressed cycles during the cooldown, then a single re-alert once it expired. In production set `interval` to minutes and `cooldown` to an hour, POST to a real webhook, and run it under systemd.

---

## Build plan (phased) — status

- **Phase 1 — MVP.** Done. CPU + signature + pool-port signals, scoring engine, table output; false positives fixed (HIGH needs >=2 signals; self-exclude; match name/path).
- **Phase 2 — Harden the signals.** Mostly done. Suspicious-path signal and multi-sample sustained CPU shipped. Remaining: a live pool-domain/IP threat feed.
- **Phase 3 — Persistence + GPU.** Done for Linux/macOS. GPU sensor via `nvidia-smi pmon`; persistence enumeration across cron, systemd, autostart, shell rc. Remaining: Windows autostart vectors (Task Scheduler, Run keys).
- **Phase 4 — Alerting + allowlist.** Done. Trusted-app allowlist, adaptive CPU floor, JSON/syslog/webhook output, and a continuous daemon with cooldown-based alert rate-limiting.
- **Stretch — browser cryptojacking.** Separate detector for drive-by mining: a single tab pinning CPU + WebAssembly usage.

---

## What to put in the write-up (for a portfolio)

- The **signal table** and why multi-signal, strength-weighted scoring beats any single check.
- The **precision/recall story**: recall 0.33 -> root-caused to a load-dependent CPU threshold -> fixed to 1.00 with precision held. The build -> measure -> fix -> re-measure loop.
- The **adversarial evaluation**: precision fell to 0.50 on a harder set; ranking signals by *strength* rather than *count* recovered it to 1.00, and the GPU sensor closed recall to 1.00.
- The **silent-sensor bug**: a broken GPU collector looked like "no GPU"; fixing it to fail loudly is exactly the kind of detail interviewers probe for.
