# Cryptojacking Detector

[![CI](https://github.com/jamesbairdjr88-star/cryptojack-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/jamesbairdjr88-star/cryptojack-detector/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Read-only tooling that detects **unauthorized crypto miners** on machines you own
or are authorized to monitor. Two complementary detectors, one signature philosophy:

- **Host detector** (`cryptojack_detect.py`) — finds miner *processes* on a machine.
- **Drive-by detector** (`browser_detect.py` + a browser extension) — finds *in-browser*
  (Coinhive-style WASM) miners running in a web page.

Both score by *signal strength* and only escalate to **HIGH** when a strong,
miner-specific signal is present — the rule that keeps false positives near zero.
Everything is read-only: it reports and scores, and never kills processes, blocks
requests, or changes anything. A human decides what to do.

This is the defender's side of crypto mining: the skill security teams actually hire for.

## Results

Both detectors ship with reproducible, labeled test harnesses that assert
**Precision 1.00 / Recall 1.00 / F1 1.00**, and both run in CI on every push:

- Host: `test_detector.py` — miners (incl. throttled + off-CPU GPU) vs benign look-alikes.
- Drive-by: `test_browser_detector.py` — Coinhive/WASM miner pages vs benign pages
  (incl. a legit WASM game and a security blog that only *mentions* "coinhive" in prose).

## Install

```bash
pip install .                 # installs the `cryptojack-detect` and `browser-detect` commands
# or run without installing:
pip install -r requirements.txt
python cryptojack_detect.py --help
python browser_detect.py --help
```

Requires Python 3.8+ and `psutil` (host detector). The drive-by analyzer is pure
stdlib. The optional host GPU signal uses `nvidia-smi` if present.

## Host detector — usage

```bash
cryptojack-detect scan                 # one scan; ranked table of suspects
cryptojack-detect scan --json          # JSON Lines (for a SIEM)
cryptojack-detect scan --persistence   # also enumerate autostart entries
cryptojack-detect persistence          # scan cron/systemd/autostart/rc only
cryptojack-detect watch --webhook URL  # continuous, rate-limited monitoring
```

Signals: adaptive-floor sustained CPU, miner name/arg signatures, mining-pool
connections, suspicious paths, GPU compute (`nvidia-smi`), and persistence
enumeration, with a trusted-app allowlist. **Exit codes:** `0` clean, `1` a HIGH
finding, `2` usage error — cron/CI-friendly. A hardened systemd unit lives in
`deploy/cryptojack-detect.service`.

## Drive-by (in-browser) detector

Catches web pages that mine crypto in the visitor's browser. Two pieces share one
signature list:

**1. Static analyzer / CLI** — scans a page's *code* (script srcs, inline JS, network
endpoints), never its visible text, so a blog that merely mentions "coinhive" is
never flagged:

```bash
browser-detect page.html               # scan a saved page
browser-detect --url https://site.tld  # fetch and scan a live page
browser-detect --url https://site.tld --fetch-scripts   # also scan external JS
browser-detect page.html --json        # JSON output
```

Signals — **strong:** miner script/library signature, mining-pool or
stratum-over-WebSocket endpoint; **weak:** WebAssembly usage, Web Worker fan-out
across cores, hashing-loop markers. HIGH requires a strong signal. Exit `0`/`1`
like the host detector.

**2. Browser extension** (`extension/`, Manifest V3, Chromium 111+) — the live,
client-side detector. It hooks `WebSocket` / `WebAssembly` / `Worker` in the page
(observe-only), statically scans script tags, warns with a page banner + toolbar
badge, and shows the verdict in a popup. Load it unpacked via
`chrome://extensions → Developer mode → Load unpacked → select extension/`.
See `extension/README.md`. It blocks nothing and sends nothing off your device.

## Run the host detector as a service

```bash
sudo cp deploy/cryptojack-detect.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cryptojack-detect
journalctl -u cryptojack-detect -f      # watch alerts
```

## Files

- `cryptojack_detect.py` — host detector + CLI: collectors, scoring engine, output/alerting, daemon
- `test_detector.py` — host precision/recall harness (also runs the browser suite, so one command covers both in CI)
- `browser_detect.py` — drive-by (in-browser) static analyzer + CLI
- `test_browser_detector.py` — drive-by precision/recall harness (labeled page fixtures)
- `extension/` — Manifest V3 browser extension (the live drive-by detector)
- `SPEC.md` — full project spec: design, phased build, evaluations, and debugging write-ups
- `pyproject.toml` — packaging; installs the `cryptojack-detect` and `browser-detect` commands
- `deploy/cryptojack-detect.service` — hardened systemd unit for the host daemon
- `requirements.txt`, `LICENSE`, `.gitignore`

## Engineering highlights (for reviewers)

Debugging stories are written up in `SPEC.md`:

1. **Load-dependent CPU threshold.** Host recall dropped to 0.33 on a 2-core box
   because a fixed 70%-of-one-core threshold missed contended miners. Root-caused,
   then replaced with an adaptive fair-share floor → recall 1.00, precision held.
2. **Silent-sensor bug.** The GPU collector swallowed errors, so a *broken* sensor
   looked identical to "no GPU present." Fixed to fail loudly.
3. **Code-not-prose matching (drive-by).** The browser analyzer scores only script
   context, so a security article about Coinhive is never a false positive — the
   same lesson as the host detector's "mentions xmrig in an argument" case.

## Scope & ethics

Run these only on systems you own or are authorized to monitor. Both detectors are
read-only by design: they report and score, and never terminate processes, block
requests, or edit configuration.

## License

MIT — see `LICENSE`.
