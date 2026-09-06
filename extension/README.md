# Cryptojack Drive-by Detector (browser extension)

A Manifest V3 (Chrome/Edge) extension that warns you when a web page runs an
**in-browser crypto miner** (Coinhive-style drive-by mining). It is the live,
client-side counterpart to `browser_detect.py`, and shares the same signature
list and the same "HIGH needs a strong signal" scoring rule.

**Read-only by design.** It observes the page and warns you. It does not block
requests, kill scripts, or change page behavior, and it sends nothing off your
device.

## What it watches

A page-world hook (`inject.js`, runs before the page's own code) wraps three
APIs to *observe* — never block — how they are used:

- **WebSocket** connections to known miner / stratum endpoints (strong signal)
- **WebAssembly** module instantiation (weak signal — games and ML use it too)
- **Web Worker** fan-out approaching your CPU core count (weak signal)

The isolated-world script (`content.js`) also statically scans `<script src>`
tags against the miner host/token list (strong signal), scores everything, and:

- flashes a dismissible red banner on the page when a page scores **HIGH**
- reflects the verdict on the toolbar badge (`!` red = HIGH, `?` amber = MED)
- shows the verdict and the reasons in the popup

A page is only **HIGH** when a strong signal is present — a strong signature or
a mining-pool endpoint — so a legitimate WebAssembly app that merely spins up
workers stays at MED and never triggers a false alarm.

## Install (unpacked)

1. Open `chrome://extensions` (or `edge://extensions`)
2. Turn on **Developer mode** (top-right)
3. Click **Load unpacked** and select this `extension/` folder
4. Browse normally — the toolbar badge and popup show each tab's verdict

Requires Chromium 111+ (uses content-script `world: "MAIN"`).

## Files

- `manifest.json` — MV3 manifest (two content-script worlds, minimal permissions)
- `signatures.js` — shared miner host/token lists
- `inject.js` — MAIN-world API observer
- `content.js` — isolated-world scanner, scorer, and banner
- `background.js` — per-tab aggregation and toolbar badge
- `popup.html` / `popup.js` — the verdict popup

## Limitations

- Signature/host lists need maintaining from public feeds (NoCoin, CoinBlockerLists).
- A miner served from an unknown host with no recognizable API and no WebSocket
  can still evade the strong signals; that is the same maintained-list tradeoff
  the host detector documents.
- Firefox uses a different injection model; this targets Chromium MV3.
