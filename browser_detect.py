#!/usr/bin/env python3
"""browser_detect.py - drive-by (in-browser) cryptojacking detector.

Read-only static analyzer. Given a web page's HTML (and optionally its linked
JS bodies and observed network endpoints), it scores the page for in-browser
mining (Coinhive-style WASM miners) using strength-weighted signals -- the same
"HIGH needs a strong signal" rule as the host detector.

It analyzes page CODE only -- <script src> URLs, inline <script> bodies, and
network endpoints -- never visible page text. That is what keeps precision high:
a security blog post that merely mentions "coinhive" in prose is never flagged,
because the word never appears in a script context.
"""
import re
from html.parser import HTMLParser

__version__ = "1.0.0"

# --- known miner families: tokens that appear in script URLs and code ---
MINER_TOKENS = [
    "coinhive", "coin-hive", "authedmine", "coinimp", "crypto-loot", "cryptoloot",
    "cryptonight", "jsecoin", "webminepool", "deepminer", "webmine", "minero",
    "hashvault", "nerohut", "coinhave", "cryptonoter", "projectpoi", "monerise",
    "wasmminer", "cryptaloot", "coinnebula", "coinlab", "papoto", "mataharirama",
]
# distinctive in-code markers (function/API calls specific to miners)
CODE_MARKERS = [
    "coinhive.anonymous", "coinhive.user", "new coinhive", "new client.anonymous",
    "client.anonymous(", "cryptonight_hash", "cn_slow_hash", "randomx",
    "startmining(", "stopmining(", "hashespersecond", "totalhashes",
    "setnumthreads", "_hashwork", "miner.start(", "new miner(", "getglobaljob",
    "throttlemining", "setthrottle(", "hashesperthread",
]
# known mining-pool / proxy hosts (incl. stratum-over-websocket proxies)
MINER_HOSTS = [
    "coinhive.com", "coin-hive.com", "authedmine.com", "ws.coinhive.com",
    "coinimp.com", "hostingcloud.racing", "crypto-loot.com", "webmine.cz",
    "webminepool.com", "cryptoloot.pro", "minero.cc", "hashvault.pro",
    "cnhv.co", "2giga.link", "coinpot.co", "jsecoin.com", "cryptonoter.com",
    "party-nnvip.top", "wss.rand.com.ru", "reasedoper.pw", "webmining.co",
]
WASM_MARKERS = ["webassembly.instantiate", "webassembly.instance",
                "instantiatestreaming", ".wasm", "application/wasm"]
HASHLOOP_MARKERS = ["hashespersecond", "hashrate", "totalhashes", "numthreads",
                    "hashesperthread", "hashes/s"]

STRONG_SIGNALS = {"signature", "pool"}   # specific to miners
WEAK_SIGNALS = {"wasm", "worker", "hashloop"}  # legit software trips these too


def classify(fired):
    """HIGH needs a strong signal, never two weak ones alone."""
    strong = len(fired & STRONG_SIGNALS)
    total = len(fired)
    if strong >= 2 or (strong >= 1 and total >= 2):
        return "HIGH"
    if fired:
        return "MED"
    return "OK"


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.script_srcs = []
        self.inline = []
        self.resource_urls = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        d = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script":
            src = d.get("src", "")
            if src:
                self.script_srcs.append(src)
            else:
                self._in_script = True
        for key in ("src", "href", "data-src", "data-url"):
            if d.get(key):
                self.resource_urls.append(d[key])

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self.inline.append(data)


def _parse(html):
    p = _PageParser()
    try:
        p.feed(html)
    except Exception:
        pass
    return p


def scan_html(html, external_js=None, endpoints=None, source="page"):
    """Score one page. Returns a dict with band, score, reasons, and signals."""
    p = _parse(html or "")
    inline_code = " ".join(p.inline).lower()
    ext = " ".join(external_js or []).lower()
    code = inline_code + " " + ext
    srcs = [s.lower() for s in p.script_srcs]
    urls = [u.lower() for u in (p.resource_urls + p.script_srcs + list(endpoints or []))]
    for m in re.findall(r"(?:https?|wss?)://[^\s\"'`)]+", code):
        urls.append(m)

    fired = set()
    reasons = []
    score = 0

    # --- signature (STRONG): tokens in script URLs/code, or miner API markers ---
    sig = set()
    for tok in MINER_TOKENS:
        if tok in code or any(tok in s for s in srcs):
            sig.add(tok)
    for mk in CODE_MARKERS:
        if mk in code:
            sig.add(mk)
    if sig:
        fired.add("signature")
        score += 50
        reasons.append("miner signature: " + ", ".join(sorted(sig)[:4]))

    # --- mining-pool endpoint (STRONG): known host, or stratum-over-websocket ---
    hosts = sorted({h for h in MINER_HOSTS if any(h in u for u in urls)})
    ws_stratum = any(
        u.startswith(("ws://", "wss://")) and ("stratum" in u or any(h in u for h in MINER_HOSTS))
        for u in urls
    ) or ("stratum+tcp" in code) or ("stratum" in code and "websocket" in code)
    if hosts or ws_stratum:
        fired.add("pool")
        score += 50
        detail = ", ".join(hosts[:3]) if hosts else "stratum-over-websocket"
        reasons.append("mining-pool endpoint: " + detail)

    # --- WebAssembly usage (WEAK): games/ML use it too ---
    if any(w in code for w in WASM_MARKERS):
        fired.add("wasm")
        score += 25
        reasons.append("WebAssembly usage")

    # --- Web Worker fan-out across cores (WEAK) ---
    if "new worker(" in code and "hardwareconcurrency" in code:
        fired.add("worker")
        score += 25
        reasons.append("Web Worker fan-out across CPU cores")

    # --- hashing-loop markers (WEAK) ---
    if any(k in code for k in HASHLOOP_MARKERS):
        fired.add("hashloop")
        score += 20
        reasons.append("hashing-loop markers")

    band = classify(fired)
    return {
        "is_high": band == "HIGH",
        "band": band,
        "score": score,
        "reasons": reasons,
        "signals": sorted(fired),
        "source": source,
    }


def _fetch(url, fetch_scripts=False, timeout=10):
    import urllib.request
    from urllib.parse import urljoin
    ua = {"User-Agent": "cryptojack-browser-detect/1.0"}
    html = urllib.request.urlopen(
        urllib.request.Request(url, headers=ua), timeout=timeout
    ).read().decode("utf-8", "ignore")
    ext = []
    if fetch_scripts:
        for s in _parse(html).script_srcs[:20]:
            try:
                full = urljoin(url, s)
                ext.append(urllib.request.urlopen(
                    urllib.request.Request(full, headers=ua), timeout=timeout
                ).read().decode("utf-8", "ignore"))
            except Exception:
                pass
    return html, ext


def _print(results):
    print("%-4s %5s  %-34s %s" % ("BAND", "SCORE", "SOURCE", "REASONS"))
    print("-" * 96)
    for r in results:
        print("%-4s %5d  %-34s %s" % (
            r["band"], r["score"], str(r["source"])[:34],
            "; ".join(r["reasons"]) or "-"))
    if not results:
        print("No pages scanned.")


def cli(argv=None):
    import argparse
    import json as _json
    ap = argparse.ArgumentParser(
        prog="browser-detect",
        description=("Drive-by (in-browser) cryptojacking detector. Statically scores "
                     "a page's scripts and network endpoints for Coinhive-style mining. "
                     "Read-only; analyzes code, not visible text."))
    ap.add_argument("--version", action="version", version="browser-detect " + __version__)
    ap.add_argument("paths", nargs="*", help="HTML files to scan")
    ap.add_argument("--url", action="append", default=[],
                    help="fetch and scan a live URL (repeatable)")
    ap.add_argument("--fetch-scripts", action="store_true",
                    help="with --url, also download <script src> bodies and scan them")
    ap.add_argument("--json", action="store_true", help="emit results as JSON")
    ap.add_argument("--exit-zero", action="store_true",
                    help="always exit 0 (default: exit 1 when a page is HIGH)")
    args = ap.parse_args(argv)

    results = []
    for path in args.paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                html = fh.read()
        except OSError as e:
            print("cannot read %s: %s" % (path, e))
            continue
        results.append(scan_html(html, source=path))
    for u in args.url:
        try:
            html, ext = _fetch(u, args.fetch_scripts)
            results.append(scan_html(html, external_js=ext, source=u))
        except Exception as e:
            print("cannot fetch %s: %s" % (u, e))

    if args.json:
        print(_json.dumps(results, indent=2))
    else:
        _print(results)

    if args.exit_zero:
        return 0
    return 1 if any(r["is_high"] for r in results) else 0


if __name__ == "__main__":
    import sys
    sys.exit(cli())
