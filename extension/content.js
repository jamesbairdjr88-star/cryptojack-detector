// content.js - runs in the ISOLATED world. Statically scans the page's script
// tags against the signature list, listens for the MAIN-world observations from
// inject.js, scores them with the same strength-weighted rule as the Python
// detector, reports the verdict to the background service worker, and shows a
// dismissible warning banner when a page is HIGH.
(function () {
  "use strict";
  var SIG = globalThis.CRYPTOJACK_SIGNATURES || { hosts: [], tokens: [] };
  var STRONG = { signature: true, pool: true };
  var fired = {};
  var reasons = [];
  var banner = null;

  function classify() {
    var strong = 0, total = 0, k;
    for (k in fired) {
      if (fired[k]) { total += 1; if (STRONG[k]) strong += 1; }
    }
    if (strong >= 2 || (strong >= 1 && total >= 2)) return "HIGH";
    if (total > 0) return "MED";
    return "OK";
  }

  function report() {
    var band = classify();
    try {
      chrome.runtime.sendMessage({
        __cryptojack: true, band: band,
        signals: Object.keys(fired), reasons: reasons, url: location.href
      });
    } catch (e) { /* service worker may be asleep; badge updates on next event */ }
    if (band === "HIGH") showBanner();
  }

  function add(signal, reason) {
    if (!fired[signal]) {
      fired[signal] = true;
      if (reason) reasons.push(reason);
      report();
    }
  }

  function showBanner() {
    if (banner || !document.body) return;
    banner = document.createElement("div");
    banner.textContent = "Cryptojack Detector: this page appears to be running an in-browser crypto miner.";
    banner.style.cssText =
      "position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#b00020;" +
      "color:#fff;font:600 14px system-ui,-apple-system,sans-serif;padding:10px 14px;" +
      "text-align:center;box-shadow:0 2px 6px rgba(0,0,0,.3)";
    var dismiss = document.createElement("span");
    dismiss.textContent = "  [dismiss]";
    dismiss.style.cssText = "cursor:pointer;text-decoration:underline;margin-left:8px";
    dismiss.addEventListener("click", function () {
      if (banner && banner.parentNode) banner.parentNode.removeChild(banner);
    });
    banner.appendChild(dismiss);
    document.body.appendChild(banner);
  }

  function staticScan() {
    var scripts = document.getElementsByTagName("script");
    for (var i = 0; i < scripts.length; i++) {
      var src = (scripts[i].src || "").toLowerCase();
      if (!src) continue;
      var j;
      for (j = 0; j < SIG.hosts.length; j++) {
        if (src.indexOf(SIG.hosts[j]) !== -1) add("pool", "script from " + SIG.hosts[j]);
      }
      for (j = 0; j < SIG.tokens.length; j++) {
        if (src.indexOf(SIG.tokens[j]) !== -1) add("signature", "miner script: " + SIG.tokens[j]);
      }
    }
  }

  window.addEventListener("message", function (e) {
    if (!e || !e.data || e.data.__cryptojack !== true) return;
    switch (e.data.signal) {
      case "pool": add("pool", "websocket to miner/stratum endpoint"); break;
      case "signature": add("signature", "miner API call"); break;
      case "wasm": add("wasm", "WebAssembly usage"); break;
      case "worker": add("worker", "Web Worker fan-out across cores"); break;
      default: break;
    }
  }, false);

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", staticScan);
  } else {
    staticScan();
  }
  report();
})();
