// inject.js - runs in the page's MAIN world (document_start) to observe
// mining-related APIs before the page uses them. It only OBSERVES: it wraps
// WebSocket / WebAssembly / Worker to note usage, then postMessages findings to
// the isolated-world content script. It never blocks or alters behavior.
(function () {
  "use strict";
  var SIG = globalThis.CRYPTOJACK_SIGNATURES || { hosts: [], tokens: [] };

  function post(signal, detail) {
    try {
      window.postMessage({ __cryptojack: true, signal: signal, detail: detail || "" }, "*");
    } catch (e) { /* ignore */ }
  }

  function hostHit(url) {
    var u = String(url || "").toLowerCase();
    for (var i = 0; i < SIG.hosts.length; i++) {
      if (u.indexOf(SIG.hosts[i]) !== -1) return SIG.hosts[i];
    }
    if (u.indexOf("stratum") !== -1 && u.indexOf("ws") === 0) return "stratum";
    return null;
  }

  // --- WebSocket: flag connections to known miner / stratum endpoints ---
  try {
    var NativeWS = window.WebSocket;
    if (NativeWS) {
      var WrappedWS = function (url, protocols) {
        var h = hostHit(url);
        if (h) post("pool", String(url));
        return protocols === undefined ? new NativeWS(url) : new NativeWS(url, protocols);
      };
      WrappedWS.prototype = NativeWS.prototype;
      WrappedWS.CONNECTING = NativeWS.CONNECTING;
      WrappedWS.OPEN = NativeWS.OPEN;
      WrappedWS.CLOSING = NativeWS.CLOSING;
      WrappedWS.CLOSED = NativeWS.CLOSED;
      window.WebSocket = WrappedWS;
    }
  } catch (e) { /* ignore */ }

  // --- WebAssembly: note module instantiation (weak signal) ---
  try {
    if (window.WebAssembly) {
      var inst = WebAssembly.instantiate;
      if (typeof inst === "function") {
        WebAssembly.instantiate = function () {
          post("wasm", "instantiate");
          return inst.apply(this, arguments);
        };
      }
      var instStream = WebAssembly.instantiateStreaming;
      if (typeof instStream === "function") {
        WebAssembly.instantiateStreaming = function () {
          post("wasm", "instantiateStreaming");
          return instStream.apply(this, arguments);
        };
      }
    }
  } catch (e) { /* ignore */ }

  // --- Worker: flag fan-out approaching the core count (weak signal) ---
  try {
    var NativeWorker = window.Worker;
    if (NativeWorker) {
      var count = 0;
      var cores = (navigator && navigator.hardwareConcurrency) || 4;
      var WrappedWorker = function (url, opts) {
        count += 1;
        if (count >= Math.max(2, cores - 1)) post("worker", count + " workers");
        return opts === undefined ? new NativeWorker(url) : new NativeWorker(url, opts);
      };
      WrappedWorker.prototype = NativeWorker.prototype;
      window.Worker = WrappedWorker;
    }
  } catch (e) { /* ignore */ }
})();
