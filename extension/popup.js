// popup.js - asks the background worker for the active tab's verdict and renders it.
(function () {
  "use strict";
  var LABEL = {
    HIGH: "Likely in-browser miner",
    MED: "Some mining-like signals",
    OK: "No mining detected"
  };
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    var tab = tabs && tabs[0];
    if (!tab) return;
    chrome.runtime.sendMessage({ __cryptojack_query: true, tabId: tab.id }, function (s) {
      s = s || { band: "OK", signals: [], reasons: [] };
      var band = s.band || "OK";
      var verdict = document.getElementById("verdict");
      verdict.innerHTML = '<span class="band ' + band + '">' + band + '</span> ' +
        (LABEL[band] || "Unknown");
      var ul = document.getElementById("reasons");
      (s.reasons || []).forEach(function (r) {
        var li = document.createElement("li");
        li.textContent = r;
        ul.appendChild(li);
      });
      document.getElementById("url").textContent = tab.url || "";
    });
  });
})();
