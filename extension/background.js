// background.js - MV3 service worker. Aggregates per-tab verdicts from the
// content scripts and reflects the worst signal on the toolbar badge. Holds no
// network access and sends nothing off the device.
var state = {}; // tabId -> { band, signals, reasons, url }

function badgeFor(band) {
  if (band === "HIGH") return { text: "!", color: "#b00020" };
  if (band === "MED") return { text: "?", color: "#b06f00" };
  return { text: "", color: "#000000" };
}

chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  // a content script reporting a verdict for its tab
  if (msg && msg.__cryptojack === true && sender.tab) {
    var tabId = sender.tab.id;
    state[tabId] = {
      band: msg.band, signals: msg.signals || [],
      reasons: msg.reasons || [], url: msg.url || ""
    };
    try {
      var rec = {};
      rec["tab_" + tabId] = state[tabId];
      chrome.storage.session.set(rec);
    } catch (e) { /* ignore */ }
    var b = badgeFor(msg.band);
    chrome.action.setBadgeText({ tabId: tabId, text: b.text });
    if (b.text) chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: b.color });
    return;
  }
  // the popup asking for the active tab's verdict
  if (msg && msg.__cryptojack_query === true) {
    var id = msg.tabId;
    if (state[id]) { sendResponse(state[id]); return true; }
    try {
      chrome.storage.session.get("tab_" + id, function (r) {
        sendResponse(r["tab_" + id] || { band: "OK", signals: [], reasons: [] });
      });
      return true; // async response
    } catch (e) {
      sendResponse({ band: "OK", signals: [], reasons: [] });
    }
  }
});

chrome.tabs.onRemoved.addListener(function (tabId) {
  delete state[tabId];
  try { chrome.storage.session.remove("tab_" + tabId); } catch (e) { /* ignore */ }
});
