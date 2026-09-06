// signatures.js - shared miner host/token lists, loaded in both the MAIN and
// ISOLATED content-script worlds. Keep this list maintained from public feeds
// (e.g. NoCoin / CoinBlockerLists). Read-only data; no logic.
globalThis.CRYPTOJACK_SIGNATURES = {
  // known mining-pool / proxy hosts (incl. stratum-over-websocket proxies)
  hosts: [
    "coinhive.com", "coin-hive.com", "authedmine.com", "ws.coinhive.com",
    "coinimp.com", "hostingcloud.racing", "crypto-loot.com", "webmine.cz",
    "webminepool.com", "cryptoloot.pro", "minero.cc", "hashvault.pro",
    "cnhv.co", "2giga.link", "coinpot.co", "jsecoin.com", "cryptonoter.com",
    "party-nnvip.top", "reasedoper.pw", "webmining.co"
  ],
  // miner-family tokens that appear in script URLs
  tokens: [
    "coinhive", "coin-hive", "authedmine", "coinimp", "crypto-loot", "cryptoloot",
    "cryptonight", "jsecoin", "webminepool", "deepminer", "webmine", "minero",
    "hashvault", "nerohut", "coinhave", "cryptonoter", "projectpoi", "wasmminer"
  ]
};
