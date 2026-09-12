package com.jamesbaird.cryptojack.data

class ScanRepository(
    private val api: DetectorApi = DetectorApi()
) {
    suspend fun loadReport(settings: DetectorSettings): Result<ScanReport> = runCatching {
        require(settings.isConfigured) { "No detector host configured" }
        api.fetchReport(settings.baseUrl, settings.token.ifBlank { null })
    }

    /** Sample data used for previews and the first-run empty state. */
    fun demoReport(): ScanReport = ScanReport(
        host = "demo-workstation",
        generatedAt = "2026-09-12T02:30:00Z",
        scanDurationSec = 1.8,
        processesScanned = 214,
        findings = listOf(
            Finding(
                pid = 4821,
                name = "xmrig",
                exe = "/tmp/.cache/xmrig",
                username = "james",
                score = 92,
                cpuPercent = 388.4,
                signals = listOf(
                    Signal("name_match", "Known miner signature", "Binary name matches xmrig", 35),
                    Signal("cpu_sustained", "Sustained CPU", "388% across 3 samples", 25),
                    Signal("pool_conn", "Mining pool connection", "pool.supportxmr.com:3333", 20),
                    Signal("susp_path", "Suspicious path", "Executable runs from /tmp", 12)
                )
            ),
            Finding(
                pid = 2210,
                name = "node",
                exe = "/usr/bin/node",
                username = "james",
                score = 45,
                cpuPercent = 96.1,
                signals = listOf(
                    Signal("cpu_sustained", "Sustained CPU", "96% across 3 samples", 25),
                    Signal("args_match", "Argument heuristic", "--max-cpu flag present", 20)
                )
            )
        )
    )
}
