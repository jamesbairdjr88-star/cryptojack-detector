package com.jamesbaird.cryptojack.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Mirrors the JSON report emitted by the cryptojack-detector Python tool
 * (`python -m detector --json`).
 */
@Serializable
data class ScanReport(
    val host: String = "unknown-host",
    @SerialName("generated_at") val generatedAt: String = "",
    @SerialName("scan_duration_sec") val scanDurationSec: Double = 0.0,
    @SerialName("processes_scanned") val processesScanned: Int = 0,
    val findings: List<Finding> = emptyList()
) {
    val criticalCount: Int get() = findings.count { it.severity == Severity.CRITICAL }
    val warningCount: Int get() = findings.count { it.severity == Severity.WARNING }
    val isClean: Boolean get() = findings.none { it.severity != Severity.INFO }
}

@Serializable
data class Finding(
    val pid: Int = 0,
    val name: String = "",
    val exe: String = "",
    val username: String = "",
    /** 0-100 confidence score produced by the detector's signal weighting. */
    val score: Int = 0,
    @SerialName("cpu_percent") val cpuPercent: Double = 0.0,
    val signals: List<Signal> = emptyList()
) {
    val severity: Severity
        get() = when {
            score >= 70 -> Severity.CRITICAL
            score >= 40 -> Severity.WARNING
            else -> Severity.INFO
        }
}

@Serializable
data class Signal(
    val id: String = "",
    val label: String = "",
    val detail: String = "",
    val weight: Int = 0
)

enum class Severity { CRITICAL, WARNING, INFO }
