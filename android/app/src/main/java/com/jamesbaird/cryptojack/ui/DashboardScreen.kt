package com.jamesbaird.cryptojack.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.jamesbaird.cryptojack.data.Finding
import com.jamesbaird.cryptojack.data.ScanReport
import com.jamesbaird.cryptojack.data.Severity
import com.jamesbaird.cryptojack.ui.theme.Critical
import com.jamesbaird.cryptojack.ui.theme.Ok
import com.jamesbaird.cryptojack.ui.theme.Warning

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    state: ScanUiState,
    onRefresh: () -> Unit,
    onOpenSettings: () -> Unit,
    onSelect: (Finding) -> Unit,
    onDismissError: () -> Unit,
    onLoadDemo: () -> Unit
) {
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(state.error) {
        state.error?.let {
            snackbarHostState.showSnackbar(it)
            onDismissError()
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("Cryptojack Companion") },
                actions = {
                    IconButton(onClick = onRefresh) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh scan")
                    }
                    IconButton(onClick = onOpenSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
        ) {
            if (state.isLoading) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp),
                    horizontalArrangement = Arrangement.Center
                ) {
                    CircularProgressIndicator()
                }
            }

            val report = state.report
            if (report == null) {
                EmptyState(onOpenSettings = onOpenSettings, onLoadDemo = onLoadDemo)
            } else {
                SummaryCard(report = report, isDemo = state.isDemo)
                Spacer(Modifier.height(12.dp))
                Text(
                    text = "Flagged processes",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(8.dp))
                LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(report.findings.sortedByDescending { it.score }) { finding ->
                        FindingRow(finding = finding, onClick = { onSelect(finding) })
                    }
                }
            }
        }
    }
}

@Composable
private fun SummaryCard(report: ScanReport, isDemo: Boolean) {
    val tone = when {
        report.criticalCount > 0 -> Critical
        report.warningCount > 0 -> Warning
        else -> Ok
    }
    val headline = when {
        report.criticalCount > 0 -> "${report.criticalCount} likely cryptojacking process(es)"
        report.warningCount > 0 -> "${report.warningCount} process(es) worth a look"
        else -> "No mining activity detected"
    }

    Card(
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        colors = CardDefaults.cardColors(containerColor = tone.copy(alpha = 0.12f))
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(headline, style = MaterialTheme.typography.titleLarge, color = tone)
            Spacer(Modifier.height(6.dp))
            Text(
                "${report.host} - ${report.processesScanned} processes scanned in ${report.scanDurationSec}s",
                style = MaterialTheme.typography.bodyMedium
            )
            Text(
                "Report generated ${report.generatedAt.ifBlank { "unknown" }}",
                style = MaterialTheme.typography.bodySmall
            )
            if (isDemo) {
                Spacer(Modifier.height(6.dp))
                Text(
                    "Demo data - configure your detector host for live results.",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.secondary
                )
            }
        }
    }
}

@Composable
private fun FindingRow(finding: Finding, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    text = "${finding.name} (pid ${finding.pid})",
                    style = MaterialTheme.typography.titleMedium
                )
                Text(
                    text = finding.exe.ifBlank { "path unavailable" },
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    text = "CPU ${"%.1f".format(finding.cpuPercent)}% - ${finding.signals.size} signal(s)",
                    style = MaterialTheme.typography.bodySmall
                )
            }
            SeverityChip(finding.severity, finding.score)
        }
    }
}

@Composable
fun SeverityChip(severity: Severity, score: Int) {
    val color = severity.color()
    Surface(color = color.copy(alpha = 0.18f), shape = MaterialTheme.shapes.small) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text("$score", style = MaterialTheme.typography.titleMedium, color = color)
            Text(severity.name, style = MaterialTheme.typography.labelSmall, color = color)
        }
    }
}

@Composable
private fun EmptyState(onOpenSettings: () -> Unit, onLoadDemo: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("No scan report yet", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(8.dp))
        Text(
            "Point the app at a machine running cryptojack-detector in report mode.",
            style = MaterialTheme.typography.bodyMedium
        )
        Spacer(Modifier.height(12.dp))
        TextButton(onClick = onOpenSettings) { Text("Configure detector host") }
        TextButton(onClick = onLoadDemo) { Text("View demo report") }
    }
}

fun Severity.color(): Color = when (this) {
    Severity.CRITICAL -> Critical
    Severity.WARNING -> Warning
    Severity.INFO -> Ok
}
