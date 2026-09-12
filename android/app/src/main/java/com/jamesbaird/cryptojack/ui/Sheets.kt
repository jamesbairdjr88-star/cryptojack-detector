package com.jamesbaird.cryptojack.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.jamesbaird.cryptojack.data.DetectorSettings
import com.jamesbaird.cryptojack.data.Finding

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DetectionDetailSheet(finding: Finding, onDismiss: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.padding(horizontal = 20.dp).padding(bottom = 32.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column {
                    Text(finding.name, style = MaterialTheme.typography.headlineSmall)
                    Text("pid ${finding.pid} - user ${finding.username.ifBlank { "unknown" }}")
                }
                SeverityChip(finding.severity, finding.score)
            }

            Spacer(Modifier.height(16.dp))
            Text("Executable", style = MaterialTheme.typography.labelLarge)
            Text(
                finding.exe.ifBlank { "unavailable" },
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodyMedium
            )

            Spacer(Modifier.height(8.dp))
            Text("CPU", style = MaterialTheme.typography.labelLarge)
            Text("${"%.1f".format(finding.cpuPercent)}% (multi-sample average)")

            Spacer(Modifier.height(16.dp))
            Text("Why it was flagged", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            finding.signals.forEach { signal ->
                Column(Modifier.padding(vertical = 6.dp)) {
                    Text("${signal.label}  (+${signal.weight})", style = MaterialTheme.typography.bodyLarge)
                    Text(signal.detail, style = MaterialTheme.typography.bodySmall)
                }
                Divider()
            }

            Spacer(Modifier.height(16.dp))
            Text(
                "This app is read-only. Investigate and terminate processes on the host itself.",
                style = MaterialTheme.typography.bodySmall
            )
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = onDismiss) { Text("Close") }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsSheet(
    settings: DetectorSettings,
    onSave: (String, String) -> Unit,
    onDismiss: () -> Unit
) {
    var baseUrl by remember { mutableStateOf(settings.baseUrl) }
    var token by remember { mutableStateOf(settings.token) }

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.padding(horizontal = 20.dp).padding(bottom = 32.dp)) {
            Text("Detector host", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(4.dp))
            Text(
                "Base URL of a machine you own that is running cryptojack-detector in report mode.",
                style = MaterialTheme.typography.bodySmall
            )
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(
                value = baseUrl,
                onValueChange = { baseUrl = it },
                label = { Text("Base URL") },
                placeholder = { Text("http://192.168.1.20:8787") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = token,
                onValueChange = { token = it },
                label = { Text("Bearer token (optional)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(20.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { onSave(baseUrl, token) }) { Text("Save and scan") }
                TextButton(onClick = onDismiss) { Text("Cancel") }
            }
        }
    }
}
