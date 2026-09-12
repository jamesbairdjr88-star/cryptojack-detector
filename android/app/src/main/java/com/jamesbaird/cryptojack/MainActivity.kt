package com.jamesbaird.cryptojack

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.jamesbaird.cryptojack.ui.DashboardScreen
import com.jamesbaird.cryptojack.ui.DetectionDetailSheet
import com.jamesbaird.cryptojack.ui.ScanViewModel
import com.jamesbaird.cryptojack.ui.SettingsSheet
import com.jamesbaird.cryptojack.ui.theme.CryptojackTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            CryptojackTheme {
                val viewModel: ScanViewModel = viewModel()
                val state by viewModel.state.collectAsStateWithLifecycle()

                DashboardScreen(
                    state = state,
                    onRefresh = viewModel::refresh,
                    onOpenSettings = { viewModel.toggleSettings(true) },
                    onSelect = viewModel::select,
                    onDismissError = viewModel::dismissError,
                    onLoadDemo = viewModel::loadDemo
                )

                state.selected?.let { finding ->
                    DetectionDetailSheet(
                        finding = finding,
                        onDismiss = { viewModel.select(null) }
                    )
                }

                if (state.showSettings) {
                    SettingsSheet(
                        settings = state.settings,
                        onSave = viewModel::saveSettings,
                        onDismiss = { viewModel.toggleSettings(false) }
                    )
                }
            }
        }
    }
}
