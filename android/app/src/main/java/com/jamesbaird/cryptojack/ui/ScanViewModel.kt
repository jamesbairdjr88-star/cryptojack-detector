package com.jamesbaird.cryptojack.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.jamesbaird.cryptojack.data.DetectorSettings
import com.jamesbaird.cryptojack.data.Finding
import com.jamesbaird.cryptojack.data.ScanReport
import com.jamesbaird.cryptojack.data.ScanRepository
import com.jamesbaird.cryptojack.data.SettingsStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

data class ScanUiState(
    val isLoading: Boolean = false,
    val report: ScanReport? = null,
    val settings: DetectorSettings = DetectorSettings(),
    val selected: Finding? = null,
    val showSettings: Boolean = false,
    val isDemo: Boolean = false,
    val error: String? = null
)

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val repository = ScanRepository()
    private val settingsStore = SettingsStore(app.applicationContext)

    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            val settings = settingsStore.settings.first()
            _state.value = _state.value.copy(settings = settings)
            if (settings.isConfigured) refresh() else loadDemo()
        }
    }

    fun refresh() {
        viewModelScope.launch {
            val settings = settingsStore.settings.first()
            if (!settings.isConfigured) {
                _state.value = _state.value.copy(
                    settings = settings,
                    showSettings = true,
                    error = "Add your detector host to run a live scan."
                )
                return@launch
            }
            _state.value = _state.value.copy(isLoading = true, error = null, settings = settings)
            repository.loadReport(settings)
                .onSuccess { report ->
                    _state.value = _state.value.copy(
                        isLoading = false,
                        report = report,
                        isDemo = false,
                        error = null
                    )
                }
                .onFailure { throwable ->
                    _state.value = _state.value.copy(
                        isLoading = false,
                        error = throwable.message ?: "Could not reach the detector host."
                    )
                }
        }
    }

    fun loadDemo() {
        _state.value = _state.value.copy(
            report = repository.demoReport(),
            isDemo = true,
            isLoading = false,
            error = null
        )
    }

    fun saveSettings(baseUrl: String, token: String) {
        viewModelScope.launch {
            settingsStore.save(baseUrl, token)
            _state.value = _state.value.copy(
                settings = DetectorSettings(baseUrl.trim(), token.trim()),
                showSettings = false
            )
            refresh()
        }
    }

    fun select(finding: Finding?) {
        _state.value = _state.value.copy(selected = finding)
    }

    fun toggleSettings(show: Boolean) {
        _state.value = _state.value.copy(showSettings = show)
    }

    fun dismissError() {
        _state.value = _state.value.copy(error = null)
    }
}
