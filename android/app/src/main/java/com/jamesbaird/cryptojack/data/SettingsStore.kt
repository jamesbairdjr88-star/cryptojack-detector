package com.jamesbaird.cryptojack.data

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "cryptojack_settings")

data class DetectorSettings(
    val baseUrl: String = "",
    val token: String = ""
) {
    val isConfigured: Boolean get() = baseUrl.isNotBlank()
}

class SettingsStore(private val context: Context) {

    private val baseUrlKey = stringPreferencesKey("base_url")
    private val tokenKey = stringPreferencesKey("token")

    val settings: Flow<DetectorSettings> = context.dataStore.data.map { prefs ->
        DetectorSettings(
            baseUrl = prefs[baseUrlKey].orEmpty(),
            token = prefs[tokenKey].orEmpty()
        )
    }

    suspend fun save(baseUrl: String, token: String) {
        context.dataStore.edit { prefs ->
            prefs[baseUrlKey] = baseUrl.trim()
            prefs[tokenKey] = token.trim()
        }
    }
}
