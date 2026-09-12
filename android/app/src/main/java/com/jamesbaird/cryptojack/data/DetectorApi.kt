package com.jamesbaird.cryptojack.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Read-only client for the detector's local report endpoint.
 * The app never issues commands to the host; it only fetches the latest report.
 */
class DetectorApi(
    private val client: OkHttpClient = defaultClient,
    private val json: Json = Json { ignoreUnknownKeys = true; isLenient = true }
) {

    suspend fun fetchReport(baseUrl: String, token: String?): ScanReport =
        withContext(Dispatchers.IO) {
            val url = baseUrl.trimEnd('/') + "/report.json"
            val request = Request.Builder()
                .url(url)
                .header("Accept", "application/json")
                .apply { if (!token.isNullOrBlank()) header("Authorization", "Bearer $token") }
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw IOException("Detector returned HTTP ${response.code}")
                }
                val body = response.body?.string().orEmpty()
                if (body.isBlank()) throw IOException("Detector returned an empty report")
                json.decodeFromString(ScanReport.serializer(), body)
            }
        }

    companion object {
        private val defaultClient: OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .build()
    }
}
