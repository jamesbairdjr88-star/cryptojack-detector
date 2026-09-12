package com.jamesbaird.cryptojack.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val Critical = Color(0xFFD32F2F)
val Warning = Color(0xFFF9A825)
val Ok = Color(0xFF2E7D32)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF7FD1B9),
    onPrimary = Color(0xFF00382B),
    secondary = Color(0xFF9BCBFF),
    background = Color(0xFF101418),
    surface = Color(0xFF161B20)
)

private val LightColors = lightColorScheme(
    primary = Color(0xFF00695C),
    onPrimary = Color.White,
    secondary = Color(0xFF1565C0),
    background = Color(0xFFF6F8FA),
    surface = Color.White
)

@Composable
fun CryptojackTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        typography = Typography(),
        content = content
    )
}
