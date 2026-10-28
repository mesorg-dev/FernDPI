package com.ferndpi.app.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import com.ferndpi.app.core.ThemeMode

private val LightColors = lightColorScheme(
    primary = FernLightPrimary,
    onPrimary = FernLightOnPrimary,
    primaryContainer = FernLightPrimaryContainer,
    onPrimaryContainer = FernLightOnPrimaryContainer,
    secondary = FernLightSecondary,
    onSecondary = FernLightOnSecondary,
    secondaryContainer = FernLightSecondaryContainer,
    onSecondaryContainer = FernLightOnSecondaryContainer,
    tertiary = FernLightTertiary,
    onTertiary = FernLightOnTertiary,
    tertiaryContainer = FernLightTertiaryContainer,
    onTertiaryContainer = FernLightOnTertiaryContainer,
    error = FernLightError,
    onError = FernLightOnError,
    background = FernLightBackground,
    onBackground = FernLightOnBackground,
    surface = FernLightSurface,
    onSurface = FernLightOnSurface,
    surfaceVariant = FernLightSurfaceVariant,
    onSurfaceVariant = FernLightOnSurfaceVariant,
    outline = FernLightOutline,
)

private val DarkColors = darkColorScheme(
    primary = FernDarkPrimary,
    onPrimary = FernDarkOnPrimary,
    primaryContainer = FernDarkPrimaryContainer,
    onPrimaryContainer = FernDarkOnPrimaryContainer,
    secondary = FernDarkSecondary,
    onSecondary = FernDarkOnSecondary,
    secondaryContainer = FernDarkSecondaryContainer,
    onSecondaryContainer = FernDarkOnSecondaryContainer,
    tertiary = FernDarkTertiary,
    onTertiary = FernDarkOnTertiary,
    tertiaryContainer = FernDarkTertiaryContainer,
    onTertiaryContainer = FernDarkOnTertiaryContainer,
    error = FernDarkError,
    onError = FernDarkOnError,
    background = FernDarkBackground,
    onBackground = FernDarkOnBackground,
    surface = FernDarkSurface,
    onSurface = FernDarkOnSurface,
    surfaceVariant = FernDarkSurfaceVariant,
    onSurfaceVariant = FernDarkOnSurfaceVariant,
    outline = FernDarkOutline,
)

@Composable
fun FernDPITheme(
    themeMode: ThemeMode = ThemeMode.SYSTEM,
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit,
) {
    val darkTheme = when (themeMode) {
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
        ThemeMode.LIGHT -> false
        ThemeMode.DARK -> true
    }
    val context = LocalContext.current
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        darkTheme -> DarkColors
        else -> LightColors
    }
    MaterialTheme(
        colorScheme = colorScheme,
        typography = AppTypography,
        content = content,
    )
}
