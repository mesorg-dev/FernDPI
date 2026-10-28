package com.ferndpi.app.core

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

enum class ThemeMode { SYSTEM, LIGHT, DARK }

data class Settings(
    val themeMode: ThemeMode = ThemeMode.SYSTEM,
    val dynamicColor: Boolean = true,
    val port: Int = 1080,
    val strategy: String = "split",
    val splitPos: String = "mid",
    val fragSize: Int = 64,
    val delayMs: Int = 0,
    val lang: String = "system",
    val autoStart: Boolean = false,
    val configId: String = ConfigRepository.CUSTOM_ID,
    val vpnMode: Boolean = true,
    val excludedApps: Set<String> = emptySet(),
)

class SettingsRepository(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("ferndpi_settings", Context.MODE_PRIVATE)

    private val _settings = MutableStateFlow(load())
    val settings: StateFlow<Settings> = _settings

    private fun load(): Settings {
        val s = Settings()
        return Settings(
            themeMode = runCatching { ThemeMode.valueOf(prefs.getString(KEY_THEME, s.themeMode.name)!!) }
                .getOrDefault(s.themeMode),
            dynamicColor = prefs.getBoolean(KEY_DYNAMIC, s.dynamicColor),
            port = prefs.getInt(KEY_PORT, s.port).coerceIn(1024, 65535),
            strategy = prefs.getString(KEY_STRATEGY, s.strategy) ?: s.strategy,
            splitPos = prefs.getString(KEY_SPLIT_POS, s.splitPos) ?: s.splitPos,
            fragSize = prefs.getInt(KEY_FRAG_SIZE, s.fragSize).coerceIn(16, 1500),
            delayMs = prefs.getInt(KEY_DELAY, s.delayMs).coerceIn(0, 5000),
            lang = prefs.getString(KEY_LANG, s.lang) ?: s.lang,
            autoStart = prefs.getBoolean(KEY_AUTOSTART, s.autoStart),
            configId = prefs.getString(KEY_CONFIG, s.configId) ?: s.configId,
            vpnMode = prefs.getBoolean(KEY_VPN_MODE, s.vpnMode),
            excludedApps = prefs.getStringSet(KEY_EXCLUDED, emptySet())?.toSet() ?: emptySet(),
        )
    }

    private fun persist(s: Settings) {
        prefs.edit()
            .putString(KEY_THEME, s.themeMode.name)
            .putBoolean(KEY_DYNAMIC, s.dynamicColor)
            .putInt(KEY_PORT, s.port)
            .putString(KEY_STRATEGY, s.strategy)
            .putString(KEY_SPLIT_POS, s.splitPos)
            .putInt(KEY_FRAG_SIZE, s.fragSize)
            .putInt(KEY_DELAY, s.delayMs)
            .putString(KEY_LANG, s.lang)
            .putBoolean(KEY_AUTOSTART, s.autoStart)
            .putString(KEY_CONFIG, s.configId)
            .putBoolean(KEY_VPN_MODE, s.vpnMode)
            .putStringSet(KEY_EXCLUDED, s.excludedApps)
            .apply()
        _settings.update { s }
    }

    fun update(transform: (Settings) -> Settings) {
        persist(transform(_settings.value))
    }

    companion object {
        private const val KEY_THEME = "theme_mode"
        private const val KEY_DYNAMIC = "dynamic_color"
        private const val KEY_PORT = "socks_port"
        private const val KEY_STRATEGY = "strategy"
        private const val KEY_SPLIT_POS = "split_pos"
        private const val KEY_FRAG_SIZE = "frag_size"
        private const val KEY_DELAY = "delay_ms"
        private const val KEY_LANG = "lang"
        private const val KEY_AUTOSTART = "autostart"
        private const val KEY_CONFIG = "config_id"
        private const val KEY_VPN_MODE = "vpn_mode"
        private const val KEY_EXCLUDED = "excluded_apps"
    }
}
