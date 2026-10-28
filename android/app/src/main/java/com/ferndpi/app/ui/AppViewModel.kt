package com.ferndpi.app.ui

import android.app.Application
import android.content.Intent
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.ferndpi.app.FernDPIApplication
import com.ferndpi.app.core.ConfigEntry
import com.ferndpi.app.core.ConfigRepository
import com.ferndpi.app.core.CoreManager
import com.ferndpi.app.core.CoreState
import com.ferndpi.app.core.Settings
import com.ferndpi.app.core.SettingsRepository
import com.ferndpi.app.service.FernDPIService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class AppViewModel(application: Application) : AndroidViewModel(application) {

    private val app = application as FernDPIApplication
    val settings: StateFlow<Settings> = app.settingsRepository.settings
    val coreState: StateFlow<CoreState> = app.coreManager.state
    val coreLog: StateFlow<List<String>> = app.coreManager.log

    private val _configs = MutableStateFlow<List<ConfigEntry>>(emptyList())
    val configs: StateFlow<List<ConfigEntry>> = _configs

    private val _importFailed = MutableStateFlow(false)
    val importFailed: StateFlow<Boolean> = _importFailed

    private val settingsRepository: SettingsRepository get() = app.settingsRepository
    private val core: CoreManager get() = app.coreManager
    private val configRepository: ConfigRepository get() = app.configRepository

    init {
        reloadConfigs()
    }

    fun reloadConfigs() {
        _configs.value = configRepository.loadAll()
    }

    fun updateSettings(transform: (Settings) -> Settings) {
        settingsRepository.update(transform)
    }

    fun selectConfig(id: String) {
        updateSettings { it.copy(configId = id) }
    }

    fun importConfig(uri: Uri) {
        val label = uri.lastPathSegment?.substringAfterLast('/') ?: "imported"
        val entry = configRepository.importFromUri(uri, label)
        _importFailed.value = entry == null
        if (entry != null) {
            reloadConfigs()
            selectConfig(entry.id)
        }
    }

    fun consumeImportFailed() {
        _importFailed.value = false
    }

    fun connect() {
        val s = settings.value
        core.notePort(s.port)
        val path = configRepository.pathFor(s.configId, _configs.value)
        val args = CoreManager.buildArgs(s, path)
        val intent = Intent(getApplication(), FernDPIService::class.java)
            .putExtra(FernDPIService.EXTRA_ARGS, args.toTypedArray())
        getApplication<FernDPIApplication>().startForegroundService(intent)
    }

    fun disconnect() {
        core.stop()
    }

    fun proxyAddress(): String = "127.0.0.1:${settings.value.port}"
}
