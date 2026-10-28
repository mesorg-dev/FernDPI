package com.ferndpi.app.ui

import android.app.Application
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.provider.Settings
import androidx.activity.result.ActivityResult
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.ferndpi.app.FernDPIApplication
import com.ferndpi.app.core.ConfigEntry
import com.ferndpi.app.core.ConfigRepository
import com.ferndpi.app.core.CoreManager
import com.ferndpi.app.core.CoreState
import com.ferndpi.app.core.Settings as AppSettings
import com.ferndpi.app.core.SettingsRepository
import com.ferndpi.app.service.FernDPIService
import com.ferndpi.app.vpn.FernDPIVpnService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class AppViewModel(application: Application) : AndroidViewModel(application) {

    private val app = application as FernDPIApplication
    val settings: StateFlow<AppSettings> = app.settingsRepository.settings
    val coreState: StateFlow<CoreState> = app.coreManager.state
    val coreLog: StateFlow<List<String>> = app.coreManager.log

    private val _configs = MutableStateFlow<List<ConfigEntry>>(emptyList())
    val configs: StateFlow<List<ConfigEntry>> = _configs

    private val _importFailed = MutableStateFlow(false)
    val importFailed: StateFlow<Boolean> = _importFailed

    /** Set by MainActivity: launches the VpnService consent dialog. */
    var vpnPermissionLauncher: ((Intent) -> Unit)? = null

    private var pendingVpnArgs: List<String>? = null

    private val settingsRepository: SettingsRepository get() = app.settingsRepository
    private val core: CoreManager get() = app.coreManager
    private val configRepository: ConfigRepository get() = app.configRepository

    init {
        reloadConfigs()
    }

    fun reloadConfigs() {
        _configs.value = configRepository.loadAll()
    }

    fun updateSettings(transform: (AppSettings) -> AppSettings) {
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
        if (s.vpnMode) {
            val prepare = VpnService.prepare(app)
            if (prepare != null) {
                pendingVpnArgs = args
                vpnPermissionLauncher?.invoke(prepare)
            } else {
                startVpn(args)
            }
        } else {
            startSocks(args)
        }
    }

    fun onVpnPermissionResult(result: ActivityResult) {
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            val args = pendingVpnArgs ?: return
            pendingVpnArgs = null
            startVpn(args)
        } else {
            pendingVpnArgs = null
            core.noteVpnError("VPN permission denied")
        }
    }

    fun disconnect() {
        if (FernDPIVpnService.isStarted()) {
            val intent = Intent(app, FernDPIVpnService::class.java)
                .setAction(FernDPIVpnService.ACTION_DISCONNECT)
            runCatching { app.startService(intent) }
        } else {
            core.stop()
        }
    }

    fun isVpnActive(): Boolean = FernDPIVpnService.isStarted()

    fun openSystemVpnSettings() {
        runCatching {
            getApplication<Application>().startActivity(
                Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }
    }

    fun excludedAppCount(): Int = settings.value.excludedApps.size

    private fun startSocks(args: List<String>) {
        val intent = Intent(app, FernDPIService::class.java)
            .putExtra(FernDPIService.EXTRA_ARGS, args.toTypedArray())
        app.startForegroundService(intent)
    }

    private fun startVpn(args: List<String>) {
        val s = settings.value
        val intent = Intent(app, FernDPIVpnService::class.java)
            .setAction(FernDPIVpnService.ACTION_CONNECT)
            .putExtra(FernDPIVpnService.EXTRA_ARGS, args.toTypedArray())
            .putExtra(FernDPIVpnService.EXTRA_PORT, s.port)
            .putStringArrayListExtra(
                FernDPIVpnService.EXTRA_EXCLUDED,
                ArrayList(s.excludedApps),
            )
        runCatching { app.startService(intent) }
            .onFailure { core.noteVpnError(it.message ?: "failed to start VPN") }

        val notify = Intent(app, FernDPIService::class.java)
            .putExtra(FernDPIService.EXTRA_VPN, true)
        app.startForegroundService(notify)
    }

    fun proxyAddress(): String = "127.0.0.1:${settings.value.port}"
}
