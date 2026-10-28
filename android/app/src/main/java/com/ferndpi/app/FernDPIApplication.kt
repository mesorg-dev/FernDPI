package com.ferndpi.app

import android.app.Application
import com.ferndpi.app.core.ConfigRepository
import com.ferndpi.app.core.CoreManager
import com.ferndpi.app.core.NativeCore
import com.ferndpi.app.core.SettingsRepository

class FernDPIApplication : Application() {

    lateinit var settingsRepository: SettingsRepository
        private set
    lateinit var configRepository: ConfigRepository
        private set
    lateinit var coreManager: CoreManager
        private set

    override fun onCreate() {
        super.onCreate()
        settingsRepository = SettingsRepository(this)
        configRepository = ConfigRepository(this)
        coreManager = CoreManager(this)
        // The native bridge (.so) is loaded lazily by NativeCore — never here.
        NativeCore.onLinkError = { e ->
            coreManager.appendExternalLog("native bridge error: ${e.message}")
        }
    }
}
