package com.ferndpi.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.ferndpi.app.core.CoreManager
import com.ferndpi.app.service.FernDPIService
import com.ferndpi.app.vpn.FernDPIVpnService

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val app = context.applicationContext as? FernDPIApplication ?: return
        val settings = app.settingsRepository.settings.value
        if (!settings.autoStart || app.coreManager.isRunning()) return
        val path = app.configRepository.pathFor(settings.configId, app.configRepository.loadAll())
        val args = CoreManager.buildArgs(settings, path)
        if (settings.vpnMode) {
            val vpnIntent = Intent(context, FernDPIVpnService::class.java)
                .setAction(FernDPIVpnService.ACTION_CONNECT)
                .putExtra(FernDPIVpnService.EXTRA_ARGS, args.toTypedArray())
                .putExtra(FernDPIVpnService.EXTRA_PORT, settings.port)
                .putStringArrayListExtra(
                    FernDPIVpnService.EXTRA_EXCLUDED,
                    ArrayList(settings.excludedApps),
                )
            runCatching { context.startService(vpnIntent) }
            val notify = Intent(context, FernDPIService::class.java)
                .putExtra(FernDPIService.EXTRA_VPN, true)
            runCatching { context.startForegroundService(notify) }
        } else {
            val serviceIntent = Intent(context, FernDPIService::class.java)
                .putExtra(FernDPIService.EXTRA_ARGS, args.toTypedArray())
            context.startForegroundService(serviceIntent)
        }
    }
}
