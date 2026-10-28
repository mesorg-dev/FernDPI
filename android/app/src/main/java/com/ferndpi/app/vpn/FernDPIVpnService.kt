package com.ferndpi.app.vpn

import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.IBinder
import com.ferndpi.app.FernDPIApplication
import com.ferndpi.app.core.CoreManager
import com.ferndpi.app.core.CoreState
import com.ferndpi.app.core.NativeCore
import hev.htproxy.TProxyService
import java.io.File
import org.json.JSONArray

/**
 * VPN mode: establish a tun, run tun2socks (hev-socks5-tunnel) on it and point
 * it at the in-process FernDPI core. The core protects its own sockets via
 * [VpnService.protect] so its traffic never loops back into the tun.
 */
class FernDPIVpnService : VpnService() {

    private val core: CoreManager
        get() = (application as FernDPIApplication).coreManager

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null || intent.action == ACTION_DISCONNECT) {
            disconnect()
            return START_NOT_STICKY
        }
        connect(intent)
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        disconnect()
    }

    override fun onDestroy() {
        disconnect()
        super.onDestroy()
    }

    private fun connect(intent: Intent) {
        if (isRunning) return
        val args = intent.getStringArrayExtra(EXTRA_ARGS)?.toList().orEmpty()
        val port = intent.getIntExtra(EXTRA_PORT, 1080)
        val excluded = intent.getStringArrayListExtra(EXTRA_EXCLUDED) ?: arrayListOf()

        core.noteVpnStarting()

        val builder = Builder()
            .setSession("FernDPI")
            .setMtu(1500)
            .addAddress("10.111.222.1", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
        excluded.forEach { pkg -> runCatching { builder.addDisallowedApplication(pkg) } }

        val tun = runCatching { builder.establish() }.getOrNull()
        if (tun == null) {
            fail("tun establish failed")
            return
        }

        val yaml = File(cacheDir, "tun2socks.yml")
        runCatching {
            yaml.writeText(
                """
                socks5:
                  port: $port
                  address: 127.0.0.1
                  udp: udp
                """.trimIndent(),
            )
        }.onFailure {
            runCatching { tun.close() }
            fail("tun2socks config: $it")
            return
        }

        val argsJson = JSONArray(args).toString()
        NativeCore.setLogSink { line -> core.appendExternalLog(line) }
        if (!NativeCore.start(argsJson, this)) {
            runCatching { tun.close() }
            fail("core failed to start")
            return
        }

        val fd = tun.detachFd()
        if (!TProxyService.TProxyStartService(yaml.absolutePath, fd)) {
            NativeCore.stop()
            fail("tun2socks failed to start")
            return
        }

        isRunning = true
        core.noteVpnStarted()
        appendLog("vpn up: tun + tun2socks -> socks5 127.0.0.1:$port")
    }

    private fun disconnect() {
        if (!isRunning) return
        isRunning = false
        appendLog("stopping vpn…")
        runCatching { TProxyService.TProxyStopService() }
        runCatching { NativeCore.stop() }
        core.noteVpnStopped()
        stopSelf()
    }

    private fun fail(message: String) {
        appendLog("error: $message")
        core.noteVpnError(message)
        stopSelf()
    }

    private fun appendLog(line: String) = core.appendExternalLog(line)

    companion object {
        const val ACTION_CONNECT = "com.ferndpi.app.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.ferndpi.app.vpn.DISCONNECT"
        const val EXTRA_ARGS = "ferndpi_vpn_args"
        const val EXTRA_PORT = "ferndpi_vpn_port"
        const val EXTRA_EXCLUDED = "ferndpi_vpn_excluded"

        @Volatile
        var isRunning: Boolean = false
            private set

        fun isStarted(): Boolean = isRunning
    }
}
