package com.ferndpi.app.core

/**
 * In-process FernDPI core (libferndpi_android.so).
 *
 * `start` takes a JSON array of CLI arguments and the active [android.net.VpnService]
 * so every outgoing socket can be protected from the tun.
 *
 * Note: plain `object` (not a class with a companion) so the JNI symbols stay
 * `Java_com_fernndpi_app_core_NativeCore_*` without a Companion suffix.
 */
object NativeCore {

    fun interface LogSink {
        fun onLog(line: String)
    }

    init {
        System.loadLibrary("ferndpi_android")
    }

    external fun start(argsJson: String, vpnService: Any?): Boolean

    external fun stop()

    external fun isRunning(): Boolean

    external fun setLogSink(sink: LogSink?)
}
