package com.ferndpi.app.core

/**
 * In-process FernDPI core (libferndpi_android.so).
 *
 * The library is loaded lazily: the plain SOCKS5 mode runs the core as an
 * external process and must not depend on this .so at app startup. All entry
 * points are wrapped so a linkage problem can never crash the process — it is
 * reported via [onLinkError] (or returns false) instead.
 *
 * Note: plain `object` (not a class with a companion) so the JNI symbols stay
 * `Java_com_fernndpi_app_core_NativeCore_*` without a Companion suffix.
 */
object NativeCore {

    fun interface LogSink {
        fun onLog(line: String)
    }

    @Volatile
    private var loaded: Boolean? = null

    /** Optional diagnostics hook (set by the application). */
    @Volatile
    var onLinkError: ((Throwable) -> Unit)? = null

    private fun ensureLoaded(): Boolean {
        loaded?.let { return it }
        synchronized(this) {
            loaded?.let { return it }
            val ok = runCatching { System.loadLibrary("ferndpi_android") }
                .onFailure { onLinkError?.invoke(it) }
                .isSuccess
            loaded = ok
            return ok
        }
    }

    fun start(argsJson: String, vpnService: Any?): Boolean {
        if (!ensureLoaded()) return false
        return runCatching { start0(argsJson, vpnService) }
            .onFailure { onLinkError?.invoke(it) }
            .getOrElse { false }
    }

    fun stop() {
        if (loaded == true) {
            runCatching { stop0() }.onFailure { onLinkError?.invoke(it) }
        }
    }

    fun isRunning(): Boolean {
        if (loaded != true) return false
        return runCatching { isRunning0() }.getOrDefault(false)
    }

    fun setLogSink(sink: LogSink?) {
        if (!ensureLoaded()) return
        runCatching { setLogSink0(sink) }.onFailure { onLinkError?.invoke(it) }
    }

    private external fun start0(argsJson: String, vpnService: Any?): Boolean

    private external fun stop0()

    private external fun isRunning0(): Boolean

    private external fun setLogSink0(sink: LogSink?)
}
