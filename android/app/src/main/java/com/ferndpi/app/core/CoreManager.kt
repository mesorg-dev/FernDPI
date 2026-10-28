package com.ferndpi.app.core

import android.content.Context
import android.os.Build
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

sealed interface CoreState {
    data object Stopped : CoreState
    data object Starting : CoreState
    data class Running(val sinceMillis: Long) : CoreState
    data class Error(val message: String) : CoreState
}

class CoreManager(context: Context) {

    private val appContext = context.applicationContext
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val logLock = Any()
    private val logBuffer = ArrayDeque<String>()

    private val _state = MutableStateFlow<CoreState>(CoreState.Stopped)
    val state: StateFlow<CoreState> = _state

    private val _log = MutableStateFlow<List<String>>(emptyList())
    val log: StateFlow<List<String>> = _log

    @Volatile
    private var process: Process? = null

    val proxyAddress: String get() = "127.0.0.1:${_currentPort}"

    @Volatile
    private var _currentPort: Int = 1080

    fun isRunning(): Boolean = process?.let { it.isAlive } == true

    @Synchronized
    fun start(args: List<String>): Boolean {
        if (isRunning()) return true
        val binary = prepareBinary()
        if (binary == null) {
            _state.value = CoreState.Error("core binary missing for ABI ${Build.SUPPORTED_ABIS.firstOrNull()}")
            appendLog("error: core binary not found for this ABI")
            return false
        }
        _state.value = CoreState.Starting
        return runCatching {
            val pb = ProcessBuilder(listOf(binary.absolutePath) + args)
                .directory(appContext.filesDir)
                .redirectErrorStream(true)
            val proc = pb.start()
            process = proc
            appendLog("$ ${binary.name} ${args.joinToString(" ")}")
            scope.launch { pumpOutput(proc) }
            scope.launch {
                proc.waitFor()
                synchronized(this) {
                    if (process === proc) {
                        process = null
                        val code = proc.exitValue()
                        if (_state.value is CoreState.Starting || _state.value is CoreState.Running) {
                            _state.value =
                                if (code == 0) CoreState.Stopped
                                else CoreState.Error("core exited with code $code")
                        }
                        appendLog("core exited with code $code")
                    }
                }
            }
            _state.value = CoreState.Running(System.currentTimeMillis())
            appendLog("core started")
            true
        }.getOrElse { e ->
            process = null
            _state.value = CoreState.Error(e.message ?: "failed to start core")
            appendLog("error: ${e.message}")
            false
        }
    }

    @Synchronized
    fun stop() {
        val proc = process ?: return
        _state.value = CoreState.Stopped
        appendLog("stopping core…")
        proc.destroy()
        scope.launch {
            runCatching {
                if (!proc.waitFor(3, TimeUnit.SECONDS)) {
                    proc.destroyForcibly()
                }
            }
            process = null
        }
    }

    fun currentPort(): Int = _currentPort

    fun notePort(port: Int) {
        _currentPort = port
    }

    private fun pumpOutput(proc: Process) {
        runCatching {
            BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    line?.let { appendLog(it) }
                }
            }
        }
    }

    private fun appendLog(line: String) {
        val stamp = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        synchronized(logLock) {
            if (logBuffer.size >= MAX_LOG_LINES) logBuffer.removeFirst()
            logBuffer.addLast("$stamp  $line")
            _log.value = logBuffer.toList()
        }
    }

    private fun prepareBinary(): File? {
        val abi = Build.SUPPORTED_ABIS.firstOrNull { it in SUPPORTED_ABIS } ?: return null
        val out = File(appContext.filesDir, "bin/ferndpi")
        if (out.isFile && out.length() > 0L && out.canExecute()) return out
        return runCatching {
            out.parentFile?.mkdirs()
            appContext.assets.open("core/$abi").use { input ->
                out.outputStream().use { input.copyTo(it) }
            }
            out.setExecutable(true, false)
            out.takeIf { it.canExecute() }
        }.getOrNull()
    }

    companion object {
        private const val MAX_LOG_LINES = 300
        private val SUPPORTED_ABIS = setOf("arm64-v8a", "armeabi-v7a", "x86_64")

        fun buildArgs(settings: Settings, configPath: String?): List<String> {
            val lang = when (settings.lang) {
                "system" -> when (Locale.getDefault().language) {
                    "ru" -> "ru"
                    else -> "en"
                }
                else -> settings.lang
            }
            val args = mutableListOf(
                "--listen", "127.0.0.1:${settings.port}",
                "--lang", lang,
            )
            if (configPath != null) {
                args += listOf("-c", configPath)
            } else if (settings.strategy == "none") {
                args += "--no-split"
            } else {
                args += listOf(
                    "--dpi-desync", settings.strategy,
                    "--dpi-desync-split-pos", settings.splitPos,
                    "--dpi-desync-frag-size", settings.fragSize.toString(),
                    "--dpi-desync-delay-ms", settings.delayMs.toString(),
                )
            }
            return args
        }
    }
}
