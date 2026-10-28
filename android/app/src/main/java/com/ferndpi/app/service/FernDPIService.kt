package com.ferndpi.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import com.ferndpi.app.FernDPIApplication
import com.ferndpi.app.MainActivity
import com.ferndpi.app.R
import com.ferndpi.app.core.CoreState
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class FernDPIService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        observeCore()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val vpnOnly = intent?.getBooleanExtra(EXTRA_VPN, false) == true
        val args = intent?.getStringArrayExtra(EXTRA_ARGS)?.toList()
        val app = application as FernDPIApplication
        if (vpnOnly) {
            startForegroundNow(getString(R.string.status_connecting))
            notifyState()
        } else if (args != null && !app.coreManager.isRunning()) {
            startForegroundNow(getString(R.string.status_connecting))
            scope.launch(Dispatchers.IO) { app.coreManager.start(args) }
        } else {
            notifyState()
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        releaseWakeLock()
        scope.cancel()
        super.onDestroy()
    }

    private fun observeCore() {
        val app = application as FernDPIApplication
        scope.launch {
            app.coreManager.state.collect { state ->
                notifyState()
                when (state) {
                    is CoreState.Running -> acquireWakeLock()
                    is CoreState.Stopped, is CoreState.Error -> {
                        releaseWakeLock()
                        stopSelf()
                    }
                    else -> Unit
                }
            }
        }
    }

    private fun stateText(): String {
        val app = application as FernDPIApplication
        return when (val state = app.coreManager.state.value) {
            is CoreState.Running -> {
                val time = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
                    .format(Date(state.sinceMillis))
                getString(R.string.status_connected) + " · " +
                    getString(R.string.connected_since, time) + " · " +
                    getString(R.string.proxy_address, app.coreManager.proxyAddress)
            }
            is CoreState.Starting -> getString(R.string.status_connecting)
            is CoreState.Error -> "${getString(R.string.status_error)}: ${state.message}"
            is CoreState.Stopped -> getString(R.string.status_disconnected)
        }
    }

    private fun startForegroundNow(text: String) {
        val notification = buildNotification(getString(R.string.app_name), text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun notifyState() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(getString(R.string.app_name), stateText()))
        val state = (application as FernDPIApplication).coreManager.state.value
        if (state is CoreState.Stopped || state is CoreState.Error) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
    }

    private fun buildNotification(title: String, text: String): Notification {
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setOngoing(true)
            .setContentIntent(contentIntent)
            .setOnlyAlertOnce(true)
            .build()
    }

    private fun createChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.app_name),
            NotificationManager.IMPORTANCE_LOW,
        )
        nm.createNotificationChannel(channel)
    }

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val pm = getSystemService(PowerManager::class.java)
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "FernDPI:core").apply {
            setReferenceCounted(false)
            acquire(10 * 60 * 60 * 1000L)
        }
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }

    companion object {
        const val EXTRA_ARGS = "ferndpi_args"
        const val EXTRA_VPN = "ferndpi_vpn"
        private const val CHANNEL_ID = "ferndpi_core"
        private const val NOTIFICATION_ID = 1
    }
}
