package io.github.nilotpal.authkey.lock

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import io.github.nilotpal.authkey.MainActivity
import io.github.nilotpal.authkey.Prefs
import io.github.nilotpal.authkey.R
import io.github.nilotpal.authkey.ble.AuthKeyDevice

/**
 * Walk-away lock. Watches the AuthKey's Bluetooth adverts (it advertises all
 * the time, even while connected) and locks the phone once it has been out of
 * range for [Prefs.awaySeconds].
 *
 * Same rules as the PC helper: it only locks after it has seen the AuthKey
 * nearby, and each lock disarms it until the AuthKey is nearby again, so
 * unlocking with your PIN while the AuthKey is away doesn't lock again.
 */
class PresenceService : Service() {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var prefs: Prefs
    private var lastNear = 0L          // elapsedRealtime of the last strong-enough advert, 0 = never
    private var lastRssi: Int? = null
    private var armed = false
    private var scanning = false
    private var lastTick = 0L
    private var shownText = ""

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        prefs = Prefs(this)
        val filter = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(btState, filter, RECEIVER_EXPORTED)
        else registerReceiver(btState, filter)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundCompat(notification(getString(R.string.lock_waiting)))
        running = true
        startScan()
        handler.removeCallbacks(tick)
        lastTick = SystemClock.elapsedRealtime()
        handler.postDelayed(tick, 1000)
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        handler.removeCallbacks(tick)
        stopScan()
        unregisterReceiver(btState)
        super.onDestroy()
    }

    // --- Scanning ----------------------------------------------------------------

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            lastRssi = result.rssi
            if (result.rssi >= prefs.minRssi) lastNear = SystemClock.elapsedRealtime()
        }

        override fun onBatchScanResults(results: MutableList<ScanResult>) = results.forEach { onScanResult(0, it) }

        override fun onScanFailed(errorCode: Int) {
            Log.w(TAG, "scan failed $errorCode")
            scanning = false
        }
    }

    @SuppressLint("MissingPermission")
    private fun startScan() {
        if (scanning || !AuthKeyDevice.hasPermissions(this)) return
        val adapter = getSystemService(BluetoothManager::class.java)?.adapter ?: return
        val scanner = adapter.bluetoothLeScanner ?: return   // Bluetooth off
        val address = prefs.deviceAddress ?: AuthKeyDevice.bonded(this)?.address
        // A filter keeps the scan running with the screen off.
        val filter = if (address != null) ScanFilter.Builder().setDeviceAddress(address).build()
                     else ScanFilter.Builder().setDeviceName(AuthKeyDevice.NAME).build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_BALANCED)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .build()
        try {
            scanner.startScan(listOf(filter), settings, scanCallback)
            scanning = true
        } catch (e: Exception) {
            Log.w(TAG, "startScan: $e")
        }
    }

    @SuppressLint("MissingPermission")
    private fun stopScan() {
        if (!scanning) return
        scanning = false
        try {
            getSystemService(BluetoothManager::class.java)?.adapter?.bluetoothLeScanner?.stopScan(scanCallback)
        } catch (_: Exception) {}
    }

    private val btState = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
            when (i.getIntExtra(BluetoothAdapter.EXTRA_STATE, -1)) {
                BluetoothAdapter.STATE_ON -> startScan()
                BluetoothAdapter.STATE_OFF -> { scanning = false; armed = false }
            }
        }
    }

    // --- Decision, once a second ---------------------------------------------------

    private val tick = object : Runnable {
        override fun run() {
            val now = SystemClock.elapsedRealtime()
            if (now - lastTick > 10_000 && armed) lastNear = now   // the phone slept: give adverts time
            lastTick = now
            if (!scanning) startScan()
            val since = if (lastNear == 0L) Long.MAX_VALUE else now - lastNear
            val near = since < 5_000
            val away = since > prefs.awaySeconds * 1000L
            if (near && !armed) {
                armed = true
            } else if (armed && away) {
                armed = false
                if (!ScreenLock.isLocked(this@PresenceService)) {
                    val ok = ScreenLock.lock(this@PresenceService)
                    Log.i(TAG, if (ok) "AuthKey away: locked" else "AuthKey away: no lock method enabled")
                }
            }
            update(when {
                armed -> getString(R.string.lock_armed, lastRssi ?: 0)
                !ScreenLock.canLock(this@PresenceService) -> getString(R.string.lock_no_method)
                else -> getString(R.string.lock_waiting)
            })
            lastState = if (armed) "armed, ${lastRssi} dBm" else "waiting for the AuthKey"
            handler.postDelayed(this, 1000)
        }
    }

    // --- Notification ------------------------------------------------------------------

    private fun notification(text: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL, getString(R.string.lock_channel),
                NotificationManager.IMPORTANCE_LOW))
        }
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_key)
            .setContentTitle(getString(R.string.lock_title))
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    private fun update(text: String) {
        if (text == shownText) return
        shownText = text
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(text))
    }

    private fun startForegroundCompat(n: Notification) {
        when {
            // Android 12+: BLUETOOTH_SCAN (never for location) is enough.
            Build.VERSION.SDK_INT >= 31 ->
                startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
            // Android 10-11: Bluetooth scans count as location access, which a
            // background app only keeps through a location-type service.
            Build.VERSION.SDK_INT >= 29 -> startForeground(NOTIFICATION_ID, n,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE or ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
            else -> startForeground(NOTIFICATION_ID, n)
        }
    }

    companion object {
        private const val TAG = "AuthKeyLock"
        private const val CHANNEL = "walk_away"
        private const val NOTIFICATION_ID = 1
        @Volatile var running = false
        @Volatile var lastState = ""

        fun start(ctx: Context) = ctx.startForegroundService(Intent(ctx, PresenceService::class.java))
        fun stop(ctx: Context) = ctx.stopService(Intent(ctx, PresenceService::class.java))
    }
}

/** Restarts the walk-away lock after a reboot or an app update. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        if (Prefs(ctx).lockEnabled && AuthKeyDevice.hasPermissions(ctx)) PresenceService.start(ctx)
    }
}
