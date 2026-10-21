package io.github.nilotpal.authkey

import android.Manifest
import android.app.admin.DevicePolicyManager
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat
import androidx.core.net.toUri
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.CredentialManager
import androidx.lifecycle.lifecycleScope
import com.google.android.material.materialswitch.MaterialSwitch
import io.github.nilotpal.authkey.ble.AuthKeyDevice
import io.github.nilotpal.authkey.ctap.Ctap
import io.github.nilotpal.authkey.ctap.Transports
import io.github.nilotpal.authkey.ctap.int
import io.github.nilotpal.authkey.lock.PresenceService
import io.github.nilotpal.authkey.lock.ScreenLock
import io.github.nilotpal.authkey.qr.ScanActivity
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {
    private lateinit var prefs: Prefs
    private val handler = Handler(Looper.getMainLooper())

    private val askPermissions = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        refresh()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        prefs = Prefs(this)

        btn(R.id.grant) { askPermissions.launch(neededPermissions()) }
        btn(R.id.btSettings) { startActivity(Intent(Settings.ACTION_BLUETOOTH_SETTINGS)) }
        btn(R.id.test) { testConnection() }

        val lockSwitch = findViewById<MaterialSwitch>(R.id.lockSwitch)
        lockSwitch.isChecked = prefs.lockEnabled
        lockSwitch.setOnCheckedChangeListener { _, on ->
            prefs.lockEnabled = on
            if (on) {
                PresenceService.start(this)
                if (!batteryExempt()) requestBatteryExemption()
            } else {
                PresenceService.stop(this)
            }
            refresh()
        }
        btn(R.id.battery) { requestBatteryExemption() }
        btn(R.id.notifications) {
            startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
        }
        btn(R.id.appSettings) {
            startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, "package:$packageName".toUri()))
        }
        val away = findViewById<EditText>(R.id.awaySeconds)
        val rssi = findViewById<EditText>(R.id.minRssi)
        away.setText(prefs.awaySeconds.toString())
        rssi.setText(prefs.minRssi.toString())
        btn(R.id.saveLock) {
            away.text.toString().toIntOrNull()?.let { prefs.awaySeconds = it }
            rssi.text.toString().toIntOrNull()?.let { prefs.minRssi = if (it > 0) -it else it }
            away.setText(prefs.awaySeconds.toString())
            rssi.setText(prefs.minRssi.toString())
            if (prefs.lockEnabled) { PresenceService.stop(this); PresenceService.start(this) }
        }
        btn(R.id.lockNormal) { startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) }
        btn(R.id.lockStrict) {
            startActivity(Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
                .putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, ScreenLock.adminComponent(this))
                .putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, getString(R.string.lock_strict_explain)))
        }

        btn(R.id.providerSettings) {
            if (Build.VERSION.SDK_INT >= 34) {
                try { CredentialManager.create(this).createSettingsPendingIntent().send() }
                catch (_: Exception) { startActivity(Intent(Settings.ACTION_SETTINGS)) }
            }
        }
        findViewById<TextView>(R.id.providerInfo).setText(
            if (Build.VERSION.SDK_INT >= 34) R.string.provider_info else R.string.provider_unavailable)
        findViewById<Button>(R.id.providerSettings).isEnabled = Build.VERSION.SDK_INT >= 34

        btn(R.id.scan) { startActivity(Intent(this, ScanActivity::class.java)) }
    }

    override fun onResume() {
        super.onResume()
        refresh()
        if (prefs.lockEnabled && AuthKeyDevice.hasPermissions(this) && !PresenceService.running) PresenceService.start(this)
        handler.post(ticker)
    }

    override fun onPause() {
        handler.removeCallbacks(ticker)
        super.onPause()
    }

    private val ticker = object : Runnable {
        override fun run() {
            refreshLockState()
            handler.postDelayed(this, 1000)
        }
    }

    private fun btn(id: Int, action: () -> Unit) = findViewById<Button>(id).setOnClickListener { action() }

    private fun neededPermissions(): Array<String> {
        val list = AuthKeyDevice.permissions().toMutableList()
        if (Build.VERSION.SDK_INT >= 33) list += Manifest.permission.POST_NOTIFICATIONS
        return list.toTypedArray()
    }

    private fun refresh() {
        val perms = neededPermissions().all { checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED }
        findViewById<Button>(R.id.grant).visibility = if (perms) android.view.View.GONE else android.view.View.VISIBLE
        val dev = AuthKeyDevice.bonded(this)
        findViewById<TextView>(R.id.deviceStatus).text = when {
            !perms -> getString(R.string.device_need_permission)
            dev == null -> getString(R.string.device_not_paired)
            else -> getString(R.string.device_paired, dev.address)
        }
        findViewById<MaterialSwitch>(R.id.lockSwitch).isEnabled = perms && dev != null
        refreshLockState()
    }

    private fun batteryExempt() =
        getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(packageName)

    /** Asks Android to exempt the app from battery optimisation (one system dialog). */
    @android.annotation.SuppressLint("BatteryLife")
    private fun requestBatteryExemption() {
        if (batteryExempt()) { refresh(); return }
        try {
            startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, "package:$packageName".toUri()))
        } catch (_: Exception) {
            startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
        }
    }

    private fun refreshLockState() {
        val notifs = NotificationManagerCompat.from(this).areNotificationsEnabled()
        findViewById<TextView>(R.id.backgroundStatus).text = getString(R.string.background_status,
            getString(if (batteryExempt()) R.string.bg_ok else R.string.bg_on),
            getString(if (notifs) R.string.notif_on else R.string.notif_off))
        findViewById<Button>(R.id.battery).isEnabled = !batteryExempt()
        val method = when {
            ScreenLock.accessibilityActive() -> getString(R.string.lock_method_normal)
            ScreenLock.adminActive(this) -> getString(R.string.lock_method_strict)
            else -> getString(R.string.lock_method_none)
        }
        val state = if (prefs.lockEnabled && PresenceService.running) PresenceService.lastState else getString(R.string.lock_off)
        findViewById<TextView>(R.id.lockStatus).text = getString(R.string.lock_status, state, method)
    }

    private fun testConnection() {
        val out = findViewById<TextView>(R.id.testResult)
        out.text = getString(R.string.test_running)
        lifecycleScope.launch {
            out.text = try {
                Transports.open(this@MainActivity).use { t ->
                    val info = Ctap.getInfo(t)
                    val versions = (info.int(1) as? List<*>)?.joinToString() ?: "?"
                    val opts = (info.int(4) as? Map<*, *>) ?: emptyMap<Any, Any>()
                    getString(R.string.test_ok, t.name, versions, opts["rk"], opts["uv"] ?: false)
                }
            } catch (e: Exception) {
                android.util.Log.e("AuthKey", "test failed", e)
                getString(R.string.test_failed, e.message ?: e.toString())
            }
        }
    }
}
