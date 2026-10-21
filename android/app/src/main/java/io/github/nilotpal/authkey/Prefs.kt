package io.github.nilotpal.authkey

import android.content.Context

/** App settings (SharedPreferences). */
class Prefs(ctx: Context) {
    private val p = ctx.getSharedPreferences("authkey", Context.MODE_PRIVATE)

    var deviceAddress: String?
        get() = p.getString("device_address", null)
        set(v) = p.edit().putString("device_address", v).apply()

    /** Walk-away lock on/off. */
    var lockEnabled: Boolean
        get() = p.getBoolean("lock_enabled", false)
        set(v) = p.edit().putBoolean("lock_enabled", v).apply()

    /** Seconds out of range before the phone locks. */
    var awaySeconds: Int
        get() = p.getInt("away_seconds", 15)
        set(v) = p.edit().putInt("away_seconds", v.coerceIn(5, 300)).apply()

    /** Adverts weaker than this (dBm) count as away. */
    var minRssi: Int
        get() = p.getInt("min_rssi", -85)
        set(v) = p.edit().putInt("min_rssi", v.coerceIn(-100, -40)).apply()
}
