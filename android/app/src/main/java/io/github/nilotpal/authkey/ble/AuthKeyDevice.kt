package io.github.nilotpal.authkey.ble

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import io.github.nilotpal.authkey.Prefs
import java.util.UUID

/** The AuthKey-ESP32's Bluetooth identity and GATT layout (see src/transport/ble.cpp). */
object AuthKeyDevice {
    const val NAME = "AuthKey-ESP32"

    // CTAP over BLE with FIDO framing, on the AuthKey's own service: Android
    // reserves the standard FIDO service (0xFFFD) for privileged system apps.
    val CTAP_CONTROL_POINT: UUID = UUID.fromString("a3c87504-8ed3-4bdf-8a39-a01bebede295")
    val CTAP_STATUS: UUID = UUID.fromString("a3c87505-8ed3-4bdf-8a39-a01bebede295")

    // Hybrid provisioning: write the "FIDO:/..." QR text, status is notified back.
    val PROV_SERVICE: UUID = UUID.fromString("a3c87500-8ed3-4bdf-8a39-a01bebede295")
    val PROV_WRITE: UUID = UUID.fromString("a3c87501-8ed3-4bdf-8a39-a01bebede295")
    val PROV_STATUS: UUID = UUID.fromString("a3c87502-8ed3-4bdf-8a39-a01bebede295")

    val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    fun permissions(): Array<String> = if (Build.VERSION.SDK_INT >= 31)
        arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
    else
        arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)

    fun hasPermissions(ctx: Context): Boolean = permissions().all {
        ctx.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
    }

    /**
     * The paired AuthKey: the remembered address, else a bonded device named
     * AuthKey-ESP32 (pair it in Android's Bluetooth settings first).
     */
    @SuppressLint("MissingPermission")
    fun bonded(ctx: Context): BluetoothDevice? {
        if (!hasPermissions(ctx)) return null
        val adapter = ctx.getSystemService(BluetoothManager::class.java)?.adapter ?: return null
        if (!adapter.isEnabled) return null
        val bonded = adapter.bondedDevices ?: return null
        val saved = Prefs(ctx).deviceAddress
        bonded.firstOrNull { it.address == saved }?.let { return it }
        val found = bonded.firstOrNull { it.name == NAME || it.alias == NAME } ?: return null
        Prefs(ctx).deviceAddress = found.address
        return found
    }
}
