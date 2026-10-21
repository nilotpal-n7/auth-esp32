package io.github.nilotpal.authkey.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.os.Build
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import java.io.IOException
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Suspending wrapper over [BluetoothGatt]: one operation at a time, each
 * awaited through its callback. Notifications go to per-characteristic listeners.
 */
@SuppressLint("MissingPermission")
class GattClient private constructor() : AutoCloseable {
    private lateinit var gatt: BluetoothGatt
    private val opLock = Mutex()
    @Volatile private var pending: CompletableDeferred<Any?>? = null
    private val connected = CompletableDeferred<Unit>()
    @Volatile var isConnected = false
        private set
    private val listeners = ConcurrentHashMap<UUID, (ByteArray) -> Unit>()
    var mtu = 23
        private set

    private val callback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS) {
                isConnected = true
                connected.complete(Unit)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                isConnected = false
                val e = IOException("Bluetooth link to the AuthKey closed (status $status)")
                connected.completeExceptionally(e)
                pending?.completeExceptionally(e)
            }
        }

        override fun onMtuChanged(g: BluetoothGatt, mtu: Int, status: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS) this@GattClient.mtu = mtu
            pending?.complete(mtu)
        }

        override fun onServicesDiscovered(g: BluetoothGatt, status: Int) = finish(status, Unit)

        override fun onCharacteristicWrite(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) =
            finish(status, Unit)

        override fun onDescriptorWrite(g: BluetoothGatt, d: BluetoothGattDescriptor, status: Int) =
            finish(status, Unit)

        override fun onCharacteristicRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray, status: Int) =
            finish(status, value)

        @Deprecated("Android 12 and older")
        override fun onCharacteristicRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) {
            if (Build.VERSION.SDK_INT < 33) @Suppress("DEPRECATION") finish(status, c.value ?: ByteArray(0))
        }

        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray) {
            listeners[c.uuid]?.invoke(value)
        }

        @Deprecated("Android 12 and older")
        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic) {
            @Suppress("DEPRECATION")
            if (Build.VERSION.SDK_INT < 33) listeners[c.uuid]?.invoke(c.value ?: ByteArray(0))
        }
    }

    private fun finish(status: Int, value: Any?) {
        val p = pending ?: return
        if (status == BluetoothGatt.GATT_SUCCESS) p.complete(value)
        else p.completeExceptionally(IOException(gattError(status)))
    }

    private fun gattError(status: Int) = when (status) {
        5, 15 -> "The AuthKey needs pairing: pair AuthKey-ESP32 in Android's Bluetooth settings (status $status)"
        else -> "Bluetooth operation failed (status $status)"
    }

    /** Runs one GATT operation: [start] kicks it off, the callback completes it. */
    private suspend fun <T> op(timeoutMs: Long = 10_000, start: () -> Boolean): T = opLock.withLock {
        if (!isConnected) throw IOException("Not connected to the AuthKey")
        val d = CompletableDeferred<Any?>()
        pending = d
        try {
            if (!start()) throw IOException("Android refused the Bluetooth request")
            @Suppress("UNCHECKED_CAST")
            withTimeout(timeoutMs) { d.await() } as T
        } finally {
            pending = null
        }
    }

    suspend fun requestMtu(want: Int): Int = op { gatt.requestMtu(want) }

    suspend fun discover() {
        op<Unit>(15_000) { gatt.discoverServices() }
    }

    /**
     * Android caches a bonded device's service list; after a firmware update
     * it can miss new characteristics. Clears the cache (hidden API) and
     * discovers again.
     */
    suspend fun rediscover() {
        // On most phones refresh() starts the discovery itself; the extra
        // discoverServices() covers the rest. Either way one callback ends it.
        op<Unit>(30_000) {
            try { gatt.javaClass.getMethod("refresh").invoke(gatt) } catch (_: Exception) {}
            gatt.discoverServices()
            true
        }
    }

    fun has(service: UUID, ch: UUID) = gatt.getService(service)?.getCharacteristic(ch) != null

    fun characteristic(service: UUID, ch: UUID): BluetoothGattCharacteristic =
        gatt.getService(service)?.getCharacteristic(ch)
            ?: throw IOException("The AuthKey doesn't offer $ch (update its firmware?)")

    suspend fun write(c: BluetoothGattCharacteristic, value: ByteArray, withResponse: Boolean = true) {
        val type = if (withResponse) BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                   else BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
        op<Unit>(15_000) {
            if (Build.VERSION.SDK_INT >= 33) gatt.writeCharacteristic(c, value, type) == BluetoothGatt.GATT_SUCCESS
            else @Suppress("DEPRECATION") run {
                c.writeType = type
                c.value = value
                gatt.writeCharacteristic(c)
            }
        }
    }

    suspend fun read(c: BluetoothGattCharacteristic): ByteArray = op {
        gatt.readCharacteristic(c)
    }

    suspend fun enableNotify(c: BluetoothGattCharacteristic, listener: (ByteArray) -> Unit) {
        listeners[c.uuid] = listener
        if (!gatt.setCharacteristicNotification(c, true)) throw IOException("Can't enable notifications")
        val d = c.getDescriptor(AuthKeyDevice.CCCD) ?: return
        val on = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        op<Unit> {
            if (Build.VERSION.SDK_INT >= 33) gatt.writeDescriptor(d, on) == BluetoothGatt.GATT_SUCCESS
            else @Suppress("DEPRECATION") run { d.value = on; gatt.writeDescriptor(d) }
        }
    }

    override fun close() {
        isConnected = false
        pending?.completeExceptionally(IOException("closed"))
        try { gatt.disconnect() } catch (_: Exception) {}
        try { gatt.close() } catch (_: Exception) {}
    }

    companion object {
        suspend fun connect(ctx: Context, device: BluetoothDevice, timeoutMs: Long = 15_000): GattClient {
            var last: Exception? = null
            repeat(2) {   // status 133 on the first try is common on Android
                val client = GattClient()
                client.gatt = device.connectGatt(ctx, false, client.callback, BluetoothDevice.TRANSPORT_LE)
                try {
                    withTimeout(timeoutMs) { client.connected.await() }
                    return client
                } catch (e: Exception) {
                    last = e
                    client.close()
                }
            }
            throw IOException("Couldn't reach the AuthKey over Bluetooth. Is it on and nearby?", last)
        }
    }
}
