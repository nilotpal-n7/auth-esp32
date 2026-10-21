package io.github.nilotpal.authkey.ctap

import android.content.Context
import io.github.nilotpal.authkey.ble.AuthKeyDevice
import io.github.nilotpal.authkey.ble.GattClient
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeout
import java.io.IOException

/**
 * CTAP2 over Bluetooth LE with FIDO framing (CTAP 2.0 §8.3): framed messages
 * written to the control point, replies notified on the status
 * characteristic. Uses the AuthKey's own service (see [AuthKeyDevice]); the
 * phone must be paired (bonded) with it, since the control point needs an
 * encrypted link.
 */
class BleCtap private constructor(private val gatt: GattClient) : CtapTransport {
    override val name = "Bluetooth"
    private val frames = Channel<ByteArray>(Channel.UNLIMITED)
    private var fragment = 20

    private suspend fun setUp() {
        gatt.requestMtu(512)
        gatt.discover()
        if (!gatt.has(AuthKeyDevice.PROV_SERVICE, AuthKeyDevice.CTAP_STATUS)) gatt.rediscover()
        val status = gatt.characteristic(AuthKeyDevice.PROV_SERVICE, AuthKeyDevice.CTAP_STATUS)
        gatt.enableNotify(status) { frames.trySend(it) }
        fragment = (gatt.mtu - 3).coerceIn(20, 512)
    }

    override suspend fun exchange(request: ByteArray, onWaiting: () -> Unit): ByteArray {
        while (frames.tryReceive().isSuccess) { /* drop stale frames */ }
        val cp = gatt.characteristic(AuthKeyDevice.PROV_SERVICE, AuthKeyDevice.CTAP_CONTROL_POINT)
        // Initial fragment: CMD(0x83 MSG) | len hi | len lo | data; then SEQ | data.
        var off = minOf(request.size, fragment - 3)
        gatt.write(cp, byteArrayOf(0x83.toByte(), (request.size shr 8).toByte(), request.size.toByte()) +
                       request.copyOfRange(0, off))
        var seq = 0
        while (off < request.size) {
            val n = minOf(request.size - off, fragment - 1)
            gatt.write(cp, byteArrayOf((seq++ and 0x7F).toByte()) + request.copyOfRange(off, off + n))
            off += n
        }

        // Reply: keepalives (0x82) while the device waits for OK, then the message.
        return withTimeout(90_000) {
            while (true) {
                val f = frames.receive()
                if (f.isEmpty()) continue
                when (f[0].toInt() and 0xFF) {
                    0x82 -> { if (f.size > 3 && f[3].toInt() == 2) onWaiting() }
                    0xBF -> throw IOException("AuthKey Bluetooth error 0x%02X".format(if (f.size > 3) f[3] else 0))
                    0x83 -> {
                        val total = ((f[1].toInt() and 0xFF) shl 8) or (f[2].toInt() and 0xFF)
                        var data = f.copyOfRange(3, f.size)
                        while (data.size < total) {
                            val c = frames.receive()
                            data += c.copyOfRange(1, c.size)
                        }
                        return@withTimeout data.copyOf(total)
                    }
                }
            }
            @Suppress("UNREACHABLE_CODE") ByteArray(0)
        }
    }

    override fun close() = gatt.close()

    companion object {
        suspend fun open(ctx: Context): BleCtap {
            val dev = AuthKeyDevice.bonded(ctx)
                ?: throw IOException("Pair AuthKey-ESP32 in Android's Bluetooth settings first (and allow Nearby devices).")
            val t = BleCtap(GattClient.connect(ctx, dev))
            try {
                t.setUp()
            } catch (e: Exception) {
                t.close()
                throw e
            }
            return t
        }
    }
}
