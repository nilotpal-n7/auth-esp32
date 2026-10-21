package io.github.nilotpal.authkey.usb

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbManager
import android.os.Build
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.IOException

/**
 * The AuthKey's USB serial console through a phone's USB-C / OTG port. Only
 * the CP210x bridge (Silicon Labs, VID 10C4) found on most ESP32 DevKits is
 * supported. DTR and RTS stay low, so opening the port doesn't reset the board.
 */
class UsbSerial private constructor(
    private val conn: UsbDeviceConnection,
    private val epIn: UsbEndpoint,
    private val epOut: UsbEndpoint,
) : AutoCloseable {
    private val buf = StringBuilder()

    fun write(line: String) {
        val b = line.toByteArray(Charsets.US_ASCII)
        var off = 0
        while (off < b.size) {
            val n = conn.bulkTransfer(epOut, b, off, b.size - off, 1000)
            if (n <= 0) throw IOException("USB write failed")
            off += n
        }
    }

    /** Next console line, or null after [timeoutMs]. */
    fun readLine(timeoutMs: Long): String? {
        val deadline = System.currentTimeMillis() + timeoutMs
        val tmp = ByteArray(512)
        while (true) {
            val nl = buf.indexOf("\n")
            if (nl >= 0) {
                val line = buf.substring(0, nl).trimEnd('\r')
                buf.delete(0, nl + 1)
                return line
            }
            val left = deadline - System.currentTimeMillis()
            if (left <= 0) return null
            val n = conn.bulkTransfer(epIn, tmp, tmp.size, minOf(left, 200L).toInt())
            if (n > 0) buf.append(String(tmp, 0, n, Charsets.ISO_8859_1))
        }
    }

    fun drain() {
        buf.setLength(0)
        val tmp = ByteArray(512)
        while (conn.bulkTransfer(epIn, tmp, tmp.size, 30) > 0) { /* discard */ }
    }

    /** Sends a console command and returns the first reply line [isFinal] accepts. */
    suspend fun command(line: String, timeoutMs: Long, isFinal: (String) -> Boolean): String? =
        withContext(Dispatchers.IO) {
            drain()
            write(line + "\n")
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                val l = readLine(deadline - System.currentTimeMillis()) ?: break
                if (isFinal(l)) return@withContext l
            }
            null
        }

    override fun close() = conn.close()

    companion object {
        private const val ACTION_PERMISSION = "io.github.nilotpal.authkey.USB_PERMISSION"
        private const val CP210X_VID = 0x10C4

        fun find(ctx: Context): UsbDevice? =
            ctx.getSystemService(UsbManager::class.java)?.deviceList?.values?.firstOrNull { it.vendorId == CP210X_VID }

        /** Opens the plugged-in AuthKey, asking Android for USB permission if needed. */
        suspend fun open(ctx: Context): UsbSerial {
            val usb = ctx.getSystemService(UsbManager::class.java) ?: throw IOException("No USB host support")
            val dev = find(ctx) ?: throw IOException("No AuthKey on USB")
            if (!usb.hasPermission(dev)) requestPermission(ctx, usb, dev)
            val conn = usb.openDevice(dev) ?: throw IOException("Couldn't open the USB device")
            val intf = dev.getInterface(0)
            if (!conn.claimInterface(intf, true)) { conn.close(); throw IOException("USB interface busy") }
            var epIn: UsbEndpoint? = null
            var epOut: UsbEndpoint? = null
            for (i in 0 until intf.endpointCount) {
                val ep = intf.getEndpoint(i)
                if (ep.type != UsbConstants.USB_ENDPOINT_XFER_BULK) continue
                if (ep.direction == UsbConstants.USB_DIR_IN) epIn = ep else epOut = ep
            }
            if (epIn == null || epOut == null) { conn.close(); throw IOException("Unexpected USB bridge") }
            // CP210x vendor requests (AN571): enable the UART, 115200 8N1, DTR/RTS low.
            fun ctl(req: Int, value: Int, data: ByteArray? = null) {
                if (conn.controlTransfer(0x41, req, value, 0, data, data?.size ?: 0, 1000) < 0)
                    throw IOException("USB setup failed (request $req)")
            }
            try {
                ctl(0x00, 0x0001)                                   // IFC_ENABLE
                ctl(0x1E, 0, byteArrayOf(0x00, 0xC2.toByte(), 0x01, 0x00))   // SET_BAUDRATE 115200
                ctl(0x03, 0x0800)                                   // SET_LINE_CTL 8N1
                ctl(0x07, 0x0300)                                   // SET_MHS: DTR=0, RTS=0
            } catch (e: IOException) {
                conn.close()
                throw e
            }
            return UsbSerial(conn, epIn, epOut)
        }

        private suspend fun requestPermission(ctx: Context, usb: UsbManager, dev: UsbDevice) {
            val result = CompletableDeferred<Boolean>()
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(c: Context, i: Intent) {
                    result.complete(i.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false))
                }
            }
            val filter = IntentFilter(ACTION_PERMISSION)
            if (Build.VERSION.SDK_INT >= 33) ctx.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            else @Suppress("UnspecifiedRegisterReceiverFlag") ctx.registerReceiver(receiver, filter)
            try {
                val pi = PendingIntent.getBroadcast(ctx, 0, Intent(ACTION_PERMISSION).setPackage(ctx.packageName),
                    PendingIntent.FLAG_MUTABLE)
                usb.requestPermission(dev, pi)
                if (!withTimeout(60_000) { result.await() }) throw IOException("USB permission denied")
            } finally {
                ctx.unregisterReceiver(receiver)
            }
        }
    }
}
