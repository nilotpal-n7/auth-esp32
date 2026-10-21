package io.github.nilotpal.authkey.ctap

import android.content.Context
import io.github.nilotpal.authkey.usb.UsbSerial
import java.io.IOException

/** CTAP2 through the AuthKey's serial console: "ctap <hex>" -> "CTAP <hex>". */
class UsbCtap private constructor(private val port: UsbSerial) : CtapTransport {
    override val name = "USB"

    override suspend fun exchange(request: ByteArray, onWaiting: () -> Unit): ByteArray {
        onWaiting()   // the console has no keepalives; the prompt may already be up
        val line = port.command("ctap " + request.toHex(), 90_000) { it.startsWith("CTAP ") || it.startsWith("ERR") }
            ?: throw IOException("No answer from the AuthKey over USB")
        if (line.startsWith("ERR")) throw IOException("AuthKey: $line")
        return line.substring(5).trim().hexToBytes()
    }

    override fun close() = port.close()

    companion object {
        fun available(ctx: Context) = UsbSerial.find(ctx) != null
        suspend fun open(ctx: Context) = UsbCtap(UsbSerial.open(ctx))
    }
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
fun String.hexToBytes(): ByteArray = ByteArray(length / 2) { substring(2 * it, 2 * it + 2).toInt(16).toByte() }
