package io.github.nilotpal.authkey.qr

import android.content.Context
import io.github.nilotpal.authkey.ble.AuthKeyDevice
import io.github.nilotpal.authkey.ble.GattClient
import io.github.nilotpal.authkey.usb.UsbSerial
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException

/**
 * Hands a QR's text to the AuthKey, like tools/qr_bridge.py on Windows:
 *  - "FIDO:/..." (passkey QR): the device signs in like a phone would (hybrid,
 *    over its WiFi plus Bluetooth near the screen showing the QR).
 *  - "otpauth://totp/..." (authenticator QR): added to the device's codes
 *    (USB only; over Bluetooth there is no channel for it).
 */
object QrSender {

    fun kind(text: String): String? = when {
        text.startsWith("FIDO:/", ignoreCase = true) -> "passkey"
        text.startsWith("otpauth://totp/", ignoreCase = true) -> "totp"
        else -> null
    }

    /** Returns a short result for the user. [progress] receives device status updates. */
    suspend fun send(ctx: Context, text: String, progress: (String) -> Unit): String {
        if (UsbSerial.find(ctx) != null) return sendUsb(ctx, text, progress)
        if (kind(text) == "totp") {
            throw IOException("Plug the AuthKey into the phone (USB) to add authenticator accounts, " +
                    "or add the link on the AuthKey's web page.")
        }
        return sendBle(ctx, text, progress)
    }

    private suspend fun sendUsb(ctx: Context, text: String, progress: (String) -> Unit): String {
        if ('"' in text) throw IOException("This QR has an unsupported character")
        UsbSerial.open(ctx).use { port ->
            progress("Sending over USB...")
            return if (kind(text) == "totp") {
                port.command("totp uri \"$text\"", 5000) { it.startsWith("OK") || it.startsWith("ERR") }
                    ?.let { if (it.startsWith("OK")) "Added to the AuthKey's codes" else "AuthKey: $it" }
                    ?: "No answer from the AuthKey"
            } else {
                port.command("hybrid $text", 5000) { it.startsWith("OK") || it.startsWith("ERR") }
                    ?.let { if (it.startsWith("OK")) "Sent. Approve on the AuthKey screen." else "AuthKey: $it" }
                    ?: "No answer from the AuthKey"
            }
        }
    }

    private suspend fun sendBle(ctx: Context, text: String, progress: (String) -> Unit): String {
        val dev = AuthKeyDevice.bonded(ctx)
            ?: throw IOException("Pair AuthKey-ESP32 in Android's Bluetooth settings first.")
        progress("Connecting to the AuthKey...")
        GattClient.connect(ctx, dev).use { gatt ->
            gatt.requestMtu(512)
            gatt.discover()
            if (!gatt.has(AuthKeyDevice.PROV_SERVICE, AuthKeyDevice.PROV_STATUS)) gatt.rediscover()
            val updates = Channel<String>(Channel.UNLIMITED)
            gatt.enableNotify(gatt.characteristic(AuthKeyDevice.PROV_SERVICE, AuthKeyDevice.PROV_STATUS)) {
                updates.trySend(String(it))
            }
            gatt.write(gatt.characteristic(AuthKeyDevice.PROV_SERVICE, AuthKeyDevice.PROV_WRITE), text.toByteArray())
            progress("Sent. The AuthKey is connecting...")
            // Follow the device until the desktop/phone side has it (as qr_bridge.py does).
            var last = "sent"
            withTimeoutOrNull(25_000) {
                while (true) {
                    val s = updates.receive()
                    last = s
                    progress("AuthKey: $s")
                    if (s == "waiting for PC" || s == "connected" || "fail" in s || s == "no WiFi" || s == "bad QR") break
                }
            }
            return when {
                "fail" in last || last == "no WiFi" || last == "bad QR" -> "AuthKey: $last"
                else -> "Approve on the AuthKey screen."
            }
        }
    }
}
