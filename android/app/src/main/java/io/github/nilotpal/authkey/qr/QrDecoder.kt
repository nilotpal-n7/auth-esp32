package io.github.nilotpal.authkey.qr

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer

/** QR decoding with ZXing; returns only passkey (FIDO:/) or authenticator (otpauth://) codes. */
object QrDecoder {
    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
    )

    fun decode(source: LuminanceSource): String? {
        val reader = MultiFormatReader().apply { setHints(hints) }
        // Dark-mode dialogs draw the QR light-on-dark: try the inverse too.
        for (s in listOf(source, source.invert())) {
            try {
                val text = reader.decodeWithState(BinaryBitmap(HybridBinarizer(s))).text
                if (QrSender.kind(text) != null) return text
            } catch (_: NotFoundException) {
            } finally {
                reader.reset()
            }
        }
        return null
    }

    fun decode(bmp: Bitmap): String? {
        val px = IntArray(bmp.width * bmp.height)
        bmp.getPixels(px, 0, bmp.width, 0, 0, bmp.width, bmp.height)
        return decode(RGBLuminanceSource(bmp.width, bmp.height, px))
    }
}
