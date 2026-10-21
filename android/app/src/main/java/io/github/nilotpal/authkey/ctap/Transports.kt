package io.github.nilotpal.authkey.ctap

import android.content.Context

object Transports {
    /** USB when an AuthKey is plugged in (faster, no pairing), otherwise Bluetooth. */
    suspend fun open(ctx: Context): CtapTransport =
        if (UsbCtap.available(ctx)) UsbCtap.open(ctx) else BleCtap.open(ctx)
}
