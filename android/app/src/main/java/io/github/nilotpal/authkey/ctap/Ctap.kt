package io.github.nilotpal.authkey.ctap

/** One way of reaching the AuthKey (Bluetooth or USB) that carries CTAP2 messages. */
interface CtapTransport : AutoCloseable {
    val name: String

    /**
     * Sends a CTAP2 request (command byte + CBOR) and returns the response
     * (status byte + CBOR). [onWaiting] is called while the device waits for
     * the user to press OK.
     */
    suspend fun exchange(request: ByteArray, onWaiting: () -> Unit = {}): ByteArray
}

class CtapException(val status: Int, message: String) : Exception(message)

object Ctap {
    const val MAKE_CREDENTIAL = 0x01
    const val GET_ASSERTION = 0x02
    const val GET_INFO = 0x04
    const val GET_NEXT_ASSERTION = 0x08

    // Status codes the app reacts to.
    const val ERR_CREDENTIAL_EXCLUDED = 0x19
    const val ERR_OPERATION_DENIED = 0x27
    const val ERR_NO_CREDENTIALS = 0x2E
    const val ERR_ACTION_TIMEOUT = 0x2F
    const val ERR_KEEPALIVE_CANCEL = 0x2D
    const val ERR_PIN_BLOCKED = 0x32
    const val ERR_CHANNEL_BUSY = 0x06

    fun describe(status: Int): String = when (status) {
        ERR_CREDENTIAL_EXCLUDED -> "This AuthKey is already registered with this site."
        ERR_OPERATION_DENIED -> "Denied on the AuthKey."
        ERR_NO_CREDENTIALS -> "No passkey for this site on the AuthKey."
        ERR_ACTION_TIMEOUT -> "Nobody pressed OK on the AuthKey in time."
        ERR_KEEPALIVE_CANCEL -> "Cancelled."
        ERR_PIN_BLOCKED -> "The AuthKey's PIN is blocked."
        ERR_CHANNEL_BUSY -> "The AuthKey is busy with another request; try again."
        0x2B, 0x2C -> "The AuthKey doesn't support an option this site asked for."
        0x26 -> "The site asked for a key type the AuthKey doesn't support."
        0x28 -> "The AuthKey's passkey storage is full."
        else -> "AuthKey error 0x%02X.".format(status)
    }

    /** Sends [cmd] + CBOR([params]) and returns the decoded response map (or throws). */
    suspend fun call(t: CtapTransport, cmd: Int, params: Map<Int, Any?>?, onWaiting: () -> Unit = {}): Map<*, *> {
        val req = byteArrayOf(cmd.toByte()) + (params?.let { Cbor.encode(it) } ?: ByteArray(0))
        val resp = t.exchange(req, onWaiting)
        if (resp.isEmpty()) throw CtapException(0x7F, "Empty reply from the AuthKey.")
        val status = resp[0].toInt() and 0xFF
        if (status != 0) throw CtapException(status, describe(status))
        if (resp.size == 1) return emptyMap<Any?, Any?>()
        return Cbor.decode(resp.copyOfRange(1, resp.size)) as Map<*, *>
    }

    suspend fun getInfo(t: CtapTransport): Map<*, *> = call(t, GET_INFO, null)
}
