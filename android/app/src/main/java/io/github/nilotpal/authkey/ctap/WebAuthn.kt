package io.github.nilotpal.authkey.ctap

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/**
 * WebAuthn JSON (what Android's Credential Manager hands a passkey provider)
 * to CTAP2 requests for the AuthKey, and CTAP2 replies back to WebAuthn JSON.
 */
object WebAuthn {

    fun b64u(b: ByteArray): String = Base64.encodeToString(b, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    fun unb64u(s: String): ByteArray = Base64.decode(s, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    /** Where the request came from: a browser passes its own clientDataHash. */
    class Caller(val clientDataHash: ByteArray?, val origin: String, val packageName: String)

    class Assertion(val json: String, val userName: String?)

    private fun clientData(type: String, challenge: String, caller: Caller): Pair<ByteArray, ByteArray> {
        val json = JSONObject()
            .put("type", type)
            .put("challenge", challenge)
            .put("origin", caller.origin)
            .put("androidPackageName", caller.packageName)
            .toString().replace("\\/", "/")
            .toByteArray()
        // With a browser's hash, the browser substitutes its own clientDataJSON.
        return json to (caller.clientDataHash ?: sha256(json))
    }

    private fun credList(arr: JSONArray?): List<Map<String, Any?>>? {
        if (arr == null || arr.length() == 0) return null
        return (0 until arr.length()).map {
            mapOf("id" to unb64u(arr.getJSONObject(it).getString("id")), "type" to "public-key")
        }
    }

    private fun wantsUv(pref: String?, info: Map<*, *>): Boolean {
        val uvSupported = ((info.int(4) as? Map<*, *>)?.get("uv") as? Boolean) == true
        return when (pref ?: "preferred") {
            "required" -> true
            "discouraged" -> false
            else -> uvSupported
        }
    }

    // --- Registration -------------------------------------------------------------

    suspend fun create(t: CtapTransport, requestJson: String, caller: Caller, onWaiting: () -> Unit): String {
        val req = JSONObject(requestJson)
        val rp = req.getJSONObject("rp")
        val rpId = rp.optString("id").ifEmpty { originHost(caller.origin) }
        val user = req.getJSONObject("user")
        val sel = req.optJSONObject("authenticatorSelection") ?: JSONObject()
        val residentKey = sel.optString("residentKey").ifEmpty { if (sel.optBoolean("requireResidentKey")) "required" else "preferred" }
        val rk = residentKey != "discouraged"
        val info = Ctap.getInfo(t)
        val uv = wantsUv(sel.optString("userVerification").ifEmpty { null }, info)
        val (clientDataJson, cdh) = clientData("webauthn.create", req.getString("challenge"), caller)

        val algs = req.optJSONArray("pubKeyCredParams") ?: JSONArray()
        val params = (0 until algs.length()).map {
            val p = algs.getJSONObject(it)
            mapOf("alg" to p.getInt("alg"), "type" to p.optString("type", "public-key"))
        }.ifEmpty { listOf(mapOf("alg" to -7, "type" to "public-key")) }

        val ctapReq = linkedMapOf<Int, Any?>(
            1 to cdh,
            2 to mapOf("id" to rpId, "name" to rp.optString("name", rpId)),
            3 to mapOf(
                "id" to unb64u(user.getString("id")),
                "name" to user.optString("name"),
                "displayName" to user.optString("displayName", user.optString("name")),
            ),
            4 to params,
        )
        credList(req.optJSONArray("excludeCredentials"))?.let { ctapReq[5] = it }
        ctapReq[7] = mapOf("rk" to rk, "uv" to uv)

        val r = Ctap.call(t, Ctap.MAKE_CREDENTIAL, ctapReq, onWaiting)
        val fmt = r.int(1) as String
        val authData = r.int(2) as ByteArray
        val attStmt = r.int(3) as Map<*, *>
        val attestationObject = Cbor.encode(mapOf("fmt" to fmt, "attStmt" to attStmt, "authData" to authData))

        // authData: rpIdHash(32) flags(1) counter(4) aaguid(16) idLen(2) credId COSEkey
        val idLen = ((authData[53].toInt() and 0xFF) shl 8) or (authData[54].toInt() and 0xFF)
        val credId = authData.copyOfRange(55, 55 + idLen)
        val cose = Cbor.decodePrefix(authData.copyOfRange(55 + idLen, authData.size)).first as Map<*, *>
        val x = cose[-2L] as ByteArray
        val y = cose[-3L] as ByteArray
        val spki = SPKI_P256_PREFIX + byteArrayOf(0x04) + x + y

        val response = JSONObject()
            .put("clientDataJSON", b64u(clientDataJson))
            .put("attestationObject", b64u(attestationObject))
            .put("authenticatorData", b64u(authData))
            .put("publicKey", b64u(spki))
            .put("publicKeyAlgorithm", -7)
            .put("transports", JSONArray(listOf("ble", "hybrid")))
        val ext = JSONObject()
        if (req.optJSONObject("extensions")?.optBoolean("credProps") == true) {
            ext.put("credProps", JSONObject().put("rk", rk))
        }
        return JSONObject()
            .put("id", b64u(credId))
            .put("rawId", b64u(credId))
            .put("type", "public-key")
            .put("authenticatorAttachment", "cross-platform")
            .put("response", response)
            .put("clientExtensionResults", ext)
            .toString()
    }

    // --- Sign-in ------------------------------------------------------------------

    /** Every matching account on the device (newest first); the user picks one if there are several. */
    suspend fun get(t: CtapTransport, requestJson: String, caller: Caller, onWaiting: () -> Unit): List<Assertion> {
        val req = JSONObject(requestJson)
        val rpId = req.optString("rpId").ifEmpty { originHost(caller.origin) }
        val info = Ctap.getInfo(t)
        val uv = wantsUv(req.optString("userVerification").ifEmpty { null }, info)
        val (clientDataJson, cdh) = clientData("webauthn.get", req.getString("challenge"), caller)

        val ctapReq = linkedMapOf<Int, Any?>(1 to rpId, 2 to cdh)
        credList(req.optJSONArray("allowCredentials"))?.let { ctapReq[3] = it }
        ctapReq[5] = mapOf("up" to true, "uv" to uv)

        val first = Ctap.call(t, Ctap.GET_ASSERTION, ctapReq, onWaiting)
        val total = (first.int(5) as? Long)?.toInt() ?: 1
        val out = mutableListOf(assertion(first, clientDataJson))
        repeat(total - 1) { out += assertion(Ctap.call(t, Ctap.GET_NEXT_ASSERTION, null), clientDataJson) }
        return out
    }

    private fun assertion(r: Map<*, *>, clientDataJson: ByteArray): Assertion {
        val cred = r.int(1) as Map<*, *>
        val id = cred["id"] as ByteArray
        val user = r.int(4) as? Map<*, *>
        val response = JSONObject()
            .put("clientDataJSON", b64u(clientDataJson))
            .put("authenticatorData", b64u(r.int(2) as ByteArray))
            .put("signature", b64u(r.int(3) as ByteArray))
        (user?.get("id") as? ByteArray)?.let { response.put("userHandle", b64u(it)) }
        val json = JSONObject()
            .put("id", b64u(id))
            .put("rawId", b64u(id))
            .put("type", "public-key")
            .put("authenticatorAttachment", "cross-platform")
            .put("response", response)
            .put("clientExtensionResults", JSONObject())
            .toString()
        val name = (user?.get("name") as? String) ?: (user?.get("displayName") as? String)
        return Assertion(json, name)
    }

    private fun originHost(origin: String) = origin.substringAfter("://").substringBefore('/').substringBefore(':')

    /** Origin Android assigns to a native app: its signing certificate's hash. */
    fun appOrigin(signingCert: ByteArray) = "android:apk-key-hash:" + b64u(sha256(signingCert))

    // DER SubjectPublicKeyInfo header for an uncompressed P-256 public key.
    private val SPKI_P256_PREFIX = byteArrayOf(
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    )

    @Suppress("unused")
    fun describeInfo(ctx: Context, info: Map<*, *>): String {
        val versions = (info.int(1) as? List<*>)?.joinToString() ?: "?"
        val options = (info.int(4) as? Map<*, *>)?.entries?.joinToString { "${it.key}=${it.value}" } ?: "?"
        return "CTAP $versions; $options"
    }
}
