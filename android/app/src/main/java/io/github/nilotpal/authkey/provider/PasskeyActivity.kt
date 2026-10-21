package io.github.nilotpal.authkey.provider

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.domerrors.NotAllowedError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.lifecycleScope
import io.github.nilotpal.authkey.R
import io.github.nilotpal.authkey.ctap.Ctap
import io.github.nilotpal.authkey.ctap.CtapException
import io.github.nilotpal.authkey.ctap.Transports
import io.github.nilotpal.authkey.ctap.WebAuthn
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/** Runs one passkey registration or sign-in against the AuthKey for Android's Credential Manager. */
@RequiresApi(34)
class PasskeyActivity : AppCompatActivity() {
    private lateinit var status: TextView
    private var job: Job? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_passkey)
        status = findViewById(R.id.status)
        findViewById<Button>(R.id.cancel).setOnClickListener { cancel() }
        setFinishOnTouchOutside(false)
        when (intent.action) {
            ACTION_CREATE -> create()
            ACTION_GET -> get()
            else -> finish()
        }
    }

    private fun say(text: String) = runOnUiThread { status.text = text }

    private fun caller(info: CallingAppInfo, clientDataHash: ByteArray?): WebAuthn.Caller {
        val cert = info.signingInfo.apkContentsSigners.firstOrNull()?.toByteArray() ?: ByteArray(0)
        return WebAuthn.Caller(clientDataHash, WebAuthn.appOrigin(cert), info.packageName)
    }

    private fun create() {
        val req = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: return finish()
        val call = req.callingRequest as? CreatePublicKeyCredentialRequest ?: return finish()
        job = lifecycleScope.launch {
            val result = Intent()
            try {
                say(getString(R.string.passkey_connecting))
                Transports.open(this@PasskeyActivity).use { t ->
                    say(getString(R.string.passkey_press_ok, t.name))
                    val json = WebAuthn.create(t, call.requestJson, caller(req.callingAppInfo, call.clientDataHash)) {
                        say(getString(R.string.passkey_press_ok, t.name))
                    }
                    PendingIntentHandler.setCreateCredentialResponse(result, CreatePublicKeyCredentialResponse(json))
                }
                setResult(RESULT_OK, result)
            } catch (e: CtapException) {
                val err = if (e.status == Ctap.ERR_CREDENTIAL_EXCLUDED) InvalidStateError() else NotAllowedError()
                PendingIntentHandler.setCreateCredentialException(result, CreatePublicKeyCredentialDomException(err, e.message))
                setResult(RESULT_OK, result)
            } catch (e: Exception) {
                PendingIntentHandler.setCreateCredentialException(result,
                    CreatePublicKeyCredentialDomException(NotAllowedError(), e.message ?: "AuthKey error"))
                setResult(RESULT_OK, result)
            }
            finish()
        }
    }

    private fun get() {
        val req = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: return finish()
        val opt = req.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().firstOrNull() ?: return finish()
        job = lifecycleScope.launch {
            val result = Intent()
            try {
                say(getString(R.string.passkey_connecting))
                val assertions = Transports.open(this@PasskeyActivity).use { t ->
                    say(getString(R.string.passkey_press_ok, t.name))
                    WebAuthn.get(t, opt.requestJson, caller(req.callingAppInfo, opt.clientDataHash)) {
                        say(getString(R.string.passkey_press_ok, t.name))
                    }
                }
                val chosen = if (assertions.size == 1) assertions[0] else choose(assertions)
                if (chosen == null) {
                    PendingIntentHandler.setGetCredentialException(result, GetCredentialCancellationException())
                } else {
                    PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PublicKeyCredential(chosen.json)))
                }
                setResult(RESULT_OK, result)
            } catch (e: Exception) {
                PendingIntentHandler.setGetCredentialException(result,
                    GetPublicKeyCredentialDomException(NotAllowedError(), e.message ?: "AuthKey error"))
                setResult(RESULT_OK, result)
            }
            finish()
        }
    }

    /** Several accounts for this site on the device: let the user pick one. */
    private suspend fun choose(list: List<WebAuthn.Assertion>): WebAuthn.Assertion? {
        val picked = CompletableDeferred<WebAuthn.Assertion?>()
        val names = list.mapIndexed { i, a -> a.userName ?: "Account ${i + 1}" }.toTypedArray()
        AlertDialog.Builder(this)
            .setTitle(R.string.passkey_choose)
            .setItems(names) { _, i -> picked.complete(list[i]) }
            .setOnCancelListener { picked.complete(null) }
            .show()
        return picked.await()
    }

    private fun cancel() {
        job?.cancel()
        val result = Intent()
        if (intent.action == ACTION_CREATE) PendingIntentHandler.setCreateCredentialException(result, CreateCredentialCancellationException())
        else PendingIntentHandler.setGetCredentialException(result, GetCredentialCancellationException())
        setResult(RESULT_OK, result)
        finish()
    }

    @Deprecated("Back cancels the request")
    override fun onBackPressed() {
        cancel()
    }

    companion object {
        const val ACTION_CREATE = "io.github.nilotpal.authkey.CREATE_PASSKEY"
        const val ACTION_GET = "io.github.nilotpal.authkey.GET_PASSKEY"
    }
}
