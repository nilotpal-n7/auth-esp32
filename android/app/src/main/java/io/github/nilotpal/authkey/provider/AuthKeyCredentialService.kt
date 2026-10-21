package io.github.nilotpal.authkey.provider

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnsupportedException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import java.util.concurrent.atomic.AtomicInteger

/**
 * Android 14+ passkey provider: AuthKey appears in Android's passkey sheet
 * (Chrome, apps). Nothing is stored on the phone; picking the entry opens
 * [PasskeyActivity], which talks to the AuthKey over Bluetooth or USB.
 */
@RequiresApi(34)
class AuthKeyCredentialService : CredentialProviderService() {

    private fun intentFor(action: String): PendingIntent = PendingIntent.getActivity(
        this, requestCodes.incrementAndGet(),
        Intent(this, PasskeyActivity::class.java).setAction(action).setPackage(packageName),
        PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        if (request !is BeginCreatePublicKeyCredentialRequest) {
            callback.onError(CreateCredentialUnsupportedException("AuthKey only stores passkeys"))
            return
        }
        val entry = CreateEntry.Builder("AuthKey security key", intentFor(PasskeyActivity.ACTION_CREATE))
            .setDescription("Saved on your AuthKey-ESP32 (approve on its screen)")
            .build()
        callback.onResult(BeginCreateCredentialResponse.Builder().addCreateEntry(entry).build())
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        // The phone can't list the device's passkeys without asking it, so
        // offer one entry; the AuthKey picks (or lets you pick) the account.
        val builder = BeginGetCredentialResponse.Builder()
        request.beginGetCredentialOptions.filterIsInstance<BeginGetPublicKeyCredentialOption>().forEach { opt ->
            builder.addCredentialEntry(
                PublicKeyCredentialEntry.Builder(this, "AuthKey security key", intentFor(PasskeyActivity.ACTION_GET), opt)
                    .setDisplayName("Bluetooth / USB: approve on the AuthKey")
                    .build()
            )
        }
        callback.onResult(builder.build())
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) = callback.onResult(null)

    companion object {
        private val requestCodes = AtomicInteger(1000)
    }
}
