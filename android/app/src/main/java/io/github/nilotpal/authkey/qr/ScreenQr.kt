package io.github.nilotpal.authkey.qr

import android.annotation.SuppressLint
import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Bitmap
import android.graphics.ImageDecoder
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.service.quicksettings.TileService
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import io.github.nilotpal.authkey.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Reading a QR shown on this phone's own screen, like the Windows helper:
 *  - Quick Settings tile "AuthKey QR": asks Android for a one-off screen
 *    capture, grabs the screen and looks for a QR.
 *  - Share a screenshot to "AuthKey" from the gallery.
 *
 * Some apps hide their window from screen capture (it comes out black); then
 * use the camera scanner on another device, or the share route.
 */
class ScreenQrActivity : AppCompatActivity() {

    private val consent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == Activity.RESULT_OK && r.data != null) {
            startForegroundService(Intent(this, ScreenCaptureService::class.java)
                .putExtra(ScreenCaptureService.EXTRA_CODE, r.resultCode)
                .putExtra(ScreenCaptureService.EXTRA_DATA, r.data))
        }
        finish()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent.action == Intent.ACTION_SEND) {
            val uri = if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                      else @Suppress("DEPRECATION") intent.getParcelableExtra(Intent.EXTRA_STREAM)
            if (uri == null) { finish(); return }
            lifecycleScope.launch { fromImage(uri); finish() }
            return
        }
        val mpm = getSystemService(MediaProjectionManager::class.java)
        consent.launch(mpm.createScreenCaptureIntent())
    }

    private suspend fun fromImage(uri: Uri) {
        val text = try {
            withContext(Dispatchers.Default) {
                val bmp = ImageDecoder.decodeBitmap(ImageDecoder.createSource(contentResolver, uri)) { d, _, _ ->
                    d.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                }
                QrDecoder.decode(bmp)
            }
        } catch (e: Exception) {
            android.util.Log.w("AuthKey", "can't read shared image: $e")
            Toast.makeText(this, getString(R.string.share_unreadable), Toast.LENGTH_LONG).show()
            return
        }
        if (text == null) {
            android.util.Log.i("AuthKey", "shared image: no QR")
            Toast.makeText(this, R.string.screen_no_qr, Toast.LENGTH_LONG).show()
            return
        }
        val msg = try {
            QrSender.send(this, text) {}
        } catch (e: Exception) {
            e.message ?: "Failed"
        }
        android.util.Log.i("AuthKey", "shared image: ${QrSender.kind(text)} QR -> $msg")
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
    }
}

/** Holds the screen capture (Android requires a foreground service for it) just long enough to find a QR. */
class ScreenCaptureService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val handler = Handler(Looper.getMainLooper())
    private var projection: MediaProjection? = null
    private var display: VirtualDisplay? = null
    private var reader: ImageReader? = null

    override fun onBind(intent: Intent?): IBinder? = null

    @SuppressLint("WrongConstant")
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, getString(R.string.screen_channel), NotificationManager.IMPORTANCE_LOW))
        val n = Notification.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_key)
            .setContentTitle(getString(R.string.screen_looking)).build()
        if (Build.VERSION.SDK_INT >= 29) startForeground(2, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION)
        else startForeground(2, n)

        val code = intent?.getIntExtra(EXTRA_CODE, 0) ?: 0
        val data = if (Build.VERSION.SDK_INT >= 33) intent?.getParcelableExtra(EXTRA_DATA, Intent::class.java)
                   else @Suppress("DEPRECATION") intent?.getParcelableExtra(EXTRA_DATA)
        if (data == null) { stopSelf(); return START_NOT_STICKY }

        val mp = getSystemService(MediaProjectionManager::class.java).getMediaProjection(code, data)
            ?: run { stopSelf(); return START_NOT_STICKY }
        projection = mp
        mp.registerCallback(object : MediaProjection.Callback() {
            override fun onStop() = cleanup()
        }, handler)
        val metrics = resources.displayMetrics
        val w = metrics.widthPixels
        val h = metrics.heightPixels
        val r = ImageReader.newInstance(w, h, PixelFormat.RGBA_8888, 2)
        reader = r
        display = mp.createVirtualDisplay("AuthKey QR", w, h, metrics.densityDpi,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR, r.surface, null, handler)

        // Give the consent dialog time to disappear, then try frames for a few seconds.
        val started = System.currentTimeMillis()
        var busy = false
        r.setOnImageAvailableListener({ ir ->
            val img = ir.acquireLatestImage() ?: return@setOnImageAvailableListener
            if (busy || System.currentTimeMillis() - started < 700) { img.close(); return@setOnImageAvailableListener }
            busy = true
            val plane = img.planes[0]
            val rowPx = plane.rowStride / plane.pixelStride
            val bmp = Bitmap.createBitmap(rowPx, h, Bitmap.Config.ARGB_8888)
            bmp.copyPixelsFromBuffer(plane.buffer)
            img.close()
            scope.launch {
                val text = withContext(Dispatchers.Default) { QrDecoder.decode(Bitmap.createBitmap(bmp, 0, 0, w, h)) }
                if (text != null) {
                    cleanup()
                    val msg = try { QrSender.send(this@ScreenCaptureService, text) {} } catch (e: Exception) { e.message ?: "Failed" }
                    android.util.Log.i("AuthKey", "screen: ${QrSender.kind(text)} QR -> $msg")
                    Toast.makeText(this@ScreenCaptureService, msg, Toast.LENGTH_LONG).show()
                    stopSelf()
                } else {
                    busy = false
                }
            }
        }, handler)
        handler.postDelayed({
            if (projection != null) {
                android.util.Log.i("AuthKey", "screen: no QR found")
                cleanup()
                Toast.makeText(this, R.string.screen_no_qr, Toast.LENGTH_LONG).show()
                stopSelf()
            }
        }, 6000)
        return START_NOT_STICKY
    }

    private fun cleanup() {
        reader?.setOnImageAvailableListener(null, null)
        display?.release(); display = null
        reader?.close(); reader = null
        projection?.stop(); projection = null
    }

    override fun onDestroy() {
        cleanup()
        super.onDestroy()
    }

    companion object {
        const val EXTRA_CODE = "code"
        const val EXTRA_DATA = "data"
        private const val CHANNEL = "screen_qr"
    }
}

/** Quick Settings tile: tap while a passkey QR is on screen. */
class QrTileService : TileService() {
    override fun onClick() {
        val intent = Intent(this, ScreenQrActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }
}
