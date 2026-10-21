package io.github.nilotpal.authkey.qr

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.zxing.PlanarYUVLuminanceSource
import io.github.nilotpal.authkey.R
import kotlinx.coroutines.launch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Camera scanner for passkey QR codes shown by any computer or phone
 * ("Use a phone or tablet" / "Use another device"), and authenticator QRs.
 */
class ScanActivity : AppCompatActivity() {
    private lateinit var status: TextView
    private val found = AtomicBoolean(false)
    private val analyzer = Executors.newSingleThreadExecutor()

    private val askCamera = registerForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        if (ok) startCamera() else { status.text = getString(R.string.scan_need_camera) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan)
        status = findViewById(R.id.status)
        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) startCamera()
        else askCamera.launch(Manifest.permission.CAMERA)
    }

    private fun startCamera() {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            val provider = future.get()
            val preview = Preview.Builder().build().also {
                it.surfaceProvider = findViewById<PreviewView>(R.id.preview).surfaceProvider
            }
            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            analysis.setAnalyzer(analyzer) { image -> analyze(image) }
            provider.unbindAll()
            provider.bindToLifecycle(this, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
        }, ContextCompat.getMainExecutor(this))
    }

    private fun analyze(image: ImageProxy) {
        try {
            if (found.get()) return
            val plane = image.planes[0]           // Y (luminance) plane
            val buf = plane.buffer
            val data = ByteArray(buf.remaining()).also { buf.get(it) }
            val source = PlanarYUVLuminanceSource(data, plane.rowStride, image.height, 0, 0,
                image.width, image.height, false)
            val text = QrDecoder.decode(source) ?: return
            if (found.compareAndSet(false, true)) runOnUiThread { handle(text) }
        } finally {
            image.close()
        }
    }

    private fun handle(text: String) {
        ProcessCameraProvider.getInstance(this).get().unbindAll()
        status.text = getString(if (QrSender.kind(text) == "totp") R.string.scan_found_totp else R.string.scan_found_passkey)
        lifecycleScope.launch {
            val msg = try {
                QrSender.send(this@ScanActivity, text) { p -> runOnUiThread { status.text = p } }
            } catch (e: Exception) {
                e.message ?: "Failed"
            }
            status.text = msg
        }
    }

    override fun onDestroy() {
        analyzer.shutdown()
        super.onDestroy()
    }
}
