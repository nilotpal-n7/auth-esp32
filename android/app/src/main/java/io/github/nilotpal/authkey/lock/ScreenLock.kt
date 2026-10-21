package io.github.nilotpal.authkey.lock

import android.accessibilityservice.AccessibilityService
import android.app.KeyguardManager
import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.view.accessibility.AccessibilityEvent

/**
 * Two ways to lock the phone, whichever the user switched on:
 *  - Accessibility ("normal"): same as the power button; fingerprint and face
 *    unlock keep working.
 *  - Device admin ("strict"): Android then needs the PIN / pattern / password
 *    once (no fingerprint, no trusted device) before unlocking.
 */
object ScreenLock {
    fun adminComponent(ctx: Context) = ComponentName(ctx, LockAdminReceiver::class.java)

    fun adminActive(ctx: Context) =
        ctx.getSystemService(DevicePolicyManager::class.java).isAdminActive(adminComponent(ctx))

    fun accessibilityActive() = LockAccessibilityService.instance != null

    fun canLock(ctx: Context) = accessibilityActive() || adminActive(ctx)

    fun isLocked(ctx: Context) = ctx.getSystemService(KeyguardManager::class.java).isKeyguardLocked

    /** Returns false if no lock method is enabled. */
    fun lock(ctx: Context): Boolean {
        LockAccessibilityService.instance?.let {
            return it.performGlobalAction(AccessibilityService.GLOBAL_ACTION_LOCK_SCREEN)
        }
        if (adminActive(ctx)) {
            ctx.getSystemService(DevicePolicyManager::class.java).lockNow()
            return true
        }
        return false
    }
}

class LockAdminReceiver : DeviceAdminReceiver()

/** Does nothing but lock the screen on request (no events are read). */
class LockAccessibilityService : AccessibilityService() {
    override fun onServiceConnected() { instance = this }
    override fun onDestroy() { instance = null; super.onDestroy() }
    override fun onUnbind(intent: android.content.Intent?): Boolean { instance = null; return super.onUnbind(intent) }
    override fun onAccessibilityEvent(event: AccessibilityEvent?) {}
    override fun onInterrupt() {}

    companion object {
        @Volatile var instance: LockAccessibilityService? = null
    }
}
