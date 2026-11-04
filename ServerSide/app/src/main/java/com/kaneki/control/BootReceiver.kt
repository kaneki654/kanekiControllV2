package com.kaneki.control
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val allowed = setOf(
            Intent.ACTION_BOOT_COMPLETED,
            "android.intent.action.LOCKED_BOOT_COMPLETED",
            "android.intent.action.QUICKBOOT_POWERON",
            "android.intent.action.QUICKBOOT_POWERON"
        )
        if (intent.action !in allowed) return
        val svc = Intent(context, KanekiService::class.java)
        ContextCompat.startForegroundService(context, svc)
    }
}