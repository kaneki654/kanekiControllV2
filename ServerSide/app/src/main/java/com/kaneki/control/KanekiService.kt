package com.kaneki.control
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
class KanekiService : Service(), KanekiServer.Listener {
    companion object {
        const val CH = "kaneki_ctrl"
        const val NOTIF_ID = 1
    }
    override fun onCreate() {
        super.onCreate()
        createChannel()
        startForeground(NOTIF_ID, buildNotif("Starting...", 0, 0))
        KanekiServer.listener = this
        val prefs = getSharedPreferences("kc", MODE_PRIVATE)
        KanekiServer.start(prefs.getString("token", "kaneki") ?: "kaneki")
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return START_STICKY
    }
    override fun onDestroy() {
        if (KanekiServer.Listener === this) KanekiServer.listener = null
        super.onDestroy()
    }
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onDevices() = updateNotif()
    override fun onLog() = Unit
    private fun updateNotif() {
        val pcs = KanekiServer.pcs.size
        val devs = KanekiServer.allDevices().size
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ID, buildNotif("Running . PCs: $pcs . Devices: $devs", pcs, devs))
    }
    private fun buildNotif(text: String, pcs: Int, devs: Int): Notification {
        val tap = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return Notification.Builder(this, CH)
            .setContentTitle("KanekiControlv2")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setContentIntent(tap)
            .setOngoing(true)
            .setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
            .also { b -> 
                if (Build.VERSION.SDK_INT >= 31) b.setForegroundServiceBehavior(
                    Notification.FOREGROUND_SERVICE_IMMEDIATE
                )
            }
            .build()
    }
    private fun createChannel() {
        val nm = setSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CH) != null) return
        val ch = NotificationChannel(CH, "KanekiControl", NotificationManager.IMPORTANCE_LOW)
        ch.description = "Server status"
        ch.setShowBadge(false)
        nm.createNotificationChannel(ch)
    }
}