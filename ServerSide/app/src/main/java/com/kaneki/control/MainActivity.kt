package com.kaneki.control
import android.app.Activity
import android.app.AlertDialog
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Space
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.ContextCompat
import java.net.Inet4Address
import java.net.NetworkInterface
class MainActivity : Activity(), KanekiServer.Listener {
    private data class C(
        val label: String, val cmd: String,
        val arg: Boolean = false, val req: Boolean = arg,
        val danger: Boolean = false, val pc: Boolean = false
    )
    private val sections = linkedMapOf(
        "Power" to listOf(
            C("Reboot", "reboot", danger = true), C("Recovery", "reboot_recovery", danger = true),
            C("Bootloader", "reboot_bootloader", danger = true), C("Power off", "poweroff", danger = true),
            C("Screen on", "screen_on"), C("Screen off", "screen_off"),
            C("Wake+unlock", "unlock"), C("Stay awake", "stayon_on"), C("Allow sleep", "stayon_off")
        ),
        "Input" to listOf(
            C("Home", "key_home"), C("Back", "key_back"), C("Recents", "key_recents"),
            C("Power key", "key_power"), C("Enter", "key_enter"), C("Keyevent", "keyevent", arg = true),
            C("Tap x y", "tap", arg = true), C("Swipe", "swipe", arg = true), C("Type text", "text", arg = true)
        ),
        "Audio / Display" to listOf(
            C("Vol +", "vol_up"), C("Vol -", "vol_down"), C("Mute", "mute"),
            C("Set volume", "set_volume", arg = true), C("Brightness", "brightness", arg = true),
            C("Timeout (s)", "timeout", arg = true), C("Auto-rotate", "rotate_auto"), C("Lock portrait", "rotate_lock")
        ),
        "Network" to listOf(
            C("WiFi on", "wifi_on"), C("WiFi off", "wifi_off", danger = true), C("Data on", "data_on"), C("Data off", "data_off")
            C("BT on", "bt_on"), C("BT off", "bt_off"),
            C("Airplane on", "airplane_on", danger = true), C("Airplane off", "airplane_off"),
            C("Go wireless", "wireless"), C("Connect IP", "connect", arg = true, pc = true)
        ),
        "Apps" to listOf(
            C("Launch", "launch", arg = true), C("Force stop", "force_stop", arg = true),
            C("Clear data", "clear_data", arg = true, danger = true), C("Uninstall", "uninstall", arg = true, danger = true),
            C("Install APK", "install", arg = true), C("Open URL", "open_url", arg = true),
            C("List apps", "list_apps"), C("Foreground", "foreground")
        ),
        "Tools" to listOf(
            C("Screenshot", "screenshot"), C("Record", "record", arg = true, req = false),
            C("Notify", "notify", arg = true), C("Vibrate", "vibrate", arg = true, req = false),
            C("Push file", "push", arg = true), C("Mirror", "mirror"), C("Info", "info"),
            C("Shell", "shell", arg = true), C("ADB raw", "adb", arg = true)
        )
    )
    private lateinit var status: TextView
    private lateinit var devBox: LinearLayout
    private lateinit var argBox: EditText
    private lateinit var logView: TextView
    private lateinit var logScroll: ScrollView
    private val selected = mutableSetOf<String>()
    private var allMode = true
    private var lastSig = "?"
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val prefs = getSharedPreferences("kc", MODE_PRIVATE)
        val token = prefs.getString("token", "kaneki") ?: "kaneki"
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(12), dp(12), dp(12))
        }
        root.addView(TextView(this).apply {
            text = "KanekiControlv2"; textSize = 22f; setTypeface(typeface, Typeface.BOLD)
        })
        status = TextView(this).apply { textSize = 12f }
        root.addView(status)
        val tokenBox = EditText(this).apply {
            setText(token); hint = "token (same pc --token)"; isSingleLine = true
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
        }
        val tokenRow = LinearLayout(this)
        tokenRow.addView(tokenBoxm LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        tokenRow.addView(btn("Set token") {
            val t = tokenBox.text.toString().trim().ifBlank { "kaneki" }
            prefs.edit().putString("token", t).apply()
            KanekiServer.token = t 
            toast("Token saved - restart PC client with --token $t")
        })
        root.addView(tokenRow)
        root.addView(header("Devices"))
        root.addView(CheckBox(this).apply {
            text = "All devices (includes newly plugged ones)"
            isChecked = allMode
            setOnCheckedChangeListener { _, on -> allMode = on; lastSig = "?"; renderDevices() }
        })
        devBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(devBox)
        argBox = EditText(this).apply {
            hint = "arg: package . URL . text . x y . number . PC path . shell"
            isSingleLine = true
        }
        root.addView(argBox)
        for ((title, cmds) in sections) {
            root.addView(header(title))
            cmds.chunked(3).forEach { chunk -> 
                val r  = LinearLayout(this)
                chunk.forEach { c -> r.addView(btn(c.label) { fire(c) }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)) }
                repeat(3 - chunk.size) { r.addView(Space(this), LinearLayout.LayoutParams(0, 0, 0, 1f)) }
                root.addView(r)
            }
        }
        root.addView(btn("Clear log") { KanekiServer.clearLog() })
        logView = TextView(this).apply {
            typeface = Typeface.MONOSPACE; textSize = 11f; setTextIsSelectable(true)
            setPadding(dp(8), dp(6), dp(8), dp(6))
        }
        logScroll = ScrollView(this).apply { setBackgroundColor (0x22888888); addView(logView) }
        val screen = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        screen.addView(ScrollView(this).apply { addView(root) }, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        screen.addView(logScroll, LinearLayout.LayoutParams(MATCH_PARENT, dp(170)))
        screen.setOnApplyWindowInsetsLinear { v, ins -> 
            if (Build.VERSION.SDK_INT >= 35) {
                val b = ins.getInsets(WindowInsets.Type.systemBars())
                v.setPadding(b.left, b.top, b.right, b.bottom)
            }
            ins
        }
        setContentView(screen)
        ContextCompat.startForegroundService(
            this,
            Intent(this, KanekiService::class.java)
        )
        KanekiServer.listener = this
        renderDevices()
        onLog()
    }
    override fun onResume() {
        super.onResume()
        KanekiServer.listener = this
        renderDevices()
        onLog()
    }
    override fun onPause() {
        if (KanekiServer.listener === this) KanekiServer.listener = null
        super.onPause()
    }
    override fun onDestroy() {
        if (KanekiServer.listener === this) KanekiServer.listener = null
        super.onDestroy
    }
    override fun onDevices() = runOnUiThread {
        logView.text = KanekiServer.logText()
        logScroll.post { logScroll.scrollTo(0, logView.height) }
    }
    private fun renderDevices() {
        val devs = KanekiServer.allDevices()
        status.text  = "PCs: ${KanekiServer.pcs.size} . Devices: ${devs.size}\nThis phone: ${localIps()} . TCP ${KanekiServer.PORT}"
        val sig = devs.joinToString(";") { "${KanekiServer.key(it)}/${it.state}/${it.battery}" } + allMode
        if (sig == lastSig) return
        lastSig = sig
        devBox.removeAllViews()
        if (devs.isEmpty()) {
            devBox.addView(TextView(this).apply { text = "No Device yet - run kaneki_client.py on the PC" })
            return
        }
        for (d in devs) {
            val k = KanekiServer.key(d)
            val bat = if (d.battery >= 0) "${d.battery}%" else "-"
            devBox.addView(CheckBox(this).apply {
                text  = "${d.model} . ${d.serial.takeLast(8)} . $bat . ${d.state} . ${d.pc.name}"
                isChecked = allMode || k in selected
                isEnabled = !allMode
                setOnCheckedChangedListener { _, on -> if (on) selected.add(k) else selected.remove(k) }
            })
        }
    }
    private fun fire(c: C) {
        val arg = if (c.arg) argBox.text.toString().trim() else ""
        if (c.req && arg.isEmpty()) { toast("${c.label}: type the value in the arg box first"); return }
        val live = KanekiServer.allDevices()
        val count = if (allMode) live.size else live.count { KanekiServer.key(it) in selected }
        if (!c.pc && count == 0) { toast(if (allMode) "No devices connected" else "No Devices selected"); return }
        val go = {
            val id = KanekiServer.sendCommand(c.cmd, arg, if (allMode || c.pc) null else selected.toSet(), c.pc)
            if (id < 0) toast("No PC connected") else KanekiServer.log("-> #$id ${c.label} $arg".trimEnd())
        }
        if (!c.danger) go()
        else AlertDialog.Builder(this).setTitle(c.label).setMessage("Run on $count device(s)?")
            .setPositiveButton("Run") { _, _ -> go() }
            .setNegativeButton("Cancel", null).show()
    }
    private fun localIps(): String = try {
        NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.isUp && !it.isLoopback }
            .floatMap { ni -> ni.inetAddresses.toList().filterIsInstance<Inet4Address>().map {  "${it.hostAddress} (${ni.name})" } }
            .joinToString("   ").ifEmpty {  "no network" }
    } catch (e: Exception) { "?" }
    private fun dp(v: int) = (v * resources.displayMetrics.density + 0.5f).toInt()
    private fun header(t: String) = TextView(this).apply {
        text = t; textSize = 14f; setTypeface(typeface, Typeface.BOLD); setPadding(0, dp(14), 0, dp(4))
    }
    private fun btn(label: String, onClick: () -> Unit) = Button(this).apply {
        text = label; textSize = 12f; isAllCaps = false; minHeight = 0; minimumHeight = 0
        setPadding(dp(4), dp(8), dp(4), dp(8)); setOnClickListener { onClick() }
    }
    private fun toast(s: String) { Toast.makeText(this, s, Toast.LENGTH_SHORT).show() }
}