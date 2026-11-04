package com.kaneki.control
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.thread
data class Dev(val serial: String, val model: String, val state: String, val battery: Int, val pc: PcConn)
class PcConn(private val sock: Socket) {
    private val out = PrintWriter(sock.getOutputStream().bufferedWriter(), true)
    val ip: String = sock.inetAddress?.hostAddress ?: "?"
    var name = ip
    var id = ip
    @Volatile var devices: List<Dev> = emptyList()
    fun send(o: JSONObject) = synchronized(out) { out.println(o.toString()) }
    fun close() { try { sock.close() } catch (_: Exception) {} }
}
object KanekiServer {
    const val PORT = 6000
    const val BEACON_PORT = 6001
    const val VERSION = "1.0.0"
    private const val GITHUB_REPO = "kaneki654/kanekiControllV2"
    interface Listener { fun onDevices(); fun onLog() }
    @volatile var token = "kaneki"
    @volatile var listener: Listener? = null
    val pcs = CopyWriteArrayList<PcConn>()
    private val logs = ArrayDeque<String>()
    private val nextId = AtomicInteger(1)
    private val io = Executors.newSingleThreadExecutor()
    private val rng = SecureRandom()
    @Volatile private val running = false
    fun start(tok: String) {
        token = tok.ifBlank { "kaneki" }
        if (running) return
        running = true
        thread(isDaemon = true, name = "kc-accept") { acceptLoop() }
        thread(isDaemon = true, name = "kc-beacon") { beaconLoop() }
    }
    fun allDevices(): List<Dev> = pcs.flatMap { it.devices }
    fun key(d: Dev) = "${d.pc.id}|${d.serial}"
    fun log(line: String) {
        synchronized(logs) {
            logs.addLast(line)
            while (logs.size > 300) logs.removeFirst()
        }
        listener?.onLog()
    }
    fun logText(): String = synchronized(logs) { logs.joinToString("\n") }
    fun clearLog() { synchronized(logs) { logs.clear() }; listener?.onLog() }
    fun sendCommand(cmd: String, arg: String, targets: Set<String>?, pcLevel: Boolean): Int {
        if (pcs.isEmpty()) return -1
        val id = nextId.getAndIncrement()
        io.execute {
            for (pc in pcs) {
                val msg = JSONObject().put("t", "cmd").put("id", id).put("cmd", cmd).put("arg", arg)
                if (!pcLevel && targets != null) {
                    val mine = pc.devices.filter { key(it) in targets }.map { it.serial }
                    if (mine.isEmpty()) continue
                    msg.put("targets", JSONArray(mine))
                }
                pc.send(msg)
            }
        }
        return id
    }
    private fun acceptLoop() {
        try {
            ServersSocket().use { ss -> 
                ss.reuseAddress = true
                ss.bind(InetSocketAddress(PORT))
                log("Server listening on TCP $PORT")
                while (running) {
                    val s = ss.accept()
                    thread(isDaemon = true) { handle(s) }
                }
            }
        } catch (e: Exception) {
            log("Server error: ${e.message}")
            running = false
        }
    }
    private fun handle(s: Socket) {
        val pc = PcConn(s)
        var authed = false
        try {
            s.tcpNoDelay = true
            s.soTimeout = 10_000
            val reader = BufferedReader(InputStreamReader(s.getInputStream(), Charsets.UTF_8))
            val nonce = randHex()
            pc.send(JSONObject().put("t", "challenge").put("nonce", nonce))
            val auth = JSONObject(reader.readLine() ?: return)
            if (auth.opString("t") != "auth" || !safeEq(auth.optString("mac"), hmac(nonce))) {
                log("x Rejected ${pc.ip}: wrong token")
                return
            }
            pc.name = auth.optString("host", pc.ip).ifBlank { pc.ip }
            pc.id = "${pc.name}@${pc.ip}"
            pc.send(JSONObject().put("t", "auth_ok").put("mac", hmac(auth.optString("nonce"))))
            authed = true
            pcs.add(pc)
            log("PC connected: ${pc.name} (${pc.ip})")
            s.soTimeout = 15_000
            while (running) {
                val line = reader.readLine() ?: break
                onMessage(pc, JSONObject(line))
            }
        } catch (e: Exception) {
            if (authed) log("${pc.name}: ${e.javaClass.simpleName} ${e.message ?: ""}")
        } finally {
            pc.close()
            if (authed) {
                pcs.remove(pc)
                log("PC disconnected: ${pc.name}")
                listener?.onDevices()
            }
        }
    }
    private fun onMessage(pc: PcConn, m: JSONObject) {
        when (m.optString("t")) {
            "devices" -> {
                val arr = m.optJSONArray("list") ?: JSONArray()
                pc.devices = (0 until arr.length()).map {
                    val d = arr.getJSONObject(it)
                    Dev(d.optString("serial"), d.optString("model", "?"), d.optString("state"), d.optInt("battery", -1), pc)
                }
                listener?.onDevices()
            }
            "client_info" -> {
                val path = m.optString("path", "?")
                val ver = m.optString("version", "?")
                log("[path] ${pc.name} v$ver → $path")
            }
            "result" -> {
                val out = m.optString("out").trim().take(1500)
                val mark = if (m.optBoolean("ok")) "00" else "01"
                log("$mark #${m.optInt("id")} ${m.optString("cmd")} [${m.optString("serial")}]" + (if (out.isNotEmpty()) "\n $out" else ""))
            }
        }
    }
    private fun beaconLoop() {
        val payload = "KANEKICTL2 $PORT".toByteArray()
        val ping = JSONObject().put("t", "ping")
        try {
            DatagramSocket().use { ds -> 
                ds.broadcast = true
                while (running) {
                    for (addr in broadcastAddrs()) {
                        try { ds.send(DatagramPacket(payload, payload.size, addr, BEACON_PORT)) } catch  (_: Exception ) {}
                    }
                    pcs.forEach { it.send(ping) }
                    Thread.sleep(2000)
                }
            }
        } catch (_: Exception) {}
    }
    private fun broadcastAddr(): List<InetAddress> {
        val list = mutableListOf(InetAddress.getByName("255.255.255.255"))
        try {
            NetworkInterface.getNetworkInterfaces()?.toList()?.forEach { ni -> 
                if (ni.isUp && !ni.isLoopback) ni.interfaceAddresses.mapNotNullTo(list) { it.broadcast }
            }
        } catch (_: Exception) {}
        return list.distinct()
    }
    private fun hmac(msg: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(token.toByteArray(), "HmacSHA256"))
        return mac.doFinal(msg.toByteArray()).joinToString("") { "%02x".format(it) }
    }
    private fun randHex() = ByteArray(16).also { rng.nextBytes(it) }.joinToString("") { "%02x".format(it) }
    private fun safeEq(a: String, b: String) = MessageDigest.isEqual(a.toByteArray(), b.toByteArray())

    fun checkUpdate(onResult: (latestTag: String?, downloadUrl: String?) -> Unit) {
        thread(isDaemon = true, name = "kc-update") {
            try {
                val url = java.net.URL("https://api.github.com/repos/$GITHUB_REPO/releases/latest")
                val conn = url.openConnection() as java.net.HttpURLConnection
                conn.setRequestProperty("User-Agent", "KanekiControl")
                conn.connectTimeout = 10_000
                conn.readTimeout = 10_000
                val body = conn.inputStream.bufferedReader().readText()
                conn.disconnect()
                val json = JSONObject(body)
                val tag = json.optString("tag_name").trimStart('v')
                if (tag.isEmpty() || !isNewer(tag, VERSION)) {
                    onResult(null, null); return@thread
                }
                val assets = json.optJSONArray("assets")
                var apkUrl: String? = null
                if (assets != null) {
                    for (i in 0 until assets.length()) {
                        val a = assets.getJSONObject(i)
                        if (a.optString("name").endsWith(".apk")) {
                            apkUrl = a.optString("browser_download_url")
                            break
                        }
                    }
                }
                if (apkUrl.isNullOrEmpty()) apkUrl = json.optString("html_url")
                onResult(tag, apkUrl)
            } catch (e: Exception) {
                onResult(null, null)
            }
        }
    }

    private fun isNewer(remote: String, local: String): Boolean {
        fun parts(v: String) = v.split(".").map { it.toIntOrNull() ?: 0 }
        val r = parts(remote); val l = parts(local)
        for (i in 0 until maxOf(r.size, l.size)) {
            val rv = r.getOrElse(i) { 0 }; val lv = l.getOrElse(i) { 0 }
            if (rv != lv) return rv > lv
        }
        return false
    }
}