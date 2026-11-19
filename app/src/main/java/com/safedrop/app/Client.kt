package com.safedrop.app

import android.content.ContentResolver
import android.net.Uri
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.net.SocketTimeoutException
import java.net.URL
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class Device(val ip: String, val port: Int, val name: String, val fp: String, var seen: Long)
class Pick(val uri: Uri, val name: String, val size: Long)

/** Listens for UDP announcements of other SafeDrop devices. */
class Discoverer(private val onUpdate: (List<Device>) -> Unit) {
    @Volatile private var running = false
    private var sock: DatagramSocket? = null
    private val devices = ConcurrentHashMap<String, Device>()

    fun start(ownFp: String) {
        running = true
        Thread {
            try {
                val s = DatagramSocket(null as SocketAddress?)
                s.reuseAddress = true
                s.bind(InetSocketAddress(PORT))
                s.soTimeout = 1000
                sock = s
                val buf = ByteArray(2048)
                while (running) {
                    try {
                        val p = DatagramPacket(buf, buf.size)
                        s.receive(p)
                        val j = JSONObject(String(p.data, 0, p.length, Charsets.UTF_8))
                        val fp = j.optString("fp", "")
                        if (j.optString("app") == "safedrop" && Regex("[0-9a-f]{64}").matches(fp) && fp != ownFp) {
                            val ip = p.address.hostAddress ?: continue
                            val port = j.optInt("port", PORT)
                            devices["$ip:$port"] = Device(ip, port, j.optString("name", "?").take(50), fp,
                                System.currentTimeMillis())
                        }
                    } catch (_: SocketTimeoutException) {
                    } catch (e: Exception) {
                        if (!running) break
                    }
                    val now = System.currentTimeMillis()
                    devices.values.removeAll { now - it.seen > 8000 }
                    onUpdate(devices.values.sortedBy { it.name })
                }
                s.close()
            } catch (_: Exception) {
            }
        }.start()
    }

    fun stop() {
        running = false
        try { sock?.close() } catch (_: Exception) {}
    }
}

private class PinTm(val expected: String?) : X509TrustManager {
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        val c = chain?.firstOrNull() ?: throw CertificateException("no certificate")
        if (expected != null && sha256Hex(c.encoded) != expected) {
            throw CertificateException("fingerprint mismatch")
        }
    }
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}

object Sender {
    private fun ctxFor(expected: String?): SSLContext {
        val c = SSLContext.getInstance("TLS")
        c.init(null, arrayOf<TrustManager>(PinTm(expected)), null)
        return c
    }

    /** Connect once and return the SHA-256 fingerprint of the peer certificate. */
    fun probe(host: String, port: Int): String {
        val s = ctxFor(null).socketFactory.createSocket() as SSLSocket
        try {
            s.connect(InetSocketAddress(host, port), 8000)
            s.soTimeout = 8000
            s.startHandshake()
            return sha256Hex(s.session.peerCertificates[0].encoded)
        } finally {
            try { s.close() } catch (_: Exception) {}
        }
    }

    /** Returns null on success or an error message. */
    fun send(host: String, port: Int, fp: String, senderName: String, files: List<Pick>,
             cr: ContentResolver, progress: (String, Long, Long) -> Unit): String? {
        try {
            val sslCtx = ctxFor(fp)
            fun open(path: String, method: String): HttpsURLConnection {
                val c = URL("https://$host:$port$path").openConnection() as HttpsURLConnection
                c.sslSocketFactory = sslCtx.socketFactory
                c.hostnameVerifier = HostnameVerifier { _, _ -> true }  // identity = pinned fingerprint
                c.requestMethod = method
                c.connectTimeout = 8000
                c.readTimeout = 100000
                return c
            }

            val arr = JSONArray()
            for (f in files) arr.put(JSONObject().put("name", f.name).put("size", f.size))
            val body = JSONObject().put("sender", senderName).put("files", arr).toString().toByteArray()
            val c = open("/v1/offer", "POST")
            c.doOutput = true
            c.setFixedLengthStreamingMode(body.size)
            c.setRequestProperty("Content-Type", "application/json")
            c.outputStream.use { it.write(body) }
            val code = c.responseCode
            val resp = if (code == 200) c.inputStream.bufferedReader().readText() else ""
            c.disconnect()
            if (code != 200) return "Rejected by the other side, or timed out (HTTP $code)"
            val tok = JSONObject(resp).getString("token")

            for ((i, f) in files.withIndex()) {
                val u = open("/v1/file/$i", "PUT")
                u.doOutput = true
                u.setFixedLengthStreamingMode(f.size)
                u.setRequestProperty("X-Token", tok)
                u.setRequestProperty("Content-Type", "application/octet-stream")
                val input = cr.openInputStream(f.uri) ?: return "Cannot read ${f.name}"
                BufferedOutputStream(u.outputStream, 65536).use { os ->
                    input.use { ins ->
                        val buf = ByteArray(65536)
                        var sent = 0L
                        var lastPct = -1L
                        while (true) {
                            val r = ins.read(buf)
                            if (r < 0) break
                            os.write(buf, 0, r)
                            sent += r
                            val pct = if (f.size > 0) sent * 100 / f.size else 100
                            if (pct != lastPct) { lastPct = pct; progress(f.name, sent, f.size) }
                        }
                    }
                }
                val rc = u.responseCode
                u.disconnect()
                if (rc != 200) return "Failed on ${f.name} (HTTP $rc)"
            }
            return null
        } catch (e: Exception) {
            return "Error: ${e.message}"
        }
    }
}
