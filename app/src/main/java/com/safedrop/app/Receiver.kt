package com.safedrop.app

import android.content.ContentValues
import android.content.Context
import android.os.Environment
import android.provider.MediaStore
import android.webkit.MimeTypeMap
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

class FileSpec(val name: String, val size: Long)
class Offer(val sender: String, val ip: String, val files: List<FileSpec>)
class Session(val files: List<FileSpec>) {
    val got: MutableSet<Int> = ConcurrentHashMap.newKeySet()
    val t: Long = System.currentTimeMillis()
}

interface Ui {
    fun log(msg: String)
    fun askOffer(o: Offer, answer: (Boolean) -> Unit)
}

/** Minimal HTTPS server. Protocol: POST /v1/offer, PUT /v1/file/<n>. */
class Receiver(private val app: Context, private val ui: Ui, private val deviceName: String) {
    @Volatile private var running = false
    private var server: SSLServerSocket? = null
    private var announceSock: DatagramSocket? = null
    private val pool = Executors.newCachedThreadPool()
    private val sessions = ConcurrentHashMap<String, Session>()
    private val busy = Semaphore(1)

    fun start() {
        val ssl = Identity.sslContext()
        val ss = ssl.serverSocketFactory.createServerSocket() as SSLServerSocket
        ss.reuseAddress = true
        ss.bind(InetSocketAddress(PORT))
        ss.enabledProtocols = arrayOf("TLSv1.3", "TLSv1.2")
        server = ss
        running = true
        Thread { acceptLoop(ss) }.start()
        Thread { announceLoop() }.start()
    }

    fun stop() {
        running = false
        try { server?.close() } catch (_: Exception) {}
        try { announceSock?.close() } catch (_: Exception) {}
    }

    private fun acceptLoop(ss: SSLServerSocket) {
        while (running) {
            try {
                val s = ss.accept() as SSLSocket
                pool.execute { handle(s) }
            } catch (e: Exception) {
                if (!running) break
            }
        }
    }

    private fun announceLoop() {
        val sock = DatagramSocket()
        sock.broadcast = true
        announceSock = sock
        val msg = JSONObject().put("app", "safedrop").put("v", 1).put("name", deviceName)
            .put("port", PORT).put("fp", Identity.fingerprint()).toString().toByteArray()
        while (running) {
            for (addr in broadcastAddresses(app)) {
                try { sock.send(DatagramPacket(msg, msg.size, addr, PORT)) } catch (_: Exception) {}
            }
            try { Thread.sleep(2000) } catch (_: InterruptedException) { break }
        }
        try { sock.close() } catch (_: Exception) {}
    }

    // ---- tiny HTTP helpers ----
    private fun readLine(inp: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = inp.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\n'.code) return sb.toString()
            if (b != '\r'.code) sb.append(b.toChar())
            if (sb.length > 8192) throw IOException("line too long")
        }
    }

    private fun readExact(inp: InputStream, n: Int): ByteArray {
        val b = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = inp.read(b, off, n - off)
            if (r < 0) throw IOException("eof")
            off += r
        }
        return b
    }

    private fun copyExact(inp: InputStream, os: OutputStream, n: Long) {
        val buf = ByteArray(65536)
        var left = n
        while (left > 0) {
            val r = inp.read(buf, 0, minOf(buf.size.toLong(), left).toInt())
            if (r < 0) throw IOException("connection lost")
            os.write(buf, 0, r)
            left -= r
        }
    }

    private fun reply(out: OutputStream, code: Int, body: String = "{}") {
        val phrase = when (code) {
            200 -> "OK"; 400 -> "Bad Request"; 403 -> "Forbidden"; 404 -> "Not Found"
            409 -> "Conflict"; 413 -> "Payload Too Large"; else -> "Error"
        }
        val b = body.toByteArray()
        val head = "HTTP/1.1 $code $phrase\r\nContent-Type: application/json\r\n" +
                "Content-Length: ${b.size}\r\nConnection: close\r\n\r\n"
        out.write(head.toByteArray())
        out.write(b)
        out.flush()
    }

    private fun handle(s: SSLSocket) {
        try {
            s.soTimeout = 60000
            s.startHandshake()
            val inp = BufferedInputStream(s.inputStream, 65536)
            val out = s.outputStream
            val reqLine = readLine(inp) ?: return
            val parts = reqLine.split(" ")
            if (parts.size < 2) return
            val headers = HashMap<String, String>()
            while (true) {
                val l = readLine(inp) ?: return
                if (l.isEmpty()) break
                if (headers.size > 64) return
                val i = l.indexOf(':')
                if (i > 0) headers[l.substring(0, i).trim().lowercase()] = l.substring(i + 1).trim()
            }
            val len = headers["content-length"]?.toLongOrNull() ?: 0L
            val ip = s.inetAddress?.hostAddress ?: "?"
            when {
                parts[0] == "POST" && parts[1] == "/v1/offer" -> onOffer(inp, out, len, ip)
                parts[0] == "PUT" && parts[1].startsWith("/v1/file/") -> onPut(inp, out, parts[1], headers, len)
                else -> reply(out, 404)
            }
        } catch (_: Exception) {
        } finally {
            try { s.close() } catch (_: Exception) {}
        }
    }

    private fun parseOffer(body: ByteArray, ip: String): Offer? = try {
        val j = JSONObject(String(body, Charsets.UTF_8))
        val arr = j.getJSONArray("files")
        if (arr.length() < 1 || arr.length() > 1000) {
            null
        } else {
            val files = ArrayList<FileSpec>()
            for (i in 0 until arr.length()) {
                val f = arr.getJSONObject(i)
                val sz = f.getLong("size")
                if (sz < 0) throw IllegalArgumentException("size")
                files.add(FileSpec(safeName(f.getString("name")), sz))
            }
            Offer(j.optString("sender", "?").filter { it >= ' ' }.take(50), ip, files)
        }
    } catch (e: Exception) {
        null
    }

    private fun onOffer(inp: InputStream, out: OutputStream, len: Long, ip: String) {
        if (len <= 0 || len > (1 shl 20)) { reply(out, 413); return }
        val offer = parseOffer(readExact(inp, len.toInt()), ip)
        if (offer == null) { reply(out, 400); return }
        if (!busy.tryAcquire()) { reply(out, 409); return }
        try {
            val q = ArrayBlockingQueue<Boolean>(1)
            ui.askOffer(offer) { q.offer(it) }
            val ok = q.poll(90, TimeUnit.SECONDS) == true
            if (!ok) { reply(out, 403); return }
            val raw = ByteArray(24)
            SecureRandom().nextBytes(raw)
            val tok = android.util.Base64.encodeToString(raw,
                android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)
            sessions[tok] = Session(offer.files)
            reply(out, 200, "{\"token\":\"$tok\"}")
        } finally {
            busy.release()
        }
    }

    private fun mime(name: String): String =
        MimeTypeMap.getSingleton().getMimeTypeFromExtension(name.substringAfterLast('.', "").lowercase())
            ?: "application/octet-stream"

    private fun onPut(inp: InputStream, out: OutputStream, path: String, h: Map<String, String>, len: Long) {
        val token = (h["x-token"] ?: "").toByteArray()
        var sess: Session? = null
        for ((t, v) in sessions) {
            if (MessageDigest.isEqual(t.toByteArray(), token)) sess = v
        }
        if (sess == null || System.currentTimeMillis() - sess.t > 3600000L) { reply(out, 403); return }
        val idx = path.removePrefix("/v1/file/").toIntOrNull()
        val f = if (idx == null) null else sess.files.getOrNull(idx)
        if (idx == null || f == null || len != f.size || sess.got.contains(idx)) { reply(out, 400); return }

        val res = app.contentResolver
        val cv = ContentValues()
        cv.put(MediaStore.Downloads.DISPLAY_NAME, f.name)
        cv.put(MediaStore.Downloads.MIME_TYPE, mime(f.name))
        cv.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/SafeDrop")
        cv.put(MediaStore.Downloads.IS_PENDING, 1)
        val uri = res.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv)
        if (uri == null) { reply(out, 500); return }
        try {
            val os = res.openOutputStream(uri) ?: throw IOException("cannot open output")
            os.use { copyExact(inp, it, len) }
            val done = ContentValues()
            done.put(MediaStore.Downloads.IS_PENDING, 0)
            res.update(uri, done, null, null)
        } catch (e: Exception) {
            try { res.delete(uri, null, null) } catch (_: Exception) {}
            try { reply(out, 500) } catch (_: Exception) {}
            ui.log("Receive failed: ${f.name}")
            return
        }
        sess.got.add(idx)
        ui.log("Saved to Downloads/SafeDrop: ${f.name}")
        reply(out, 200)
    }
}
