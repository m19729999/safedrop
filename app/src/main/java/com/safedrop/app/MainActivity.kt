package com.safedrop.app

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.text.InputType
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import java.util.concurrent.ArrayBlockingQueue

class MainActivity : Activity(), Ui {
    private lateinit var status: TextView
    private lateinit var devicesBox: LinearLayout
    private lateinit var progressView: TextView
    private lateinit var logView: TextView
    private lateinit var recvSwitch: Switch
    private lateinit var ipField: EditText

    private var receiver: Receiver? = null
    private var discoverer: Discoverer? = null
    private var mcLock: WifiManager.MulticastLock? = null
    private var target: Triple<String, Int, String?>? = null
    private val myName: String = "${Build.MANUFACTURER} ${Build.MODEL}"

    private fun label(text: String, sp: Float, bold: Boolean = false): TextView {
        val t = TextView(this)
        t.text = text
        t.textSize = sp
        if (bold) t.setTypeface(t.typeface, android.graphics.Typeface.BOLD)
        t.setPadding(0, (8 * resources.displayMetrics.density).toInt(), 0, (4 * resources.displayMetrics.density).toInt())
        return t
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this)
        root.orientation = LinearLayout.VERTICAL
        root.setPadding(pad, pad, pad, pad)
        val scroll = ScrollView(this)
        scroll.addView(root)
        scroll.setOnApplyWindowInsetsListener { v, insets ->
            val b = insets.getInsets(WindowInsets.Type.systemBars())
            v.setPadding(b.left, b.top, b.right, b.bottom)
            insets
        }
        setContentView(scroll)

        root.addView(label("SafeDrop", 26f, true))
        status = label("Device: $myName", 14f)
        status.setTextIsSelectable(true)
        root.addView(status)

        recvSwitch = Switch(this)
        recvSwitch.text = "Receive files (keep this screen open)"
        recvSwitch.isChecked = true
        recvSwitch.setOnCheckedChangeListener { _, on -> if (on) startReceiver() else stopReceiver() }
        root.addView(recvSwitch)

        root.addView(label("Send to a nearby device", 18f, true))
        devicesBox = LinearLayout(this)
        devicesBox.orientation = LinearLayout.VERTICAL
        root.addView(devicesBox)

        root.addView(label("...or enter an IP address", 14f))
        val row = LinearLayout(this)
        row.orientation = LinearLayout.HORIZONTAL
        ipField = EditText(this)
        ipField.hint = "192.168.x.x"
        ipField.inputType = InputType.TYPE_CLASS_PHONE
        row.addView(ipField, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        val go = Button(this)
        go.text = "Choose files"
        go.setOnClickListener {
            val ip = ipField.text.toString().trim()
            if (ip.isNotEmpty()) pickFor(ip, PORT, null)
        }
        row.addView(go)
        root.addView(row)

        progressView = label("", 14f)
        root.addView(progressView)
        logView = label("", 13f)
        logView.setTextIsSelectable(true)
        root.addView(logView)

        Thread {
            val code = fpCode(Identity.fingerprint())
            runOnUiThread {
                status.text = "Device: $myName\nFingerprint code: $code\nReceived files: Downloads/SafeDrop"
            }
        }.start()
        showDevices(emptyList())
    }

    override fun onStart() {
        super.onStart()
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val wm = applicationContext.getSystemService(WifiManager::class.java)
        mcLock = wm?.createMulticastLock("safedrop")?.also {
            it.setReferenceCounted(false)
            it.acquire()
        }
        val ds = Discoverer { list -> runOnUiThread { showDevices(list) } }
        discoverer = ds
        Thread { ds.start(Identity.fingerprint()) }.start()
        if (recvSwitch.isChecked) startReceiver()
    }

    override fun onStop() {
        super.onStop()
        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        stopReceiver()
        discoverer?.stop()
        discoverer = null
        mcLock?.let { if (it.isHeld) it.release() }
        mcLock = null
    }

    // ---- receiving ----
    private fun startReceiver() {
        if (receiver != null) return
        Thread {
            try {
                val r = Receiver(applicationContext, this, myName)
                r.start()
                receiver = r
                log("Receiving as \"$myName\" on port $PORT")
            } catch (e: Exception) {
                log("Cannot start receiver: ${e.message}")
            }
        }.start()
    }

    private fun stopReceiver() {
        receiver?.stop()
        receiver = null
    }

    override fun log(msg: String) {
        runOnUiThread { logView.append(msg + "\n") }
    }

    override fun askOffer(o: Offer, answer: (Boolean) -> Unit) {
        runOnUiThread {
            val sb = StringBuilder()
            sb.append("From: ${o.sender} (${o.ip})\n\n")
            o.files.take(10).forEach { sb.append("${it.name}  (${human(it.size)})\n") }
            if (o.files.size > 10) sb.append("... and ${o.files.size - 10} more\n")
            AlertDialog.Builder(this)
                .setTitle("Receive ${o.files.size} file(s)?")
                .setMessage(sb.toString())
                .setCancelable(false)
                .setPositiveButton("Accept") { _, _ -> answer(true) }
                .setNegativeButton("Reject") { _, _ -> answer(false) }
                .show()
        }
    }

    private fun askYesNo(title: String, msg: String, yes: String, no: String): Boolean {
        val q = ArrayBlockingQueue<Boolean>(1)
        runOnUiThread {
            AlertDialog.Builder(this).setTitle(title).setMessage(msg).setCancelable(false)
                .setPositiveButton(yes) { _, _ -> q.offer(true) }
                .setNegativeButton(no) { _, _ -> q.offer(false) }
                .show()
        }
        return q.take()
    }

    // ---- sending ----
    private fun showDevices(list: List<Device>) {
        devicesBox.removeAllViews()
        if (list.isEmpty()) {
            devicesBox.addView(label("Searching... (the other device must run SafeDrop in receive mode on the same Wi-Fi)", 14f))
            return
        }
        for (dv in list) {
            val b = Button(this)
            b.text = "${dv.name}  (${dv.ip})"
            b.isAllCaps = false
            b.setOnClickListener { pickFor(dv.ip, dv.port, dv.fp) }
            devicesBox.addView(b)
        }
    }

    private fun pickFor(ip: String, port: Int, announcedFp: String?) {
        target = Triple(ip, port, announcedFp)
        val i = Intent(Intent.ACTION_OPEN_DOCUMENT)
        i.addCategory(Intent.CATEGORY_OPENABLE)
        i.type = "*/*"
        i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
        startActivityForResult(i, 1)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != 1 || resultCode != RESULT_OK || data == null) return
        val t = target ?: return
        val uris = ArrayList<Uri>()
        val cd = data.clipData
        if (cd != null) {
            for (i in 0 until cd.itemCount) uris.add(cd.getItemAt(i).uri)
        } else {
            val one = data.data
            if (one != null) uris.add(one)
        }
        if (uris.isEmpty()) return
        doSend(t.first, t.second, t.third, uris)
    }

    private fun resolve(uri: Uri): Pick? {
        var name = "file"
        var size = -1L
        contentResolver.query(uri, null, null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val ni = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (ni >= 0) name = c.getString(ni) ?: "file"
                val si = c.getColumnIndex(OpenableColumns.SIZE)
                if (si >= 0 && !c.isNull(si)) size = c.getLong(si)
            }
        }
        if (size < 0) {
            size = try {
                contentResolver.openAssetFileDescriptor(uri, "r")?.use { it.length } ?: -1L
            } catch (e: Exception) {
                -1L
            }
        }
        return if (size < 0) null else Pick(uri, name, size)
    }

    private fun known(): MutableSet<String> =
        HashSet(getSharedPreferences("safedrop", MODE_PRIVATE).getStringSet("known", emptySet()) ?: emptySet())

    private fun saveKnown(fp: String) {
        val s = known()
        s.add(fp)
        getSharedPreferences("safedrop", MODE_PRIVATE).edit().putStringSet("known", s).apply()
    }

    private fun doSend(ip: String, port: Int, announced: String?, uris: List<Uri>) {
        Thread {
            try {
                val picks = uris.mapNotNull { resolve(it) }
                if (picks.isEmpty()) { log("Could not read the selected files."); return@Thread }
                log("Connecting to $ip ...")
                val fp = Sender.probe(ip, port)
                if (announced != null && announced != fp) {
                    log("Certificate does not match the device announcement - aborted.")
                    return@Thread
                }
                if (fp !in known()) {
                    val ok = askYesNo("First contact",
                        "Fingerprint code of the other device:\n\n${fpCode(fp)}\n\n" +
                                "Does it match the code shown on that device's screen?", "Match", "Cancel")
                    if (!ok) { log("Cancelled."); return@Thread }
                    saveKnown(fp)
                }
                log("Waiting for the other side to accept...")
                val err = Sender.send(ip, port, fp, myName, picks, contentResolver) { n, done, total ->
                    val pct = if (total > 0) done * 100 / total else 100
                    runOnUiThread { progressView.text = "$n: $pct%" }
                }
                runOnUiThread { progressView.text = "" }
                log(err ?: "Done: ${picks.size} file(s) sent.")
            } catch (e: Exception) {
                log("Error: ${e.message}")
            }
        }.start()
    }
}
