package com.safedrop.app

import android.content.Context
import android.net.ConnectivityManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.net.Inet4Address
import java.net.InetAddress
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.security.auth.x500.X500Principal

const val PORT = 53318
private val RESERVED = setOf("CON", "PRN", "AUX", "NUL") +
        (1..9).map { "COM$it" } + (1..9).map { "LPT$it" }

fun sha256Hex(b: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

/** Short code for people to compare by eye (same format as the PC side). */
fun fpCode(fp: String): String = (0 until 5).joinToString("-") { fp.substring(it * 4, it * 4 + 4) }.uppercase()

fun safeName(n: String): String {
    var s = n.replace('\\', '/').substringAfterLast('/')
    s = s.replace(Regex("[\\x00-\\x1f<>:\"|?*]"), "_").trim(' ', '.')
    if (s.isEmpty()) s = "file"
    if (s.substringBefore('.').uppercase() in RESERVED) s = "_$s"
    return s.take(200)
}

fun human(n: Long): String {
    var v = n.toDouble()
    val u = arrayOf("B", "KB", "MB", "GB")
    var i = 0
    while (v >= 1024 && i < 3) { v /= 1024; i++ }
    return if (i == 0) "$n B" else String.format("%.1f %s", v, u[i])
}

/** Addresses to send discovery broadcasts to: global + the real subnet broadcast. */
fun broadcastAddresses(ctx: Context): List<InetAddress> {
    val l = ArrayList<InetAddress>()
    try { l.add(InetAddress.getByName("255.255.255.255")) } catch (_: Exception) {}
    try {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        val lp = cm.getLinkProperties(cm.activeNetwork)
        if (lp != null) {
            for (la in lp.linkAddresses) {
                val a = la.address
                if (a is Inet4Address) {
                    val p = la.prefixLength
                    val mask = if (p == 0) 0 else (-1 shl (32 - p))
                    var ip = 0
                    for (x in a.address) ip = (ip shl 8) or (x.toInt() and 0xff)
                    val b = ip or mask.inv()
                    l.add(InetAddress.getByAddress(byteArrayOf(
                        (b ushr 24).toByte(), (b ushr 16).toByte(), (b ushr 8).toByte(), b.toByte())))
                }
            }
        }
    } catch (_: Exception) {}
    return l
}

/**
 * This device's identity: an EC P-256 key pair created inside the Android
 * Keystore (the private key can never be exported) with a self-signed cert.
 */
object Identity {
    private const val ALIAS = "safedrop_identity"

    private fun ks(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    @Synchronized
    fun ensure() {
        if (ks().containsAlias(ALIAS)) return
        val now = System.currentTimeMillis()
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512, KeyProperties.DIGEST_NONE)
            .setCertificateSubject(X500Principal("CN=safedrop"))
            .setCertificateNotBefore(Date(now - 86400000L))
            .setCertificateNotAfter(Date(now + 3650L * 86400000L))
            .build()
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        kpg.initialize(spec)
        kpg.generateKeyPair()
    }

    fun fingerprint(): String {
        ensure()
        return sha256Hex((ks().getCertificate(ALIAS) as X509Certificate).encoded)
    }

    fun sslContext(): SSLContext {
        ensure()
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks(), null)
        val c = SSLContext.getInstance("TLS")
        c.init(kmf.keyManagers, null, null)
        return c
    }
}
