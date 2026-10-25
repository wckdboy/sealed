// Thin client for vault-api v1. UNVERIFIED (see android/README.md).
//
// Deliberately dumb: no retries, no caching, no offline queue. Phase 0.5 adds a
// resumable upload worker; until then a failed upload is a retry by the user.

package sh.vault.sealed

import org.json.JSONArray
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

class SealedApi(private val base: String) {
    var token: String? = null
        private set

    private fun request(method: String, path: String, body: JSONObject?): JSONObject {
        val conn = (URL(base + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 15_000
            readTimeout = 60_000
            setRequestProperty("Accept", "application/json")
            token?.let { setRequestProperty("Authorization", "Bearer $it") }
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
        }
        if (body != null) {
            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(body.toString()) }
        }
        val stream = if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream
        val text = stream?.bufferedReader()?.use { it.readText() } ?: ""
        if (conn.responseCode !in 200..299) {
            val err = runCatching { JSONObject(text) }.getOrNull()
            throw IllegalStateException("${conn.responseCode} ${err?.optString("error") ?: text}")
        }
        return if (text.isBlank()) JSONObject() else JSONObject(text)
    }

    // ---- accounts

    fun createAccount(kdfSaltHex: String, authSecretHex: String, recoveryBlobHex: String): JSONObject =
        request(
            "POST",
            "/v1/accounts",
            JSONObject()
                .put("kdf_salt", kdfSaltHex)
                .put("auth_secret", authSecretHex)
                .put("recovery_blob", recoveryBlobHex)
                .put("kdf_version", 1)
                .put("client", "sealed_android"),
        )

    fun prepareAuth(accountDigits: String): JSONObject =
        request("POST", "/v1/auth/prepare", JSONObject().put("account_number", accountDigits))

    fun login(accountDigits: String, authSecretHex: String): JSONObject {
        val resp = request(
            "POST",
            "/v1/auth",
            JSONObject().put("account_number", accountDigits).put("auth_secret", authSecretHex),
        )
        token = resp.getString("token")
        return resp
    }

    /** 18+ confirmation. Returns the portal key (hex) for public content. */
    fun gate(): String = request("POST", "/v1/gate", JSONObject().put("confirmed", true))
        .optString("portal_key")

    fun me(): JSONObject = request("GET", "/v1/me", null)

    // ---- files

    fun initFile(
        size: Long,
        plaintextDigest: String,
        mime: String,
        visibility: String,
        wrappedKeys: List<Pair<String, ByteArray>>,
    ): JSONObject {
        val keys = JSONArray()
        for ((type, blob) in wrappedKeys) {
            keys.put(JSONObject().put("wrap_type", type).put("blob", blob.toHex()))
        }
        return request(
            "POST",
            "/v1/files",
            JSONObject()
                .put("size", size)
                .put("plaintext_digest", plaintextDigest)
                .put("mime", mime)
                .put("visibility", visibility)
                .put("keys", keys),
        )
    }

    /** Upload ciphertext to the signed path returned by [initFile]. */
    fun putBlob(signedPath: String, ciphertext: ByteArray) {
        val conn = (URL(base + signedPath).openConnection() as HttpURLConnection).apply {
            requestMethod = "PUT"
            doOutput = true
            connectTimeout = 15_000
            readTimeout = 120_000
            setRequestProperty("Content-Type", "application/octet-stream")
            setFixedLengthStreamingMode(ciphertext.size)
        }
        conn.outputStream.use { it.write(ciphertext) }
        if (conn.responseCode !in 200..299) {
            throw IllegalStateException("upload failed: HTTP ${conn.responseCode}")
        }
    }

    fun complete(fileId: String): JSONObject = request("POST", "/v1/files/$fileId/complete", JSONObject())

    fun listFiles(): JSONArray = request("GET", "/v1/files", null).getJSONArray("files")

    fun fileKeys(fileId: String): Map<String, ByteArray> {
        val json = request("GET", "/v1/files/$fileId/keys", null)
        val arr = json.getJSONArray("keys")
        val out = mutableMapOf<String, ByteArray>()
        for (i in 0 until arr.length()) {
            val item = arr.getJSONObject(i)
            out[item.getString("wrap_type")] = item.getString("blob").hexToBytes()
        }
        return out
    }

    fun fileUrl(fileId: String): String = request("GET", "/v1/files/$fileId/url", null).getString("path")

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun String.hexToBytes(): ByteArray =
        chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
