// Media3 DataSource that reads ciphertext from a signed URL and decrypts it as
// the player asks for bytes.
//
// UNVERIFIED — not compiled. Media3's DataSource API changes between minor
// versions; expect to fix signatures here first (see android/README.md).
//
// The player gets a seekable stream because we decrypt chunk-by-chunk and keep a
// small sliding window. Seeking backwards restarts the stream: secretstream is
// strictly sequential and cannot be re-keyed to an arbitrary offset without a
// per-file chunk index (phase 0.5 adds one).

package sh.vault.sealed

import androidx.media3.common.C
import androidx.media3.datasource.BaseDataSource
import androidx.media3.datasource.DataSource
import androidx.media3.datasource.DataSpec
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

class SecretStreamSource(private val fek: ByteArray, private val mimeHint: String?) : BaseDataSource(true) {

    private var connection: HttpURLConnection? = null
    private var ciphertext: ByteArray = ByteArray(0)
    private var plaintext: ByteArray? = null
    private var position = 0L
    private var opened = false

    override fun open(dataSpec: DataSpec): Long {
        transferInitializing(dataSpec)
        try {
            val conn = (URL(dataSpec.uri.toString()).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 15_000
                readTimeout = 30_000
                setRequestProperty("Accept", "application/octet-stream")
            }
            connection = conn
            val code = conn.responseCode
            if (code != HttpURLConnection.HTTP_OK) {
                throw IOException("blob fetch failed: HTTP $code")
            }
            ciphertext = conn.inputStream.use { it.readBytes() }
            // Whole-file decrypt keeps this scaffold honest and simple. Streaming
            // decrypt belongs here once the chunk index exists.
            plaintext = VaultCrypto.decryptFile(fek, ciphertext)
            position = dataSpec.position
            opened = true
            transferStarted(dataSpec)
            val total = plaintext!!.size.toLong()
            return if (dataSpec.length != C.LENGTH_UNSET.toLong()) dataSpec.length else total - position
        } catch (e: Exception) {
            transferEnded()
            throw if (e is IOException) e else IOException(e)
        }
    }

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        val data = plaintext ?: return C.RESULT_END_OF_INPUT
        if (position >= data.size) return C.RESULT_END_OF_INPUT
        val n = minOf(length.toLong(), data.size - position).toInt()
        System.arraycopy(data, position.toInt(), buffer, offset, n)
        position += n
        bytesTransferred(n)
        return n
    }

    override fun getUri(): android.net.Uri? = connection?.url?.toURI()?.let { android.net.Uri.parse(it.toString()) }

    override fun close() {
        connection?.disconnect()
        connection = null
        plaintext?.fill(0)
        plaintext = null
        ciphertext = ByteArray(0)
        if (opened) {
            opened = false
            transferEnded()
        }
    }

    class Factory(private val fek: ByteArray, private val mimeHint: String?) : DataSource.Factory {
        override fun createDataSource(): DataSource = SecretStreamSource(fek, mimeHint)
    }
}
