// Minimal shell: signup, unlock, list, play. UNVERIFIED (see android/README.md).
//
// The UI is deliberately ugly: this exists to prove the pipeline, not to be
// designed. Real screens land after the JVM conformance test is green.

package sh.vault.sealed

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.media3.common.MediaItem
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.ui.PlayerView

class MainActivity : AppCompatActivity() {
    private val api = SealedApi(BuildConfig.API_BASE)
    private var ukek: ByteArray? = null
    private var portalKey: ByteArray? = null
    private var player: ExoPlayer? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val status = TextView(this)
        val passphrase = EditText(this).apply { hint = "passphrase (3+ words)" }
        val accountNumber = EditText(this).apply { hint = "account number (unlock only)" }
        val output = TextView(this)
        val playerView = PlayerView(this)

        val create = Button(this).apply { text = "Create account" }
        create.setOnClickListener {
            runCatching {
                val salt = VaultCrypto.randomBytes(VaultCrypto.SALT_BYTES)
                val derived = VaultCrypto.deriveKeys(passphrase.text.toString().toByteArray(), salt)
                val recoveryKey = VaultCrypto.randomBytes(32) // replace with a 24-word phrase + Store
                val recoveryBlob = VaultCrypto.wrapKey(recoveryKey, derived.ukek)
                val created = api.createAccount(salt.toHex(), derived.authSecret.toHex(), recoveryBlob.toHex())
                ukek = derived.ukek
                status.text = "write this down: ${created.optString("account_number")}"
                accountNumber.setText(created.optString("digits"))
            }.onFailure { status.text = "signup failed: ${it.message}" }
        }

        val unlock = Button(this).apply { text = "Unlock" }
        unlock.setOnClickListener {
            runCatching {
                val digits = VaultCrypto.parseAccount(accountNumber.text.toString())
                val prepared = api.prepareAuth(digits)
                val salt = prepared.getString("kdf_salt").hexToBytes()
                val derived = VaultCrypto.deriveKeys(passphrase.text.toString().toByteArray(), salt)
                api.login(digits, derived.authSecret.toHex())
                ukek = derived.ukek
                val pk = api.gate()
                portalKey = if (pk.isNotEmpty()) pk.hexToBytes() else null
                renderFiles(output, playerView)
            }.onFailure { status.text = "unlock failed: ${it.message}" }
        }

        root.addView(status)
        root.addView(accountNumber)
        root.addView(passphrase)
        root.addView(create)
        root.addView(unlock)
        root.addView(output)
        root.addView(playerView)
        setContentView(root)
    }

    private fun renderFiles(output: TextView, playerView: PlayerView) {
        val files = api.listFiles()
        output.text = buildString {
            for (i in 0 until files.length()) {
                val f = files.getJSONObject(i)
                appendLine("${f.getString("file_id")}  ${f.getString("mime")}  ${f.getLong("size")}  ${f.getString("status")}")
            }
            appendLine("tap a file id to play is not wired yet")
        }
        // Playing needs a real file picker; the pipeline itself is:
        //   keys["user"] -> unwrapKey(ukek) -> fileUrl -> SecretStreamSource.Factory
        player?.release()
        player = ExoPlayer.Builder(this).build().also { playerView.player = it }
    }

    override fun onDestroy() {
        player?.release()
        player = null
        ukek?.fill(0)
        super.onDestroy()
    }
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
