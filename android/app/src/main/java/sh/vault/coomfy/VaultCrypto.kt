// Sealed crypto mirror of vault-core (Rust) and web/src/crypto.ts.
//
// UNVERIFIED: written against lazysodium's documented API, but never compiled
// (no Android toolchain in the environment this repo was started in). Before
// trusting it, port web/src/conformance.test.ts to a JVM test and make it pass
// against spec/crypto-vectors.json.
//
// Formats (normative, see docs/adr/0002-secretstream-framing.md):
//   file body   "COOMF1" | header(24) | (u32le len | ciphertext)+   final tag on last chunk
//   key wrap    "CWRP"  | ver(1) | nonce(24) | secretbox(key + MAC)
//   kdf         Argon2id13(passphrase, salt, ops=3, mem=64MiB) -> 64 bytes -> UKEK | auth

package sh.vault.sealed

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.PwHash
import com.goterl.lazysodium.interfaces.SecretBox
import com.goterl.lazysodium.interfaces.SecretStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

object VaultCrypto {
    const val KDF_OPS = 3L
    const val KDF_MEM_BYTES = 64L * 1024 * 1024
    const val CHUNK_PLAINTEXT = 4 * 1024 * 1024
    const val TAG_BYTES = 17
    const val LEN_PREFIX = 4
    const val KEY_BYTES = 32
    const val SALT_BYTES = 16
    const val NONCE_BYTES = 24
    const val HEADER_BYTES = 24
    const val WRAPPED_KEY_LEN = 4 + 1 + NONCE_BYTES + KEY_BYTES + 16

    private val MAGIC_WRAP = "CWRP".toByteArray(Charsets.US_ASCII)
    private val MAGIC_STREAM = "COOMF1".toByteArray(Charsets.US_ASCII)

    val sodium = LazySodiumAndroid(SodiumAndroid())

    class Derived(val ukek: ByteArray, val authSecret: ByteArray)

    /** Argon2id(passphrase, salt) -> 64 bytes -> (UKEK, auth_secret). */
    fun deriveKeys(passphrase: ByteArray, salt: ByteArray): Derived {
        require(salt.size == SALT_BYTES) { "salt must be 16 bytes" }
        val out = ByteArray(64)
        val ok = sodium.cryptoPwHash(
            out, out.size.toLong(),
            passphrase, passphrase.size.toLong(),
            salt, KDF_OPS, KDF_MEM_BYTES,
            PwHash.Alg.PWHASH_ALG_ARGON2ID13,
        )
        check(ok) { "argon2id failed" }
        val derived = Derived(out.copyOfRange(0, 32), out.copyOfRange(32, 64))
        out.fill(0)
        return derived
    }

    fun randomBytes(n: Int): ByteArray = sodium.randomBytesBuf(n)

    // ---------------------------------------------------------------- wrapping

    /** Wrap a 32-byte key: CWRP | 1 | nonce(24) | secretbox(48). */
    fun wrapKey(kek: ByteArray, target: ByteArray): ByteArray {
        require(kek.size == KEY_BYTES && target.size == KEY_BYTES)
        val nonce = randomBytes(NONCE_BYTES)
        return wrapKeyWithNonce(kek, target, nonce)
    }

    fun wrapKeyWithNonce(kek: ByteArray, target: ByteArray, nonce: ByteArray): ByteArray {
        val ct = ByteArray(target.size + SecretBox.MACBYTES)
        val ok = sodium.cryptoSecretBoxEasy(ct, target, target.size.toLong(), nonce, kek)
        check(ok) { "secretbox failed" }
        return MAGIC_WRAP + byteArrayOf(1) + nonce + ct
    }

    fun unwrapKey(kek: ByteArray, blob: ByteArray): ByteArray {
        require(blob.size == WRAPPED_KEY_LEN) { "bad wrapped key length" }
        require(blob.copyOfRange(0, 4).contentEquals(MAGIC_WRAP)) { "bad wrap magic" }
        require(blob[4].toInt() == 1) { "unsupported wrap version" }
        val nonce = blob.copyOfRange(5, 29)
        val ct = blob.copyOfRange(29, blob.size)
        val out = ByteArray(KEY_BYTES)
        val ok = sodium.cryptoSecretBoxOpenEasy(out, ct, ct.size.toLong(), nonce, kek)
        check(ok) { "secretbox open failed" }
        return out
    }

    // ------------------------------------------------------------- file stream

    /** Encrypt a whole buffer into COOMF1 framing (use the streaming form for large files). */
    fun encryptFile(key: ByteArray, plaintext: ByteArray): ByteArray {
        val state = SecretStream.XChaCha20Poly1305.State()
        val header = ByteArray(HEADER_BYTES)
        check(sodium.cryptoSecretStreamXChaCha20Poly1305InitPush(state, header, key))

        val out = java.io.ByteArrayOutputStream(plaintext.size + 64)
        out.write(MAGIC_STREAM)
        out.write(header)

        val chunks = if (plaintext.isEmpty()) 1 else (plaintext.size + CHUNK_PLAINTEXT - 1) / CHUNK_PLAINTEXT
        for (i in 0 until chunks) {
            val from = i * CHUNK_PLAINTEXT
            val to = minOf(plaintext.size, from + CHUNK_PLAINTEXT)
            val chunk = plaintext.copyOfRange(from, to)
            val isFinal = i == chunks - 1
            val ct = ByteArray(chunk.size + TAG_BYTES)
            val tag = if (isFinal) SecretStream.XChaCha20Poly1305.TAG_FINAL else SecretStream.XChaCha20Poly1305.TAG_MESSAGE
            check(sodium.cryptoSecretStreamXChaCha20Poly1305Push(state, ct, null, 0, chunk, chunk.size.toLong(), null, 0, tag))
            out.write(le32(ct.size))
            out.write(ct)
        }
        return out.toByteArray()
    }

    fun decryptFile(key: ByteArray, blob: ByteArray): ByteArray {
        require(blob.size >= 6 + HEADER_BYTES) { "blob too short" }
        require(blob.copyOfRange(0, 6).contentEquals(MAGIC_STREAM)) { "bad stream magic" }
        val header = blob.copyOfRange(6, 30)
        val state = SecretStream.XChaCha20Poly1305.State()
        check(sodium.cryptoSecretStreamXChaCha20Poly1305InitPull(state, header, key))

        val out = java.io.ByteArrayOutputStream(blob.size)
        var cursor = 30
        while (true) {
            check(cursor != blob.size) { "stream ended before the final chunk" }
            check(blob.size - cursor >= LEN_PREFIX) { "malformed chunk length" }
            val len = ByteBuffer.wrap(blob, cursor, 4).order(ByteOrder.LITTLE_ENDIAN).int
            cursor += LEN_PREFIX
            check(len in TAG_BYTES..(CHUNK_PLAINTEXT + TAG_BYTES)) { "bad chunk length" }
            check(blob.size - cursor >= len) { "truncated chunk" }
            val ct = blob.copyOfRange(cursor, cursor + len)
            cursor += len

            val plain = ByteArray(len - TAG_BYTES)
            val tag = ByteArray(1)
            check(sodium.cryptoSecretStreamXChaCha20Poly1305Pull(state, plain, null, tag, ct, ct.size.toLong(), null, 0))
            out.write(plain)
            if (tag[0] == SecretStream.XChaCha20Poly1305.TAG_FINAL) {
                check(cursor == blob.size) { "trailing data" }
                return out.toByteArray()
            }
        }
    }

    fun ciphertextLenFor(plaintextLen: Long): Long {
        val chunks = if (plaintextLen == 0L) 1L else (plaintextLen + CHUNK_PLAINTEXT - 1) / CHUNK_PLAINTEXT
        return 6L + HEADER_BYTES + chunks * (LEN_PREFIX + TAG_BYTES) + plaintextLen
    }

    // ---------------------------------------------------------------- digests

    /** Domain-separated plaintext digest as the server expects it. */
    fun plaintextDigest(plaintext: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update("vault/plaintext-sha256/v1".toByteArray(Charsets.UTF_8))
        md.update(plaintext)
        return md.digest().toHex()
    }

    // --------------------------------------------------------- account numbers

    private val DAMM = arrayOf(
        intArrayOf(0, 3, 1, 7, 5, 9, 8, 6, 4, 2),
        intArrayOf(7, 0, 9, 2, 1, 5, 4, 8, 6, 3),
        intArrayOf(4, 2, 0, 6, 8, 7, 1, 3, 5, 9),
        intArrayOf(1, 7, 5, 0, 9, 8, 3, 4, 2, 6),
        intArrayOf(6, 1, 2, 3, 0, 4, 5, 9, 7, 8),
        intArrayOf(3, 6, 7, 4, 2, 0, 9, 5, 8, 1),
        intArrayOf(5, 8, 6, 9, 7, 2, 0, 1, 3, 4),
        intArrayOf(8, 9, 4, 5, 3, 6, 2, 0, 1, 7),
        intArrayOf(9, 4, 3, 8, 6, 1, 7, 2, 0, 5),
        intArrayOf(2, 5, 8, 1, 4, 3, 6, 7, 9, 0),
    )

    fun dammCheck(digits: String): Int =
        digits.fold(0) { acc, ch -> DAMM[acc][ch - '0'] }

    /** Normalise typed input to 12 validated digits, or throw. */
    fun parseAccount(input: String): String {
        val digits = input.trim()
            .removePrefix("vault:acct:")
            .replace(Regex("[\\s\\-._]"), "")
        require(Regex("^\\d{16}$").matches(digits)) { "expected 16 digits" }
        require(dammCheck(digits.substring(0, 15)) == digits[15] - '0') { "check digit mismatch" }
        require(digits.toSet().size > 1) { "degenerate number" }
        return digits
    }

    fun formatAccount(digits: String): String =
        digits.chunked(4).joinToString(" ")

    fun accountFingerprint(digits: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update("vault/acct-fingerprint/v1".toByteArray(Charsets.UTF_8))
        md.update(digits.toByteArray(Charsets.UTF_8))
        return md.digest().copyOfRange(0, 3).toHex().uppercase()
    }

    private fun le32(v: Int): ByteArray = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
