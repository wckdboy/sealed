//! Chunked file encryption with `crypto_secretstream_xchacha20poly1305`.
//!
//! This is the only file-body format in the system. Both clients must produce
//! byte-identical framing; `spec/crypto-vectors.json` pins a real blob that the
//! JS implementation has to decrypt.
//!
//! Framing:
//! ```text
//! COOMF1                      magic, 6 bytes
//! <header>                    24 bytes, from secretstream init_push
//! repeat:                     4-byte LE ciphertext length, then that many bytes
//! ```
//! Plaintext chunk size is [`CHUNK_PLAINTEXT`] (4 MiB), so a ciphertext chunk is
//! at most `CHUNK_PLAINTEXT + 17`. The last chunk carries `TAG_FINAL`; a reader
//! that reaches EOF without seeing `TAG_FINAL` must reject the file (truncation
//! is an attack, not a partial download).

use crate::error::{Error, Result};
use crate::keys::Key;
use crate::sodium;
use libsodium_sys as sodium_sys;

pub const MAGIC: [u8; 6] = *b"COOMF1";
pub const HEADER_BYTES: usize = 24;
pub const TAG_BYTES: usize = 17;
pub const CHUNK_PLAINTEXT: usize = 4 * 1024 * 1024;
pub const CHUNK_CIPHERTEXT_MAX: usize = CHUNK_PLAINTEXT + TAG_BYTES;
const LEN_PREFIX: usize = 4;

fn check_key_len(key: &Key) -> Result<()> {
    if key.as_bytes().len() != 32 {
        return Err(Error::InvalidParameter("secretstream key must be 32 bytes"));
    }
    Ok(())
}

/// Streaming encryptor: create once per file, feed chunks, mark the last.
pub struct StreamEncryptor {
    state: Box<sodium_sys::crypto_secretstream_xchacha20poly1305_state>,
    header: [u8; HEADER_BYTES],
}

impl StreamEncryptor {
    pub fn new(key: &Key) -> Result<Self> {
        check_key_len(key)?;
        sodium::init();
        // Boxed so the struct never moves its state; libsodium keeps pointers
        // into it only for the duration of each call, but boxing keeps layout
        // stable if a caller moves the encryptor between chunks.
        let mut state = Box::new(unsafe {
            std::mem::zeroed::<sodium_sys::crypto_secretstream_xchacha20poly1305_state>()
        });
        let mut header = [0u8; HEADER_BYTES];
        let rc = unsafe {
            sodium_sys::crypto_secretstream_xchacha20poly1305_init_push(
                state.as_mut(),
                header.as_mut_ptr(),
                key.as_bytes().as_ptr(),
            )
        };
        if rc != 0 {
            return Err(Error::AuthFailed);
        }
        Ok(Self { state, header })
    }

    /// The 24-byte stream header. Written once, right after the magic.
    pub fn header(&self) -> &[u8; HEADER_BYTES] {
        &self.header
    }

    /// Encrypt one chunk. Returns the raw ciphertext (a 4-byte length prefix is
    /// added by [`encrypt_all`] / the uploader, not here).
    pub fn push(&mut self, chunk: &[u8], final_chunk: bool) -> Result<Vec<u8>> {
        if chunk.len() > CHUNK_PLAINTEXT {
            return Err(Error::ChunkTooLarge);
        }
        let tag = if final_chunk {
            unsafe { sodium_sys::crypto_secretstream_xchacha20poly1305_tag_final() }
        } else {
            unsafe { sodium_sys::crypto_secretstream_xchacha20poly1305_tag_message() }
        };
        let mut ct = vec![0u8; chunk.len() + TAG_BYTES];
        let mut ct_len: u64 = 0;
        let rc = unsafe {
            sodium_sys::crypto_secretstream_xchacha20poly1305_push(
                self.state.as_mut(),
                ct.as_mut_ptr(),
                &mut ct_len,
                chunk.as_ptr(),
                chunk.len() as u64,
                std::ptr::null(),
                0,
                tag,
            )
        };
        if rc != 0 {
            return Err(Error::AuthFailed);
        }
        ct.truncate(ct_len as usize);
        Ok(ct)
    }
}

/// Streaming decryptor: create per file from the stored header.
pub struct StreamDecryptor {
    state: Box<sodium_sys::crypto_secretstream_xchacha20poly1305_state>,
    done: bool,
}

impl StreamDecryptor {
    pub fn new(key: &Key, header: &[u8]) -> Result<Self> {
        check_key_len(key)?;
        if header.len() != HEADER_BYTES {
            return Err(Error::MalformedBlob);
        }
        sodium::init();
        let mut state = Box::new(unsafe {
            std::mem::zeroed::<sodium_sys::crypto_secretstream_xchacha20poly1305_state>()
        });
        let rc = unsafe {
            sodium_sys::crypto_secretstream_xchacha20poly1305_init_pull(
                state.as_mut(),
                header.as_ptr(),
                key.as_bytes().as_ptr(),
            )
        };
        if rc != 0 {
            return Err(Error::AuthFailed);
        }
        Ok(Self { state, done: false })
    }

    /// Decrypt one chunk. Returns `(plaintext, was_final)`.
    pub fn pull(&mut self, ct: &[u8]) -> Result<(Vec<u8>, bool)> {
        if self.done {
            return Err(Error::TrailingData);
        }
        if ct.len() < TAG_BYTES || ct.len() > CHUNK_CIPHERTEXT_MAX {
            return Err(Error::ChunkTooLarge);
        }
        let mut plain = vec![0u8; ct.len().saturating_sub(TAG_BYTES)];
        let mut plain_len: u64 = 0;
        let mut tag: u8 = 0;
        let rc = unsafe {
            sodium_sys::crypto_secretstream_xchacha20poly1305_pull(
                self.state.as_mut(),
                plain.as_mut_ptr(),
                &mut plain_len,
                &mut tag,
                ct.as_ptr(),
                ct.len() as u64,
                std::ptr::null(),
                0,
            )
        };
        if rc != 0 {
            return Err(Error::AuthFailed);
        }
        plain.truncate(plain_len as usize);
        let is_final =
            tag == unsafe { sodium_sys::crypto_secretstream_xchacha20poly1305_tag_final() };
        if is_final {
            self.done = true;
        }
        Ok((plain, is_final))
    }
}

/// Encrypt a whole buffer into the `COOMF1` framing. Convenience for tests,
/// thumbnails and small files; large files should drive [`StreamEncryptor`].
pub fn encrypt_all(key: &Key, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut enc = StreamEncryptor::new(key)?;
    let mut out = Vec::with_capacity(plaintext.len() + 64);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(enc.header());

    // An empty file still needs one chunk, so the final tag exists.
    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        vec![&[][..]]
    } else {
        plaintext.chunks(CHUNK_PLAINTEXT).collect()
    };
    let total = chunks.len();
    for (i, chunk) in chunks.into_iter().enumerate() {
        let ct = enc.push(chunk, i + 1 == total)?;
        out.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        out.extend_from_slice(&ct);
    }
    Ok(out)
}

/// Decrypt a `COOMF1` blob, enforcing the final tag and rejecting trailing data.
pub fn decrypt_all(key: &Key, blob: &[u8]) -> Result<Vec<u8>> {
    let (header, body) = split_blob(blob)?;
    let mut dec = StreamDecryptor::new(key, header)?;
    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0usize;
    loop {
        if cursor == body.len() {
            return Err(Error::TruncatedStream);
        }
        if body.len() - cursor < LEN_PREFIX {
            return Err(Error::MalformedBlob);
        }
        let len =
            u32::from_le_bytes(body[cursor..cursor + LEN_PREFIX].try_into().unwrap()) as usize;
        cursor += LEN_PREFIX;
        if len > CHUNK_CIPHERTEXT_MAX || body.len() - cursor < len {
            return Err(Error::MalformedBlob);
        }
        let (plain, is_final) = dec.pull(&body[cursor..cursor + len])?;
        cursor += len;
        out.extend_from_slice(&plain);
        if is_final {
            if cursor != body.len() {
                return Err(Error::TrailingData);
            }
            return Ok(out);
        }
    }
}

/// Exact ciphertext length for a plaintext of `plaintext_len` bytes.
///
/// The server enforces this on upload: it stores ciphertext, so the only thing
/// it can check about a body is that the framing is the right size for the
/// declared plaintext. Both ends and the tests use this one function.
pub fn ciphertext_len_for(plaintext_len: u64) -> u64 {
    let chunks = if plaintext_len == 0 {
        1
    } else {
        plaintext_len.div_ceil(CHUNK_PLAINTEXT as u64)
    };
    MAGIC.len() as u64
        + HEADER_BYTES as u64
        + chunks * (LEN_PREFIX as u64 + TAG_BYTES as u64)
        + plaintext_len
}

/// Split a blob into `(header, framed chunks)` after validating magic/version.
pub fn split_blob(blob: &[u8]) -> Result<(&[u8], &[u8])> {
    if blob.len() < MAGIC.len() + HEADER_BYTES {
        return Err(Error::MalformedBlob);
    }
    if blob[..MAGIC.len()] != MAGIC {
        return Err(Error::MalformedBlob);
    }
    Ok(blob[MAGIC.len()..].split_at(HEADER_BYTES))
}

/// Header of a blob, for clients that stream and need the plaintext length hint.
pub fn blob_header(blob: &[u8]) -> Result<&[u8; HEADER_BYTES]> {
    let (header, _) = split_blob(blob)?;
    header.try_into().map_err(|_| Error::MalformedBlob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_len_matches_writer() {
        for pt_len in [
            0u64,
            1,
            1024,
            CHUNK_PLAINTEXT as u64 - 1,
            CHUNK_PLAINTEXT as u64,
            CHUNK_PLAINTEXT as u64 + 1,
            2 * CHUNK_PLAINTEXT as u64 + 7,
        ] {
            let pt = vec![0x5au8; pt_len as usize];
            let blob = encrypt_all(&Key::random(), &pt).unwrap();
            assert_eq!(
                blob.len() as u64,
                ciphertext_len_for(pt_len),
                "pt_len={pt_len}"
            );
        }
    }

    #[test]
    fn roundtrip_empty() {
        let k = Key::random();
        let blob = encrypt_all(&k, b"").unwrap();
        assert_eq!(&blob[..6], &MAGIC);
        assert_eq!(decrypt_all(&k, &blob).unwrap(), b"");
    }

    #[test]
    fn roundtrip_small() {
        let k = Key::random();
        let pt = b"vault: a private vault in your pocket";
        let blob = encrypt_all(&k, pt).unwrap();
        assert_eq!(decrypt_all(&k, &blob).unwrap(), pt);
    }

    #[test]
    fn roundtrip_multi_chunk() {
        let k = Key::random();
        // 2.5 chunks: exercises the final partial chunk.
        let pt: Vec<u8> = (0..(CHUNK_PLAINTEXT * 2 + 12345))
            .map(|i| (i % 251) as u8)
            .collect();
        let blob = encrypt_all(&k, &pt).unwrap();
        let chunks = pt.len().div_ceil(CHUNK_PLAINTEXT);
        assert_eq!(
            blob.len(),
            MAGIC.len() + HEADER_BYTES + chunks * LEN_PREFIX + pt.len() + chunks * TAG_BYTES
        );
        assert_eq!(decrypt_all(&k, &blob).unwrap(), pt);
    }

    #[test]
    fn wrong_key_rejected() {
        let k = Key::random();
        let blob = encrypt_all(&k, b"secret").unwrap();
        assert_eq!(decrypt_all(&Key::random(), &blob), Err(Error::AuthFailed));
    }

    #[test]
    fn truncation_rejected() {
        let k = Key::random();
        let blob = encrypt_all(&k, &vec![7u8; 100_000]).unwrap();
        let cut = &blob[..blob.len() - 40];
        assert!(matches!(
            decrypt_all(&k, cut),
            Err(Error::MalformedBlob) | Err(Error::AuthFailed) | Err(Error::TruncatedStream)
        ));
    }

    #[test]
    fn dropping_final_tag_rejected() {
        // Remove the last chunk entirely: reader must report a truncated stream
        // rather than returning a playable prefix.
        let k = Key::random();
        let pt = vec![1u8; CHUNK_PLAINTEXT + 10];
        let blob = encrypt_all(&k, &pt).unwrap();
        let header_len = MAGIC.len() + HEADER_BYTES;
        let first_len =
            u32::from_le_bytes(blob[header_len..header_len + 4].try_into().unwrap()) as usize;
        let cut = &blob[..header_len + 4 + first_len];
        assert_eq!(decrypt_all(&k, cut), Err(Error::TruncatedStream));
    }

    #[test]
    fn trailing_data_rejected() {
        let k = Key::random();
        let mut blob = encrypt_all(&k, b"abc").unwrap();
        blob.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            decrypt_all(&k, &blob),
            Err(Error::TrailingData) | Err(Error::MalformedBlob)
        ));
    }

    #[test]
    fn reordering_chunks_rejected() {
        let k = Key::random();
        let pt = vec![9u8; CHUNK_PLAINTEXT + 10];
        let blob = encrypt_all(&k, &pt).unwrap();
        let header_len = MAGIC.len() + HEADER_BYTES;
        let first_len =
            u32::from_le_bytes(blob[header_len..header_len + 4].try_into().unwrap()) as usize;
        let chunk_end = header_len + 4 + first_len;
        let mut swapped = blob[..header_len].to_vec();
        swapped.extend_from_slice(&blob[chunk_end..]);
        swapped.extend_from_slice(&blob[header_len..chunk_end]);
        assert!(decrypt_all(&k, &swapped).is_err());
    }

    #[test]
    fn garbage_is_total() {
        // The parser must never panic, whatever bytes it is handed.
        let k = Key::random();
        for len in 0..600 {
            let junk: Vec<u8> = sodium::random_bytes(len);
            let _ = decrypt_all(&k, &junk);
        }
        let mut fake = MAGIC.to_vec();
        fake.extend_from_slice(&[0u8; HEADER_BYTES]);
        fake.extend_from_slice(&[0xff; 4]);
        assert!(decrypt_all(&k, &fake).is_err());
    }
}
