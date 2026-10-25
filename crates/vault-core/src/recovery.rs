//! 24-word recovery phrase (BIP39 encoding, our own domain separation).
//!
//! 256 bits of entropy + 8 bits of checksum = 24 words from the BIP39 English
//! list. The phrase is generated on the client at signup, shown once, and used
//! to wrap the UKEK so a forgotten passphrase does not mean a lost vault.
//!
//! We reuse BIP39's *encoding* (wordlist + checksum) because it is the format
//! users already know how to write on paper and password managers already parse.
//! The keys are not Bitcoin keys: the wrapping key is `SHA-256("vault/
//! recovery-key/v1" || entropy)`, and the recovery blob is a `CWRP` envelope
//! around the UKEK.

use crate::error::{Error, Result};
use crate::keys::{self, Key};
use crate::sodium;
use sha2::{Digest, Sha256};

/// BIP39 English wordlist, 2048 words. Vendored so builds are reproducible and
/// offline; `data/english.txt` carries the canonical sha256 in the README.
const WORDLIST: &str = include_str!("../data/english.txt");

pub const WORD_COUNT: usize = 24;
const ENTROPY_BYTES: usize = 32;
pub const RECOVERY_WORDLIST_SHA256: &str =
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

pub fn wordlist() -> Vec<&'static str> {
    WORDLIST.lines().filter(|l| !l.is_empty()).collect()
}

fn wordlist_checked() -> Result<Vec<&'static str>> {
    let words = wordlist();
    if words.len() != 2048 {
        return Err(Error::InvalidParameter("wordlist must have 2048 words"));
    }
    Ok(words)
}

/// A recovery phrase that has been checksum-validated.
pub struct RecoveryPhrase {
    entropy: [u8; ENTROPY_BYTES],
}

impl RecoveryPhrase {
    pub fn generate() -> Result<Self> {
        sodium::init();
        Ok(Self {
            entropy: sodium::random_array(),
        })
    }

    pub fn from_entropy(entropy: [u8; ENTROPY_BYTES]) -> Self {
        Self { entropy }
    }

    pub fn entropy(&self) -> &[u8; ENTROPY_BYTES] {
        &self.entropy
    }

    /// 24 space-separated words.
    pub fn words(&self) -> Result<Vec<&'static str>> {
        let list = wordlist_checked()?;
        let checksum = Sha256::digest(self.entropy)[0];
        let mut bits = [0u8; ENTROPY_BYTES + 1];
        bits[..ENTROPY_BYTES].copy_from_slice(&self.entropy);
        bits[ENTROPY_BYTES] = checksum;

        let mut out = Vec::with_capacity(WORD_COUNT);
        let mut bit_pos = 0usize;
        for _ in 0..WORD_COUNT {
            let mut idx = 0usize;
            for _ in 0..11 {
                let byte = bits[bit_pos / 8];
                let bit = (byte >> (7 - (bit_pos % 8))) & 1;
                idx = (idx << 1) | bit as usize;
                bit_pos += 1;
            }
            out.push(list[idx]);
        }
        Ok(out)
    }

    pub fn phrase(&self) -> Result<String> {
        Ok(self.words()?.join(" "))
    }

    /// Parse a phrase, validating every word and the checksum.
    pub fn parse(phrase: &str) -> Result<Self> {
        let list = wordlist_checked()?;
        let words: Vec<&str> = phrase.split_whitespace().collect();
        if words.len() != WORD_COUNT {
            return Err(Error::BadRecoveryPhrase("expected 24 words"));
        }
        let mut bits = [0u8; ENTROPY_BYTES + 1];
        let mut bit_pos = 0usize;
        for w in &words {
            let idx = list
                .binary_search(&w.to_lowercase().as_str())
                .map_err(|_| Error::BadRecoveryPhrase("unknown word"))?;
            for i in (0..11).rev() {
                let bit = ((idx >> i) & 1) as u8;
                if bit == 1 {
                    bits[bit_pos / 8] |= 1 << (7 - (bit_pos % 8));
                }
                bit_pos += 1;
            }
        }
        let mut entropy = [0u8; ENTROPY_BYTES];
        entropy.copy_from_slice(&bits[..ENTROPY_BYTES]);
        let expected = Sha256::digest(entropy)[0];
        if expected != bits[ENTROPY_BYTES] {
            return Err(Error::BadRecoveryPhrase("checksum mismatch"));
        }
        Ok(Self { entropy })
    }

    /// The 32-byte key that wraps the UKEK. 256-bit entropy, so no KDF cost.
    pub fn wrapping_key(&self) -> Key {
        let mut h = Sha256::new();
        h.update(b"vault/recovery-key/v1");
        h.update(self.entropy);
        let out = h.finalize();
        let mut k = [0u8; 32];
        k.copy_from_slice(&out);
        Key::from_bytes(k)
    }

    /// Wrap the UKEK for emergency recovery. This blob is the only
    /// passphrase-independent copy of the key material, and it is stored
    /// server-side — safe, because unwrapping it costs 2^256 guesses.
    pub fn wrap_ukek(&self, ukek: &Key) -> Result<Vec<u8>> {
        keys::wrap_key(&self.wrapping_key(), ukek)
    }

    pub fn unwrap_ukek(phrase: &str, blob: &[u8]) -> Result<Key> {
        let p = Self::parse(phrase)?;
        keys::unwrap_key(&p.wrapping_key(), blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_canonical() {
        assert_eq!(wordlist().len(), 2048);
        assert_eq!(
            hex::encode(Sha256::digest(WORDLIST.as_bytes())),
            RECOVERY_WORDLIST_SHA256
        );
    }

    #[test]
    fn generate_parse_roundtrip() {
        for _ in 0..20 {
            let p = RecoveryPhrase::generate().unwrap();
            let phrase = p.phrase().unwrap();
            assert_eq!(phrase.split_whitespace().count(), 24);
            let parsed = RecoveryPhrase::parse(&phrase).unwrap();
            assert_eq!(parsed.entropy(), p.entropy());
            assert_eq!(parsed.wrapping_key(), p.wrapping_key());
        }
    }

    #[test]
    fn bad_checksum_rejected() {
        let p = RecoveryPhrase::generate().unwrap();
        let mut words: Vec<&str> = p.words().unwrap();
        // Swap the last word for a different one -> checksum must fail.
        let list = wordlist();
        let replacement = list.iter().find(|w| **w != words[23]).unwrap();
        words[23] = replacement;
        assert_eq!(
            RecoveryPhrase::parse(&words.join(" ")).err(),
            Some(Error::BadRecoveryPhrase("checksum mismatch"))
        );
    }

    #[test]
    fn bad_word_and_length_rejected() {
        let p = RecoveryPhrase::generate().unwrap();
        let mut words: Vec<&str> = p.words().unwrap();
        words[0] = "notaword";
        assert_eq!(
            RecoveryPhrase::parse(&words.join(" ")).err(),
            Some(Error::BadRecoveryPhrase("unknown word"))
        );
        let short = p.words().unwrap()[..23].join(" ");
        assert_eq!(
            RecoveryPhrase::parse(&short).err(),
            Some(Error::BadRecoveryPhrase("expected 24 words"))
        );
    }

    #[test]
    fn parse_is_whitespace_and_case_tolerant() {
        let p = RecoveryPhrase::generate().unwrap();
        let messy = p
            .words()
            .unwrap()
            .iter()
            .map(|w| w.to_uppercase())
            .collect::<Vec<_>>()
            .join("   \n ");
        assert_eq!(
            RecoveryPhrase::parse(&messy).unwrap().entropy(),
            p.entropy()
        );
    }

    #[test]
    fn recovery_rewraps_ukek() {
        let ukek = Key::random();
        let p = RecoveryPhrase::generate().unwrap();
        let blob = p.wrap_ukek(&ukek).unwrap();
        assert_eq!(blob.len(), keys::WRAPPED_KEY_LEN);
        let recovered = RecoveryPhrase::unwrap_ukek(&p.phrase().unwrap(), &blob).unwrap();
        assert_eq!(recovered, ukek);

        let wrong = RecoveryPhrase::generate().unwrap();
        assert!(RecoveryPhrase::unwrap_ukek(&wrong.phrase().unwrap(), &blob).is_err());
    }

    #[test]
    fn known_entropy_known_phrase() {
        // All-zero entropy is the canonical BIP39 test vector; word 1 would be
        // "abandon" x23 + "art".
        let p = RecoveryPhrase::from_entropy([0u8; 32]);
        let phrase = p.phrase().unwrap();
        assert!(phrase.starts_with("abandon abandon abandon"));
        assert_eq!(phrase.split_whitespace().last().unwrap(), "art");
        assert_eq!(
            RecoveryPhrase::parse(&phrase).unwrap().entropy(),
            &[0u8; 32]
        );
    }
}
