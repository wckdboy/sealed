//! Account numbers: 16 digits, one of which is a check digit.
//!
//! A Mullvad-style numeric identity with no email. Sixteen digits are 10^16 if
//! fully random; one digit is spent on a Damm check digit so typos and OCR slips
//! are self-correcting, leaving **10^15 = one quadrillion** numbers — five orders
//! of magnitude of headroom over the original 12-digit design, which matters
//! because the number is the only identifier an account has and it is exposed in
//! every support conversation.
//!
//! An account number is a *name*, not a secret. It authenticates nothing on its
//! own — every login also needs the passphrase-derived secret (see `auth`).

use crate::error::{Error, Result};
use crate::sodium;
use std::fmt;
use std::str::FromStr;

pub const DIGITS: usize = 16;
const RANDOM_DIGITS: usize = DIGITS - 1;

/// Damm quasigroup table (integer check digit, catches all single-digit errors
/// and all adjacent transpositions).
const DAMM: [[u8; 10]; 10] = [
    [0, 3, 1, 7, 5, 9, 8, 6, 4, 2],
    [7, 0, 9, 2, 1, 5, 4, 8, 6, 3],
    [4, 2, 0, 6, 8, 7, 1, 3, 5, 9],
    [1, 7, 5, 0, 9, 8, 3, 4, 2, 6],
    [6, 1, 2, 3, 0, 4, 5, 9, 7, 8],
    [3, 6, 7, 4, 2, 0, 9, 5, 8, 1],
    [5, 8, 6, 9, 7, 2, 0, 1, 3, 4],
    [8, 9, 4, 5, 3, 6, 2, 0, 1, 7],
    [9, 4, 3, 8, 6, 1, 7, 2, 0, 5],
    [2, 5, 8, 1, 4, 3, 6, 7, 9, 0],
];

/// Reject numbers whose digits are all identical. They are one in ten billion to
/// draw, they cannot be told apart at a glance, and `000000000000` is a
/// support-ticket magnet.
fn is_degenerate(digits: &[u8]) -> bool {
    digits.windows(2).all(|w| w[0] == w[1])
}

fn damm_check(digits: &[u8]) -> u8 {
    let mut interim = 0u8;
    for d in digits {
        interim = DAMM[interim as usize][(*d % 10) as usize];
    }
    interim
}

/// A validated 12-digit account number.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountNumber([u8; DIGITS]);

impl AccountNumber {
    /// Generate from the OS CSPRNG.
    pub fn generate() -> Self {
        sodium::init();
        let mut digits = [0u8; DIGITS];
        loop {
            for slot in digits.iter_mut().take(RANDOM_DIGITS) {
                *slot = (sodium::random_bytes(1)[0] % 10) as u8;
            }
            if is_degenerate(&digits[..RANDOM_DIGITS]) {
                continue;
            }
            // Damm is a quasigroup: every 11-digit prefix has exactly one check
            // digit, including 0. One draw, no rejection sampling beyond the
            // degenerate case above.
            digits[DIGITS - 1] = damm_check(&digits[..RANDOM_DIGITS]);
            return Self(digits);
        }
    }

    /// Parse something a human typed or a password manager stored. Accepts
    /// spaces, dashes, and a `vault:acct:` prefix. Exactly 16 digits, Damm-valid.
    pub fn parse(input: &str) -> Result<Self> {
        let mut digits = [0u8; DIGITS];
        let mut n = 0usize;
        let trimmed = input
            .trim()
            .strip_prefix("vault:acct:")
            .unwrap_or(input.trim());
        for ch in trimmed.chars() {
            match ch {
                '0'..='9' => {
                    if n == DIGITS {
                        return Err(Error::BadAccountNumber("too many digits"));
                    }
                    digits[n] = ch as u8 - b'0';
                    n += 1;
                }
                ' ' | '-' | '.' | '\t' | '_' => continue,
                _ => return Err(Error::BadAccountNumber("unexpected character")),
            }
        }
        if n != DIGITS {
            return Err(Error::BadAccountNumber("expected 16 digits"));
        }
        if damm_check(&digits[..RANDOM_DIGITS]) != digits[DIGITS - 1] {
            return Err(Error::BadAccountNumber("check digit mismatch"));
        }
        if is_degenerate(&digits) {
            return Err(Error::BadAccountNumber("degenerate number"));
        }
        Ok(Self(digits))
    }

    /// Bare digit string, as stored and indexed server-side.
    pub fn digits(&self) -> String {
        self.0.iter().map(|d| (b'0' + d) as char).collect()
    }

    /// Human form: groups of four, e.g. `4827 3910 5649 0182`.
    pub fn formatted(&self) -> String {
        let d = self.digits();
        d.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).expect("digits are ASCII"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// QR / paste payload.
    pub fn qr_payload(&self) -> String {
        format!("vault:acct:{}", self.digits())
    }

    /// 6 hex characters derived from the account number. Shown at signup and in
    /// the app header so a user can tell "my account loaded" from "someone
    /// else's account loaded" without exposing the number on screen shares.
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"vault/acct-fingerprint/v1");
        h.update(self.digits().as_bytes());
        let out = h.finalize();
        hex::encode_upper(&out[..3])
    }

    pub fn as_bytes(&self) -> &[u8; DIGITS] {
        &self.0
    }
}

impl fmt::Display for AccountNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.formatted())
    }
}

impl fmt::Debug for AccountNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Account numbers are not secrets, but they are identifiers: keep them
        // out of logs at debug level anyway.
        write!(f, "AccountNumber({})", self.formatted())
    }
}

impl FromStr for AccountNumber {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_numbers_validate() {
        for _ in 0..2000 {
            let a = AccountNumber::generate();
            let parsed = AccountNumber::parse(&a.digits()).unwrap();
            assert_eq!(a, parsed);
            assert_eq!(a.digits().len(), DIGITS);
            assert_eq!(a.formatted().len(), 19);
            assert_eq!(a.formatted().split(' ').count(), 4);
        }
    }

    #[test]
    fn generation_varies() {
        let set: HashSet<String> = (0..1000)
            .map(|_| AccountNumber::generate().digits())
            .collect();
        assert!(
            set.len() > 995,
            "generator looks stuck: {} unique",
            set.len()
        );
    }

    #[test]
    fn rejects_typos() {
        let a = AccountNumber::generate();
        let mut digits: Vec<u8> = a.digits().bytes().collect();
        digits[5] = if digits[5] == b'9' {
            b'0'
        } else {
            digits[5] + 1
        };
        let typo = String::from_utf8(digits).unwrap();
        assert!(AccountNumber::parse(&typo).is_err());
    }

    #[test]
    fn catches_adjacent_transposition() {
        // Damm catches all adjacent transpositions, so a swapped pair is always
        // a check-digit mismatch rather than a subtly wrong account.
        let mut checked = 0;
        for _ in 0..200 {
            let a = AccountNumber::generate();
            let d: Vec<char> = a.digits().chars().collect();
            for i in 0..RANDOM_DIGITS - 1 {
                if d[i] == d[i + 1] {
                    continue;
                }
                let mut t = d.clone();
                t.swap(i, i + 1);
                let swapped: String = t.into_iter().collect();
                assert!(
                    AccountNumber::parse(&swapped).is_err(),
                    "transposition at {i} of {} was accepted",
                    a.digits()
                );
                checked += 1;
            }
        }
        assert!(checked > 100, "only {checked} transpositions exercised");
    }

    #[test]
    fn catches_zero_nine_transposition() {
        // The pair Luhn misses. Build a valid number starting "90" and swap it.
        let mut prefix = vec![9u8, 0u8];
        prefix.extend(std::iter::repeat_n(4u8, RANDOM_DIGITS - 2));
        let check = damm_check(&prefix);
        let valid: String = prefix
            .iter()
            .chain(std::iter::once(&check))
            .map(|d| (b'0' + d) as char)
            .collect();
        let acc = AccountNumber::parse(&valid).expect("constructed number must be valid");
        let mut d: Vec<char> = acc.digits().chars().collect();
        d.swap(0, 1);
        let swapped: String = d.into_iter().collect();
        assert_eq!(
            AccountNumber::parse(&swapped).err(),
            Some(Error::BadAccountNumber("check digit mismatch"))
        );
    }

    #[test]
    fn accepts_human_formats() {
        let a = AccountNumber::generate();
        let d = a.digits();
        for form in [
            a.formatted(),
            format!("  {} ", a.formatted()),
            d.clone(),
            d.chars()
                .collect::<Vec<_>>()
                .chunks(3)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join("-"),
            a.qr_payload(),
        ] {
            assert_eq!(AccountNumber::parse(&form).unwrap(), a, "failed on {form}");
        }
    }

    #[test]
    fn rejects_junk() {
        for bad in [
            "",
            "123",
            "12345678901a",
            "1234567890123",
            "000000000000",
            "  ",
        ] {
            assert!(
                AccountNumber::parse(bad).is_err(),
                "{bad:?} should not parse"
            );
        }
        // "000000000000" passes the check digit (all-zero prefix yields a 0
        // check digit) and is refused as degenerate instead.
        assert_eq!(
            AccountNumber::parse("0000000000000000").err(),
            Some(Error::BadAccountNumber("degenerate number"))
        );
    }

    #[test]
    fn formats_as_four_groups_of_four() {
        let digits = "4827391056490182";
        let a = AccountNumber::parse(digits).expect("vector must be damm-valid");
        assert_eq!(a.formatted(), "4827 3910 5649 0182");
        assert_eq!(a.formatted().replace(' ', ""), digits);
        assert_eq!(a.qr_payload(), format!("vault:acct:{digits}"));
    }

    #[test]
    fn fingerprint_is_stable_and_short() {
        let a = AccountNumber::parse(&AccountNumber::generate().digits()).unwrap();
        assert_eq!(a.fingerprint(), a.fingerprint());
        assert_eq!(a.fingerprint().len(), 6);
    }
}
