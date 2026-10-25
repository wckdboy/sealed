//! Upload screening: the only content-aware gate in the system.
//!
//! The server never receives plaintext. What it receives is the client's
//! `plaintext_digest` (domain-separated SHA-256) and a declared size, and it
//! holds a set of known-bad digests (NCMEC/PhotoDNA/Thorn Safer lists,
//! normalised into our digest space at ingest time).
//!
//! Honest limits, stated here because they must also be stated in the ToS and
//! the trust-and-safety runbook:
//!
//!   * This catches *known* material, exactly. It is a hash match, not a
//!     classifier. Novel material is invisible to it.
//!   * The digest is self-reported by the client. A hostile client sends a
//!     hash of a picture of a cat and uploads anything. This is inherent to
//!     zero-knowledge storage; it is why uploads are paywalled, invite-bound,
//!     and why the report/quarantine path exists.
//!   * Because we cannot inspect the file, quarantine is enforced by *freezing
//!     the account and the blob*, never by deleting evidence: legal hold first,
//!     report second, delete only on instruction (see docs/ts-runbook.md).
//!
//! Keep this module pure: no I/O, no logging of digests, no network calls. The
//! caller decides what to persist.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No match; allow the upload.
    Allow,
    /// Match against a known-bad list: quarantine, freeze account, report.
    KnownBad { list: String },
    /// The digest is syntactically fine but the upload violates a policy rule
    /// (over quota, size, unknown mime) — rejected before any blob is stored.
    Reject { reason: &'static str },
}

/// A named set of digests, e.g. `ncmec-2026-10`.
#[derive(Debug, Default, Clone)]
pub struct HashList {
    name: String,
    digests: HashSet<String>,
}

impl HashList {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            digests: HashSet::new(),
        }
    }

    /// Parse a newline-delimited list of hex digests. Blank lines and `#`
    /// comments are ignored; anything malformed is an error so a broken
    /// download cannot silently become "no matches".
    pub fn from_lines(name: impl Into<String>, text: &str) -> Result<Self, String> {
        let mut list = Self::new(name);
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let digest = line
                .split_whitespace()
                .next()
                .ok_or_else(|| format!("line {}: empty", i + 1))?;
            if !crate::ids::is_sha256_hex(&digest.to_lowercase()) {
                return Err(format!("line {}: not a sha256 hex digest", i + 1));
            }
            list.digests.insert(digest.to_lowercase());
        }
        Ok(list)
    }

    pub fn insert(&mut self, digest: &str) -> Result<(), String> {
        let d = digest.to_lowercase();
        if !crate::ids::is_sha256_hex(&d) {
            return Err("not a sha256 hex digest".into());
        }
        self.digests.insert(d);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.digests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn contains(&self, digest: &str) -> bool {
        self.digests.contains(&digest.to_lowercase())
    }
}

/// All the lists we screen against, plus the per-upload policy limits.
#[derive(Debug, Default)]
pub struct Screening {
    lists: Vec<HashList>,
    max_bytes: u64,
}

impl Screening {
    pub fn new(max_upload_bytes: u64) -> Self {
        Self {
            lists: Vec::new(),
            max_bytes: max_upload_bytes,
        }
    }

    pub fn add_list(&mut self, list: HashList) {
        self.lists.push(list);
    }

    pub fn list_names(&self) -> Vec<&str> {
        self.lists.iter().map(|l| l.name()).collect()
    }

    /// Screen one upload. `declared_size` is the plaintext size the client
    /// promised; the caller separately enforces quota.
    pub fn screen(&self, plaintext_digest: &str, declared_size: u64) -> Verdict {
        if declared_size == 0 {
            return Verdict::Reject {
                reason: "empty upload",
            };
        }
        if declared_size > self.max_bytes {
            return Verdict::Reject {
                reason: "exceeds maximum upload size",
            };
        }
        if !crate::ids::is_sha256_hex(&plaintext_digest.to_lowercase()) {
            return Verdict::Reject {
                reason: "malformed plaintext digest",
            };
        }
        for list in &self.lists {
            if list.contains(plaintext_digest) {
                return Verdict::KnownBad {
                    list: list.name().to_string(),
                };
            }
        }
        Verdict::Allow
    }
}

/// Counters for the ops dashboard; no digests, no user linkage.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScreenStats {
    pub allowed: u64,
    pub rejected: u64,
    pub quarantined: HashMap<String, u64>,
}

impl ScreenStats {
    pub fn record(&mut self, verdict: &Verdict) {
        match verdict {
            Verdict::Allow => self.allowed += 1,
            Verdict::Reject { .. } => self.rejected += 1,
            Verdict::KnownBad { list } => {
                *self.quarantined.entry(list.clone()).or_insert(0) += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::plaintext_digest;

    fn list_with(content: &[u8]) -> HashList {
        let mut list = HashList::new("test");
        list.insert(&plaintext_digest(content)).unwrap();
        list
    }

    #[test]
    fn parses_and_rejects_bad_lines() {
        let d = plaintext_digest(b"x");
        let text = format!("# header\n\n{d}\n");
        let list = HashList::from_lines("ncmec-test", &text).unwrap();
        assert_eq!(list.len(), 1);
        assert!(list.contains(&d));
        assert!(HashList::from_lines("bad", "nope\n").is_err());
    }

    #[test]
    fn screen_verdicts() {
        let s = Screening {
            lists: vec![list_with(b"bad material")],
            max_bytes: 1024,
        };
        assert_eq!(
            s.screen(&plaintext_digest(b"bad material"), 10),
            Verdict::KnownBad {
                list: "test".into()
            }
        );
        assert_eq!(s.screen(&plaintext_digest(b"cat"), 10), Verdict::Allow);
        assert!(matches!(
            s.screen(&plaintext_digest(b"cat"), 0),
            Verdict::Reject { .. }
        ));
        assert!(matches!(
            s.screen(&plaintext_digest(b"cat"), 99_999),
            Verdict::Reject { .. }
        ));
        assert!(matches!(
            s.screen("not-a-digest", 10),
            Verdict::Reject { .. }
        ));
    }

    #[test]
    fn digest_case_insensitive_on_lists() {
        let d = plaintext_digest(b"x");
        let mut list = HashList::new("t");
        list.insert(&d).unwrap();
        assert!(list.contains(&d.to_uppercase()));
    }

    #[test]
    fn stats_count() {
        let mut st = ScreenStats::default();
        st.record(&Verdict::Allow);
        st.record(&Verdict::Reject { reason: "x" });
        st.record(&Verdict::KnownBad { list: "a".into() });
        st.record(&Verdict::KnownBad { list: "a".into() });
        assert_eq!(st.allowed, 1);
        assert_eq!(st.rejected, 1);
        assert_eq!(st.quarantined["a"], 2);
    }
}
