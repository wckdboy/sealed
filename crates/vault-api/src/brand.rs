//! Product branding, loaded from `brand/brand.json` at compile time.
//!
//! The point of this module is that a rebrand is a data change, not a fork: the
//! public mirror of this project ships the same source with a different
//! `brand.json`. Nothing in the crypto, the wire formats, the database, or the
//! API may depend on the brand — the account-number QR prefix, the digest domain
//! separators and the env prefix are all brand-neutral (`vault/*`) precisely so
//! that renaming the product cannot invalidate existing accounts or files.
//!
//! Override at runtime with `VAULT_BRAND_NAME` (rarely useful; the UI copy comes
//! from the web bundle, so a partial override looks broken more often than not).

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

const RAW: &str = include_str!("../../../brand/brand.json");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Brand {
    /// Product name, e.g. "Sealed".
    pub name: String,
    /// Client/APK name, e.g. "Sealed".
    pub app: String,
    pub tagline: String,
    /// CSS colour for the web client.
    pub accent: String,
    pub homepage: String,
    /// Fallback DMCA contact when `VAULT_DMCA_CONTACT` is unset.
    pub dmca_default: String,
    /// Word used in the UI for the numeric identity.
    pub account_label: String,
}

static BRAND: OnceLock<Brand> = OnceLock::new();

pub fn brand() -> &'static Brand {
    BRAND.get_or_init(|| {
        let mut brand: Brand = serde_json::from_str(RAW).expect("brand/brand.json is not valid");
        if let Ok(name) = std::env::var("VAULT_BRAND_NAME") {
            brand.name = name;
        }
        brand
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brand_file_parses_and_is_presentable() {
        let b = brand();
        assert!(!b.name.is_empty() && !b.app.is_empty());
        assert!(
            b.accent.starts_with('#') && b.accent.len() == 7,
            "accent must be #rrggbb"
        );
        assert!(
            b.dmca_default.contains('@'),
            "dmca_default must be an address"
        );
        // Nothing brand-ish is allowed in the wire formats; see the module docs.
        assert!(
            !b.name.contains('/'),
            "brand name must not look like a path or namespace"
        );
    }
}
