//! Generate / verify `spec/crypto-vectors.json`.
//!
//! The vector file is the contract between this crate and the JS (and later
//! Kotlin) implementations. Deterministic primitives (Argon2id, secretbox with
//! a fixed nonce, HMAC, Damm, digests) are byte-pinned. secretstream cannot be
//! deterministic because the header comes from the CSPRNG, so it is pinned by a
//! committed ciphertext that other implementations must be able to *read*, plus
//! their own output that this crate must be able to read (see the JS test).
//!
//! Usage:
//!   cargo run -p vault-core --bin vecgen      # print vectors
//!   cargo run -p vault-core --bin vecgen -- --check   # verify committed file

use serde_json::{json, Value};
use std::collections::BTreeMap;
use vault_core::{account, auth, ids, kdf, keys, recovery, screen, sign, sodium, stream};

const SPEC_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/crypto-vectors.json"
);

const PASSPHRASE: &str = "harbor violet tractor cinder";
const SALT_HEX: &str = "000102030405060708090a0b0c0d0e0f";
const FEK_HEX: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
const KEK_HEX: &str = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";
const NONCE_HEX: &str = "808182838485868788898a8b8c8d8e8f9091929394959697";
const PEPPER: &[u8] = b"0123456789abcdef0123456789abcdef";
const SIGN_SECRET: &[u8] = b"fedcba9876543210fedcba9876543210";
const ENTROPY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
/// A Damm-valid account number, used in the identity and auth vectors.
const VECTOR_ACCOUNT: &str = "4827391056490182";
const STREAM_PLAINTEXT: &str =
    "vault conformance vector: the quick brown fox jumps over the lazy dog.\n";

fn deterministic() -> BTreeMap<String, Value> {
    let salt = kdf::Salt::from_hex(SALT_HEX).unwrap();
    let derived = kdf::kdf_split(PASSPHRASE, &salt, kdf::KdfParams::v1()).unwrap();
    let fek = keys::Key::from_hex(FEK_HEX).unwrap();
    let kek = keys::Key::from_hex(KEK_HEX).unwrap();
    let nonce: [u8; 24] = sodium::from_hex(NONCE_HEX).unwrap().try_into().unwrap();
    let wrapped = keys::wrap_key_with_nonce(&kek, &fek, &nonce).unwrap();
    let verifier = auth::verifier(PEPPER, &derived.auth_secret, VECTOR_ACCOUNT).unwrap();
    let signer = sign::Signer::new(SIGN_SECRET).unwrap();
    let url = signer
        .sign_download("0123456789abcdef0123456789abcdef01234567", 1_800_000_000)
        .unwrap();
    let phrase = recovery::RecoveryPhrase::from_entropy(
        sodium::from_hex(ENTROPY_HEX).unwrap().try_into().unwrap(),
    );
    // Fixed nonce so the whole deterministic block is byte-reproducible.
    let recovery_nonce: [u8; 24] =
        sodium::from_hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafa0a1a2a3a4a5a6a7")
            .unwrap()
            .try_into()
            .unwrap();
    let recovery_blob =
        keys::wrap_key_with_nonce(&phrase.wrapping_key(), &derived.ukek, &recovery_nonce).unwrap();

    let mut m = BTreeMap::new();
    m.insert(
        "kdf".into(),
        json!({
            "passphrase": PASSPHRASE,
            "salt_hex": SALT_HEX,
            "ops": kdf::KdfParams::v1().ops,
            "mem_bytes": kdf::KdfParams::v1().mem_bytes,
            "alg": "argon2id13",
            "ukek_hex": derived.ukek.to_hex(),
            "auth_secret_hex": derived.auth_secret.to_hex(),
        }),
    );
    m.insert(
        "secretbox_wrap".into(),
        json!({
            "kek_hex": KEK_HEX,
            "fek_hex": FEK_HEX,
            "nonce_hex": NONCE_HEX,
            "blob_hex": hex::encode(&wrapped),
            "layout": "CWRP|ver(1)|nonce(24)|secretbox(48)",
        }),
    );
    m.insert(
        "auth_verifier".into(),
        json!({
            "pepper_hex": hex::encode(PEPPER),
            "account_number_digits": VECTOR_ACCOUNT,
            "auth_secret_hex": derived.auth_secret.to_hex(),
            "verifier_hex": verifier,
            "note": "HMAC-SHA256(pepper, 'vault/auth-verifier/v1'||auth_secret||digits)",
        }),
    );
    let acct =
        account::AccountNumber::parse(VECTOR_ACCOUNT).expect("VECTOR_ACCOUNT must be damm-valid");
    m.insert(
        "account_number".into(),
        json!({
            "valid": [VECTOR_ACCOUNT],
            "invalid": [
                "4827391056490180",
                "482739105649018",
                "48273910564901821",
                "0000000000000000"
            ],
            "check_digit": "damm",
            "fingerprint_of_valid": acct.fingerprint(),
            "formatted": acct.formatted(),
            "qr_payload": acct.qr_payload(),
        }),
    );
    m.insert(
        "digests".into(),
        json!({
            "content": "abc",
            "plaintext_digest_hex": ids::plaintext_digest(b"abc"),
            "sha256_hex": ids::sha256_hex(b"abc"),
        }),
    );
    m.insert(
        "recovery".into(),
        json!({
            "entropy_hex": ENTROPY_HEX,
            "phrase": phrase.phrase().unwrap(),
            "wrapping_key_hex": phrase.wrapping_key().to_hex(),
            "ukek_wrapped_blob_hex": hex::encode(&recovery_blob),
        }),
    );
    m.insert(
        "signed_url".into(),
        json!({
            "secret_hex": hex::encode(SIGN_SECRET),
            "blob_ref": "0123456789abcdef0123456789abcdef01234567",
            "expires_at": 1_800_000_000u64,
            "path": url.to_path(),
            "token_hex": url.token,
        }),
    );
    let bad_digest = ids::plaintext_digest(b"known bad sample");
    let mut list = screen::HashList::from_lines("vector-list", &bad_digest).unwrap();
    list.insert(&bad_digest).unwrap();
    let mut screening = screen::Screening::new(1024);
    screening.add_list(list);
    m.insert(
        "screening".into(),
        json!({
            "list_name": "vector-list",
            "list_line_hex": bad_digest,
            "max_upload_bytes": 1024,
            "verdict_for_listed_digest": verdict_name(&screening.screen(&bad_digest, 10)),
            "verdict_for_clean_digest": verdict_name(&screening.screen(&ids::plaintext_digest(b"clean"), 10)),
        }),
    );
    m
}

fn verdict_name(v: &screen::Verdict) -> &'static str {
    match v {
        screen::Verdict::Allow => "allow",
        screen::Verdict::KnownBad { .. } => "known_bad",
        screen::Verdict::Reject { .. } => "reject",
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let key = keys::Key::random();
    let stream_blob = stream::encrypt_all(&key, STREAM_PLAINTEXT.as_bytes()).unwrap();

    let doc = json!({
        "$comment": "Generated by `cargo run -p vault-core --bin vecgen`. Do not hand-edit.",
        "version": 1,
        "deterministic": deterministic(),
        "stream": {
            "key_hex": key.to_hex(),
            "plaintext_utf8": STREAM_PLAINTEXT,
            "blob_hex": hex::encode(&stream_blob),
            "chunk_plaintext": stream::CHUNK_PLAINTEXT,
            "layout": "COOMF1|header(24)|(u32le len|ct)+ final tag on last chunk",
        },
    });

    if mode == "--check" {
        let committed =
            std::fs::read_to_string(SPEC_PATH).expect("spec/crypto-vectors.json missing");
        let committed: Value =
            serde_json::from_str(&committed).expect("committed vectors are not JSON");
        // Stream vectors are regenerated with a fresh key on every run, so the
        // check compares only the deterministic half plus the *shape* of stream.
        let mut mismatch = Vec::new();
        if committed["deterministic"] != doc["deterministic"] {
            mismatch.push("deterministic vectors drifted from spec/crypto-vectors.json");
        }
        for field in ["plaintext_utf8", "chunk_plaintext", "layout"] {
            if committed["stream"][field] != doc["stream"][field] {
                mismatch.push("stream metadata drifted");
            }
        }
        // And prove the committed stream blob still decrypts with its own key.
        let ck = keys::Key::from_hex(committed["stream"]["key_hex"].as_str().unwrap()).unwrap();
        let blob = hex::decode(committed["stream"]["blob_hex"].as_str().unwrap()).unwrap();
        match stream::decrypt_all(&ck, &blob) {
            Ok(pt) if pt == STREAM_PLAINTEXT.as_bytes() => {}
            _ => mismatch.push("committed stream blob does not decrypt to the pinned plaintext"),
        }
        if mismatch.is_empty() {
            println!("ok: spec/crypto-vectors.json matches this implementation");
        } else {
            for m in mismatch {
                eprintln!("MISMATCH: {m}");
            }
            std::process::exit(1);
        }
        return;
    }

    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
