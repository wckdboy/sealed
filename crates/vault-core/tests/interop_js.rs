//! Cross-implementation check, JS -> Rust direction.
//!
//! `web/src/conformance.test.ts` writes a secretstream blob produced by
//! libsodium.js. This test decrypts it with the Rust core, so the wire format is
//! proven readable in *both* directions rather than just one.
//!
//! The file only exists after `npm test` has run in `web/`. In CI the order is
//! fixed and `VAULT_REQUIRE_JS_INTEROP=1` makes a missing file a failure.

use vault_core::keys::Key;
use vault_core::stream;

#[test]
fn js_produced_blob_decrypts_in_rust() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../web/.conformance/js-stream-blob.json");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => {
            let msg = format!(
                "no JS interop fixture at {}; run `npm test` in web/ first",
                path.display()
            );
            assert!(std::env::var("VAULT_REQUIRE_JS_INTEROP").is_err(), "{msg}");
            eprintln!("skipping: {msg}");
            return;
        }
    };

    let v: serde_json::Value = serde_json::from_str(&text).expect("fixture is JSON");
    let key = Key::from_hex(v["key_hex"].as_str().unwrap()).unwrap();
    let blob = hex::decode(v["blob_hex"].as_str().unwrap()).unwrap();
    let expected = v["plaintext_utf8"].as_str().unwrap().as_bytes().to_vec();

    let plain = stream::decrypt_all(&key, &blob).expect("JS-produced blob must decrypt in Rust");
    assert_eq!(plain, expected);
    assert_eq!(
        blob.len() as u64,
        stream::ciphertext_len_for(plain.len() as u64)
    );
}
