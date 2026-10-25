//! End-to-end test for the no-JS client: real HTTP against the real API router.
//!
//! The API is started in-process on an ephemeral port (so this test needs no
//! fixtures, no Docker, no network), then the CLI library does what a user does:
//! signup → login → upload → list → fetch → decrypt. The assertion that matters is
//! that the bytes coming back are identical to the bytes that went in.

use std::io::Cursor;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};

use vault_api::{app, build_state, Config};
use vault_core::wire::Visibility;

static CONFIG_COUNTER: AtomicU16 = AtomicU16::new(0);

/// Start the API on a free port and return its base URL plus the temp dir to keep
/// alive for the test's duration.
async fn spawn_api() -> (String, PathBuf) {
    let n = CONFIG_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("vault-cli-e2e-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Reserve a port, then hand it to the server. Small race, irrelevant in tests.
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let mut cfg = Config::for_test(&dir);
    cfg.rate_limit_enabled = false;
    let state = build_state(cfg).await.expect("state");
    let base = format!("http://127.0.0.1:{port}");
    let bind = format!("127.0.0.1:{port}");
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(&bind).await.expect("bind");
        axum::serve(listener, app(state).into_make_service())
            .await
            .expect("serve");
    });

    // Wait for the listener to accept.
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    (base, dir)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signup_upload_fetch_roundtrip_without_any_javascript() {
    let (base, dir) = spawn_api().await;

    // Session file goes to a throwaway config dir, never the real one.
    let cfg_dir = dir.join("config");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &cfg_dir);

    const PASSPHRASE: &str = "harbor violet tractor cinder";
    let base_for_blocking = base.clone();

    let result = tokio::task::spawn_blocking(move || {
        let created = vault_cli::signup(&base_for_blocking, PASSPHRASE).unwrap();
        assert_eq!(created.digits.len(), 16);
        assert_eq!(created.words.len(), 24);
        assert_eq!(created.formatted.replace(' ', ""), created.digits);
        assert_eq!(
            created.formatted.split(' ').count(),
            4,
            "four groups of four"
        );

        let session = vault_cli::login(&base_for_blocking, &created.digits, PASSPHRASE).unwrap();
        assert!(
            vault_cli::Session::load().is_ok(),
            "session must be persisted"
        );

        // A payload spanning two chunks, so the framing is exercised for real.
        let src = std::env::temp_dir().join("vault-cli-e2e-input.bin");
        let payload: Vec<u8> = (0..(4 * 1024 * 1024 + 12_345))
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(&src, &payload).unwrap();

        let api = vault_cli::Api::from_session(&session);
        let up = vault_cli::upload(
            &api,
            &session,
            &src,
            Visibility::Private,
            "video/mp4".to_string(),
            PASSPHRASE,
        )
        .unwrap();
        assert_eq!(up.plaintext_len, payload.len() as u64);
        assert!(up.ciphertext_len > up.plaintext_len);

        let list = api.list().unwrap();
        assert_eq!(list.files.len(), 1, "upload must appear in the listing");
        assert_eq!(list.files[0].file_id, up.file_id);

        let mut out = Cursor::new(Vec::new());
        let n = vault_cli::fetch(&api, &session, &up.file_id, PASSPHRASE, &mut out).unwrap();
        let decrypted = out.into_inner();
        assert_eq!(n, payload.len() as u64);
        assert_eq!(
            decrypted, payload,
            "decrypted bytes must match the source file"
        );

        // Wrong passphrase must fail, not silently produce garbage.
        let mut bad = Cursor::new(Vec::new());
        let wrong = vault_cli::fetch(
            &api,
            &session,
            &up.file_id,
            "wrong passphrase entirely",
            &mut bad,
        );
        assert!(wrong.is_err(), "a wrong passphrase must be rejected");

        let _ = std::fs::remove_file(&src);
        up.file_id
    })
    .await
    .expect("blocking task");

    assert!(result.starts_with("f_"));
    // Logout clears the token file.
    vault_cli::Session::clear().unwrap();
    assert!(vault_cli::Session::load().is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_upload_uses_the_portal_key() {
    let (base, dir) = spawn_api().await;
    let cfg_dir = dir.join("config");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &cfg_dir);

    let base_for_blocking = base.clone();
    let file_id = tokio::task::spawn_blocking(move || {
        let pass = "another passphrase entirely";
        let created = vault_cli::signup(&base_for_blocking, pass).unwrap();
        let session = vault_cli::login(&base_for_blocking, &created.digits, pass).unwrap();
        let api = vault_cli::Api::from_session(&session);

        let src = std::env::temp_dir().join("vault-cli-e2e-public.bin");
        std::fs::write(&src, b"public clip payload".repeat(200)).unwrap();
        let up = vault_cli::upload(
            &api,
            &session,
            &src,
            Visibility::Public,
            "video/mp4".to_string(),
            pass,
        )
        .unwrap();
        let _ = std::fs::remove_file(&src);
        up.file_id
    })
    .await
    .expect("blocking task");

    assert!(file_id.starts_with("f_"));
    vault_cli::Session::clear().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
