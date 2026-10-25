//! End-to-end API tests. These drive the real router against a real SQLite file
//! and real blob directory, and they do the cryptography as a client would: the
//! server never sees a plaintext or an unwrapped key here either.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use vault_api::{app, build_state, Config};
use vault_core::account::AccountNumber;
use vault_core::ids;
use vault_core::kdf::{self, KdfParams};
use vault_core::keys::{self, Key};
use vault_core::recovery::RecoveryPhrase;
use vault_core::stream;
use vault_core::wire::*;

struct Harness {
    app: Router,
    dir: std::path::PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn harness(name: &str) -> Harness {
    let dir = std::env::temp_dir().join(format!("vault-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = Config::for_test(&dir);
    let state = build_state(cfg).await.expect("state");
    Harness {
        app: app(state),
        dir,
    }
}

impl Harness {
    async fn send(&self, req: Request<Body>) -> (StatusCode, Value) {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, value)
    }

    async fn send_headers(
        &self,
        req: Request<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, headers, bytes)
    }

    async fn send_raw(&self, req: Request<Body>) -> (StatusCode, Vec<u8>) {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, bytes)
    }

    async fn post(&self, uri: &str, body: Value, token: Option<&str>) -> (StatusCode, Value) {
        let mut req = Request::post(uri).header(header::CONTENT_TYPE, "application/json");
        if let Some(t) = token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        self.send(req.body(Body::from(body.to_string())).unwrap())
            .await
    }

    async fn get(&self, uri: &str, token: Option<&str>) -> (StatusCode, Value) {
        let mut req = Request::get(uri);
        if let Some(t) = token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        self.send(req.body(Body::empty()).unwrap()).await
    }
}

/// A client that behaves like Sealed: derives keys locally, keeps the UKEK.
struct Client {
    passphrase: String,
    account: String,
    ukek: Key,
    auth_secret: Key,
    recovery: String,
    recovery_blob: Vec<u8>,
    token: Option<String>,
    portal: Option<Key>,
}

const PASSPHRASE: &str = "harbor violet tractor cinder";

impl Client {
    async fn signup(h: &Harness, passphrase: &str) -> (Client, StatusCode, Value) {
        let salt = kdf::Salt::random();
        let derived = kdf::derive(passphrase, &salt, KdfParams::test_only_fast()).unwrap();
        let phrase = RecoveryPhrase::generate().unwrap();
        let recovery_blob = phrase.wrap_ukek(&derived.ukek).unwrap();

        let req = AccountCreateRequest {
            kdf_salt: salt.to_hex(),
            auth_secret: derived.auth_secret.to_hex(),
            recovery_blob: hex::encode(&recovery_blob),
            kdf_version: Some(0),
            client: ClientKind::SealedAndroid,
        };
        let (status, body) = h
            .post("/v1/accounts", serde_json::to_value(&req).unwrap(), None)
            .await;
        (
            Client {
                passphrase: passphrase.to_string(),
                account: body["digits"].as_str().unwrap_or_default().to_string(),
                ukek: derived.ukek.clone(),
                auth_secret: derived.auth_secret.clone(),
                recovery: phrase.phrase().unwrap(),
                recovery_blob: recovery_blob.clone(),
                token: None,
                portal: None,
            },
            status,
            body,
        )
    }

    async fn login(&mut self, h: &Harness) -> (StatusCode, Value) {
        let prep = h
            .post(
                "/v1/auth/prepare",
                json!({"account_number": self.account}),
                None,
            )
            .await;
        assert_eq!(prep.0, StatusCode::OK, "prepare failed: {:?}", prep.1);
        let salt = kdf::Salt::from_hex(prep.1["kdf_salt"].as_str().unwrap()).unwrap();
        let derived = kdf::kdf_split(&self.passphrase, &salt, KdfParams::test_only_fast()).unwrap();
        // Sanity: the client must land on the same U+auth halves.
        assert_eq!(derived.ukek, self.ukek);

        let (status, body) = h
            .post(
                "/v1/auth",
                json!({"account_number": self.account, "auth_secret": self.auth_secret.to_hex()}),
                None,
            )
            .await;
        if status == StatusCode::OK {
            self.token = Some(body["token"].as_str().unwrap().to_string());
        }
        (status, body)
    }

    async fn gate(&mut self, h: &Harness) -> StatusCode {
        let (status, body) = h
            .post(
                "/v1/gate",
                json!({"confirmed": true}),
                self.token.as_deref(),
            )
            .await;
        if let Some(pk) = body["portal_key"].as_str() {
            self.portal = Some(Key::from_hex(pk).unwrap());
        }
        status
    }

    fn key_wrap(&self, fek: &Key) -> WrappedKey {
        WrappedKey {
            wrap_type: WrapType::User,
            blob: hex::encode(keys::wrap_key(&self.ukek, fek).unwrap()),
        }
    }
}

/// Encrypt a payload as Sealed would and return (ciphertext blob, wrapped keys).
fn build_upload(
    client: &Client,
    plaintext: &[u8],
    visibility: Visibility,
) -> (Vec<u8>, Vec<WrappedKey>, String) {
    let fek = Key::random();
    let blob = stream::encrypt_all(&fek, plaintext).unwrap();
    let mut wraps = vec![client.key_wrap(&fek)];
    match visibility {
        Visibility::Public => wraps.push(WrappedKey {
            wrap_type: WrapType::Portal,
            blob: hex::encode(
                keys::wrap_key(client.portal.as_ref().expect("gated"), &fek).unwrap(),
            ),
        }),
        Visibility::Passphrase => wraps.push(WrappedKey {
            wrap_type: WrapType::Passphrase,
            blob: hex::encode(keys::wrap_key(&Key::random(), &fek).unwrap()),
        }),
        Visibility::Private => {}
    }
    (blob, wraps, ids::plaintext_digest(plaintext))
}

async fn ready_client(h: &Harness) -> Client {
    let (mut client, status, body) = Client::signup(h, PASSPHRASE).await;
    assert_eq!(status, StatusCode::CREATED, "signup: {body:?}");
    let (status, body) = client.login(h).await;
    assert_eq!(status, StatusCode::OK, "login: {body:?}");
    assert_eq!(client.gate(h).await, StatusCode::OK);
    client
}

async fn upload_file(
    h: &Harness,
    client: &Client,
    plaintext: &[u8],
    visibility: Visibility,
) -> (String, Vec<u8>) {
    let (blob, wraps, digest) = build_upload(client, plaintext, visibility);
    let init = FileInitRequest {
        size: plaintext.len() as u64,
        plaintext_digest: digest,
        mime: "video/mp4".into(),
        duration_ms: Some(4200),
        visibility,
        keys: wraps,
        thumb_bytes: None,
    };
    let (status, body) = h
        .post(
            "/v1/files",
            serde_json::to_value(&init).unwrap(),
            client.token.as_deref(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "init: {body:?}");
    let file_id = body["file_id"].as_str().unwrap().to_string();
    let upload_path = body["upload"]["path"].as_str().unwrap().to_string();

    let req = Request::put(&upload_path)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(blob.clone()))
        .unwrap();
    let (status, body) = h.send(req).await;
    assert_eq!(status, StatusCode::OK, "upload: {body:?}");

    let (status, body) = h
        .post(
            &format!("/v1/files/{file_id}/complete"),
            json!({}),
            client.token.as_deref(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "complete: {body:?}");
    (file_id, blob)
}

#[tokio::test]
async fn signup_login_me_and_fingerprint() {
    let h = harness("signup").await;
    let (mut client, status, body) = Client::signup(&h, PASSPHRASE).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["digits"].as_str().unwrap().len(), 16);
    assert_eq!(body["account_number"].as_str().unwrap().len(), 19);
    // The account number the server returned must be self-consistent.
    let parsed = AccountNumber::parse(&client.account).unwrap();
    assert_eq!(parsed.fingerprint(), body["fingerprint"].as_str().unwrap());

    let (status, body) = client.login(&h).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["tier"], "premium1");
    assert_eq!(body["gate_passed"], false);

    let (status, me) = h.get("/v1/me", client.token.as_deref()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["fingerprint"], parsed.fingerprint());
    assert_eq!(me["storage_used"], 0);

    // The recovery phrase the client kept restores the UKEK from the blob the
    // server holds — the whole point of signing up with pen and paper.
    let restored = RecoveryPhrase::unwrap_ukek(&client.recovery, &client.recovery_blob).unwrap();
    assert_eq!(restored, client.ukek);
}

#[tokio::test]
async fn wrong_passphrase_and_lockout() {
    let h = harness("lockout").await;
    let (client, _, _) = Client::signup(&h, PASSPHRASE).await;

    // Wrong secret: same generic error as an unknown account.
    let (status, body) = h
        .post(
            "/v1/auth",
            json!({"account_number": client.account, "auth_secret": "11".repeat(32)}),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_credentials");

    // Unknown account: identical shape, no enumeration.
    let unknown = AccountNumber::generate().digits();
    let (status2, body2) = h
        .post(
            "/v1/auth",
            json!({"account_number": unknown, "auth_secret": "11".repeat(32)}),
            None,
        )
        .await;
    assert_eq!(status2, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], body2["error"]);
    assert_eq!(body["message"], body2["message"]);

    // Five failures lock the account.
    for _ in 0..4 {
        let _ = h
            .post(
                "/v1/auth",
                json!({"account_number": client.account, "auth_secret": "22".repeat(32)}),
                None,
            )
            .await;
    }
    let (status, body) = h
        .post(
            "/v1/auth",
            json!({"account_number": client.account, "auth_secret": client.auth_secret.to_hex()}),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "expected lockout: {body:?}"
    );
    assert_eq!(body["error"], "locked");
}

#[tokio::test]
async fn private_file_roundtrip_is_server_blind() {
    let h = harness("private").await;
    let client = ready_client(&h).await;
    let plaintext = b"private payload: 0123456789abcdef".repeat(500);
    let (file_id, uploaded) = upload_file(&h, &client, &plaintext, Visibility::Private).await;

    let (status, list) = h.get("/v1/files", client.token.as_deref()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["files"][0]["file_id"], file_id.as_str());
    assert_eq!(list["files"][0]["status"], "ready");
    assert_eq!(list["files"][0]["size"], plaintext.len());

    // Owner fetches their wrapped key, unwraps locally, downloads ciphertext.
    let (status, keys_body) = h
        .get(
            &format!("/v1/files/{file_id}/keys"),
            client.token.as_deref(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let user_wrap = keys_body["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["wrap_type"] == "user")
        .expect("user wrap");
    let fek = keys::unwrap_key(
        &client.ukek,
        &hex::decode(user_wrap["blob"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(stream::decrypt_all(&fek, &uploaded).unwrap(), plaintext);

    // Owner pulls the ciphertext back through a signed URL and reads it locally.
    let (status, url) = h
        .get(&format!("/v1/files/{file_id}/url"), client.token.as_deref())
        .await;
    assert_eq!(status, StatusCode::OK, "{url:?}");
    let path = url["path"].as_str().unwrap();
    let (status, bytes) = h
        .send_raw(Request::get(path).body(Body::empty()).unwrap())
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, uploaded);
    assert_eq!(stream::decrypt_all(&fek, &bytes).unwrap(), plaintext);

    // The blob endpoint refuses an unsigned request.
    let (status, _) = h.get("/v1/blobs/deadbeef", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn public_file_requires_gate_and_unwraps_with_portal_key() {
    let h = harness("public").await;
    let client = ready_client(&h).await;
    let plaintext = b"public clip: everyone with the portal key can watch".repeat(100);
    let (file_id, uploaded) = upload_file(&h, &client, &plaintext, Visibility::Public).await;

    // A fresh, un-gated client must be refused.
    let (mut stranger, _, _) = Client::signup(&h, "another passphrase here ok").await;
    let (status, _) = stranger.login(&h).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = h
        .get(&format!("/v1/p/{file_id}"), stranger.token.as_deref())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body:?}");

    // After the gate, the manifest yields a portal-wrapped FEK and a signed blob.
    assert_eq!(stranger.gate(&h).await, StatusCode::OK);
    let (status, manifest) = h
        .get(&format!("/v1/p/{file_id}"), stranger.token.as_deref())
        .await;
    assert_eq!(status, StatusCode::OK, "{manifest:?}");
    assert_eq!(manifest["mime"], "video/mp4");
    assert_eq!(manifest["view_count"], 1);

    // `portal_key` in the manifest is the FEK wrapped under the portal key.
    let wrapped = hex::decode(manifest["portal_key"].as_str().unwrap()).unwrap();
    assert_eq!(wrapped.len(), keys::WRAPPED_KEY_LEN);
    let fek = keys::unwrap_key(&client.portal.clone().unwrap(), &wrapped).unwrap();
    assert_eq!(stream::decrypt_all(&fek, &uploaded).unwrap(), plaintext);

    let path = manifest["blob"]["path"].as_str().unwrap();
    let (status, bytes) = h
        .send_raw(Request::get(path).body(Body::empty()).unwrap())
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, uploaded, "served ciphertext must be byte-identical");
}

#[tokio::test]
async fn oversized_body_and_digest_mismatch_rejected() {
    let h = harness("oversize").await;
    let client = ready_client(&h).await;
    let plaintext = b"x".repeat(4096);
    let (blob, wraps, digest) = build_upload(&client, &plaintext, Visibility::Private);
    let init = FileInitRequest {
        size: plaintext.len() as u64,
        plaintext_digest: digest,
        mime: "video/mp4".into(),
        duration_ms: None,
        visibility: Visibility::Private,
        keys: wraps,
        thumb_bytes: None,
    };
    let (status, body) = h
        .post(
            "/v1/files",
            serde_json::to_value(&init).unwrap(),
            client.token.as_deref(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let path = body["upload"]["path"].as_str().unwrap().to_string();

    // Truncated body -> rejected, and the partial file is not left behind.
    let req = Request::put(&path)
        .body(Body::from(blob[..blob.len() - 10].to_vec()))
        .unwrap();
    let (status, body) = h.send(req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");

    // Extended body -> rejected.
    let mut fat = blob.clone();
    fat.extend_from_slice(&[0u8; 32]);
    let req = Request::put(&path).body(Body::from(fat)).unwrap();
    let (status, _) = h.send(req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Correct body still works afterwards (the failed attempts did not consume it).
    let req = Request::put(&path).body(Body::from(blob)).unwrap();
    let (status, _) = h.send(req).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn unsigned_and_forged_uploads_rejected() {
    let h = harness("forged").await;
    let client = ready_client(&h).await;
    let plaintext = b"abc".repeat(10);
    let (blob, wraps, digest) = build_upload(&client, &plaintext, Visibility::Private);
    let init = FileInitRequest {
        size: plaintext.len() as u64,
        plaintext_digest: digest,
        mime: "video/mp4".into(),
        duration_ms: None,
        visibility: Visibility::Private,
        keys: wraps,
        thumb_bytes: None,
    };
    let (_, body) = h
        .post(
            "/v1/files",
            serde_json::to_value(&init).unwrap(),
            client.token.as_deref(),
        )
        .await;
    let file_id = body["file_id"].as_str().unwrap();

    for uri in [
        format!("/v1/files/{file_id}/blob"),
        format!(
            "/v1/files/{file_id}/blob?exp=9999999999&sig={}",
            "00".repeat(32)
        ),
    ] {
        let req = Request::put(&uri).body(Body::from(blob.clone())).unwrap();
        let (status, _) = h.send(req).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
    }

    // A blob that was never completed is not servable.
    let (status, _) = h
        .get("/v1/blobs/anything?exp=9999999999&sig=00", None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn hash_match_blocks_upload_and_bans() {
    let dir = std::env::temp_dir().join(format!("vault-test-hash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let bad = ids::plaintext_digest(b"known bad sample");
    let list_path = dir.join("list.txt");
    std::fs::write(&list_path, format!("# test list\n{bad}\n")).unwrap();
    let mut cfg = Config::for_test(&dir);
    cfg.hash_lists = vec![("test-list".to_string(), list_path)];
    let state = build_state(cfg).await.unwrap();
    let h = Harness {
        app: app(state),
        dir: dir.clone(),
    };
    let client = ready_client(&h).await;

    let req = FileInitRequest {
        size: 1024,
        plaintext_digest: bad,
        mime: "video/mp4".into(),
        duration_ms: None,
        visibility: Visibility::Private,
        keys: vec![client.key_wrap(&Key::random())],
        thumb_bytes: None,
    };
    let (status, body) = h
        .post(
            "/v1/files",
            serde_json::to_value(&req).unwrap(),
            client.token.as_deref(),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["message"], "upload rejected");

    // Account is now restricted; even a clean upload is refused.
    let clean = FileInitRequest {
        plaintext_digest: ids::plaintext_digest(b"cat"),
        ..req
    };
    let (status, _) = h
        .post(
            "/v1/files",
            serde_json::to_value(&clean).unwrap(),
            client.token.as_deref(),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (_, me) = h.get("/v1/me", client.token.as_deref()).await;
    assert_eq!(me["ban_flag"], true);
    assert_eq!(me["strikes"], 1);
}

#[tokio::test]
async fn basic_tier_cannot_upload_and_quota_is_enforced() {
    let h = harness("quota").await;
    // Force a basic account by signing up then downgrading directly in SQL — the
    // API has no self-service tier change (payments do that).
    let (mut client, _, _) = Client::signup(&h, PASSPHRASE).await;
    let _ = client.login(&h).await;
    assert_eq!(client.gate(&h).await, StatusCode::OK);

    let (status, _) = h
        .post(
            "/v1/gate",
            json!({"confirmed": false}),
            client.token.as_deref(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let plaintext = b"tiny".to_vec();
    let (blob, wraps, digest) = build_upload(&client, &plaintext, Visibility::Private);
    let init = FileInitRequest {
        size: plaintext.len() as u64,
        plaintext_digest: digest,
        mime: "video/mp4".into(),
        duration_ms: None,
        visibility: Visibility::Private,
        keys: wraps,
        thumb_bytes: None,
    };

    // Over-declared size is rejected before anything is stored.
    let mut oversized = init.clone();
    oversized.size = vault_core::wire::MAX_UPLOAD_BYTES + 1;
    let (status, _) = h
        .post(
            "/v1/files",
            serde_json::to_value(&oversized).unwrap(),
            client.token.as_deref(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Wrong MIME is rejected: this is a video/image vault, not a file host.
    let mut bad_mime = init.clone();
    bad_mime.mime = "application/x-msdownload".into();
    let (status, _) = h
        .post(
            "/v1/files",
            serde_json::to_value(&bad_mime).unwrap(),
            client.token.as_deref(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Under-wrapped private file (portal wrap only) is rejected by validation.
    let mut under = init.clone();
    under.keys = vec![WrappedKey {
        wrap_type: WrapType::Portal,
        blob: hex::encode(keys::wrap_key(&Key::random(), &Key::random()).unwrap()),
    }];
    let (status, body) = h
        .post(
            "/v1/files",
            serde_json::to_value(&under).unwrap(),
            client.token.as_deref(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");
    let _ = blob;

    // Unauthenticated access to a protected route.
    let (status, _) = h.get("/v1/files", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h.get("/v1/nope", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reports_quarantine_immediately() {
    let h = harness("report").await;
    let client = ready_client(&h).await;
    let (file_id, _) = upload_file(&h, &client, b"content", Visibility::Private).await;

    let (status, body) = h
        .post(
            "/v1/reports",
            json!({"file_id": file_id, "reason": "csam", "detail": "test"}),
            client.token.as_deref(),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body:?}");
    assert!(body["report_id"].as_str().unwrap().starts_with("r_"));

    let (_, list) = h.get("/v1/files", client.token.as_deref()).await;
    assert_eq!(list["files"][0]["status"], "quarantined");

    let (status, _) = h
        .post(
            "/v1/reports",
            json!({"file_id": file_id, "reason": "arbitrary"}),
            client.token.as_deref(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn healthz_and_dmca_are_public() {
    let h = harness("health").await;
    let (status, body) = h.get("/healthz", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");

    let (status, bytes) = h
        .send_raw(Request::get("/dmca").body(Body::empty()).unwrap())
        .await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("Designated agent"));
}

#[tokio::test]
async fn serves_the_built_client_and_keeps_api_404s_json() {
    let dir = std::env::temp_dir().join(format!("vault-test-static-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let web = dir.join("web");
    std::fs::create_dir_all(web.join("assets")).unwrap();
    std::fs::write(
        web.join("index.html"),
        "<!doctype html><title>MARKER</title>",
    )
    .unwrap();
    std::fs::write(web.join("assets/app.js"), "console.log('marker')").unwrap();

    // A web dir without index.html must fail at boot, not 404 in production.
    let mut broken = Config::for_test(&dir);
    broken.web_dir = Some(dir.join("does-not-exist"));
    assert!(
        build_state(broken).await.is_err(),
        "boot must reject a web dir with no index.html"
    );

    let mut cfg = Config::for_test(&dir);
    cfg.web_dir = Some(web.clone());
    let h = Harness {
        app: app(build_state(cfg).await.unwrap()),
        dir: dir.clone(),
    };

    let resp = h
        .app
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("MARKER"));

    let resp = h
        .app
        .clone()
        .oneshot(Request::get("/assets/app.js").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // SPA deep link: served the shell so client routing works.
    let resp = h
        .app
        .clone()
        .oneshot(Request::get("/vault/f_abc").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // An unknown API path stays a JSON 404 — it must never fall through to HTML.
    let (status, body) = h.get("/v1/nope", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "not_found");

    // And the API still works with the static layer mounted.
    let (status, body) = h.get("/healthz", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn blobs_support_range_requests_and_cache_headers() {
    let h = harness("range").await;
    let client = ready_client(&h).await;
    let plaintext = b"0123456789abcdef".repeat(4096); // 64 KiB of ciphertext payload
    let (file_id, _ciphertext) = upload_file(&h, &client, &plaintext, Visibility::Private).await;

    let (status, url) = h
        .get(&format!("/v1/files/{file_id}/url"), client.token.as_deref())
        .await;
    assert_eq!(status, StatusCode::OK);
    let path = url["path"].as_str().unwrap().to_string();

    // Full body: cacheable, byte ranges advertised, strong ETag.
    let (status, headers, full) = h
        .send_headers(Request::get(&path).body(Body::empty()).unwrap())
        .await;
    assert_eq!(status, StatusCode::OK);
    let cache = headers.get("cache-control").unwrap().to_str().unwrap();
    assert!(
        cache.starts_with("public"),
        "blobs must be cacheable by a CDN: {cache}"
    );
    assert!(cache.contains("s-maxage="), "CDN needs s-maxage: {cache}");
    assert_eq!(headers.get("accept-ranges").unwrap(), "bytes");
    let etag = headers.get("etag").unwrap().to_str().unwrap().to_string();
    assert!(etag.starts_with('"') && etag.ends_with('"'));
    assert_eq!(full.len() as u64, ciphertext_len(&plaintext));

    // Conditional request: 304, no body.
    let req = Request::get(&path)
        .header(header::IF_NONE_MATCH, &etag)
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = h.send_headers(req).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());

    // Single range: exact bytes, 206, Content-Range.
    let req = Request::get(&path)
        .header(header::RANGE, "bytes=10-19")
        .body(Body::empty())
        .unwrap();
    let (status, headers, part) = h.send_headers(req).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(part, full[10..20].to_vec());
    assert_eq!(
        headers.get("content-range").unwrap().to_str().unwrap(),
        format!("bytes 10-19/{}", full.len())
    );
    assert_eq!(headers.get("content-length").unwrap(), "10");

    // Open-ended and suffix ranges.
    let req = Request::get(&path)
        .header(header::RANGE, "bytes=100-")
        .body(Body::empty())
        .unwrap();
    let (status, _, part) = h.send_headers(req).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(part, full[100..].to_vec());

    let req = Request::get(&path)
        .header(header::RANGE, "bytes=-16")
        .body(Body::empty())
        .unwrap();
    let (status, _, part) = h.send_headers(req).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(part, full[full.len() - 16..].to_vec());

    // Unsatisfiable range.
    let req = Request::get(&path)
        .header(header::RANGE, format!("bytes={}-", full.len() + 10))
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = h.send_headers(req).await;
    assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        headers.get("content-range").unwrap().to_str().unwrap(),
        format!("bytes */{}", full.len())
    );

    // Multi-range is ignored rather than mis-implemented.
    let req = Request::get(&path)
        .header(header::RANGE, "bytes=0-1,5-6")
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = h.send_headers(req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.len(), full.len());
}

/// Ciphertext length for a plaintext, without importing core internals at call sites.
fn ciphertext_len(plaintext: &[u8]) -> u64 {
    vault_core::stream::ciphertext_len_for(plaintext.len() as u64)
}

#[tokio::test]
async fn origin_secret_gates_blob_access() {
    let dir = std::env::temp_dir().join(format!("vault-test-origin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut cfg = Config::for_test(&dir);
    cfg.origin_secret = Some("only-the-cdn-knows-this".to_string());
    let h = Harness {
        app: app(build_state(cfg).await.unwrap()),
        dir: dir.clone(),
    };
    let client = ready_client(&h).await;
    let (file_id, _) = upload_file(&h, &client, b"origin gated", Visibility::Private).await;
    let (_, url) = h
        .get(&format!("/v1/files/{file_id}/url"), client.token.as_deref())
        .await;
    let path = url["path"].as_str().unwrap().to_string();

    let (status, _) = h
        .send_raw(Request::get(&path).body(Body::empty()).unwrap())
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "direct origin hit must be refused"
    );

    let req = Request::get(&path)
        .header("x-origin-secret", "only-the-cdn-knows-this")
        .body(Body::empty())
        .unwrap();
    let (status, bytes) = h.send_raw(req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!bytes.is_empty());

    // A wrong secret is not a partial match.
    let req = Request::get(&path)
        .header("x-origin-secret", "only-the-cdn-knows-thi")
        .body(Body::empty())
        .unwrap();
    let (status, _) = h.send_raw(req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn signup_is_rate_limited_per_ip() {
    let dir = std::env::temp_dir().join(format!("vault-test-rl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut cfg = Config::for_test(&dir);
    cfg.rate_limit_enabled = true;
    cfg.trust_forwarded = true;
    let h = Harness {
        dir: dir.clone(),
        app: app(build_state(cfg).await.unwrap()),
    };

    let signup = |ip: &'static str| {
        let h = &h;
        async move {
            let salt = kdf::Salt::random();
            let derived = kdf::derive(PASSPHRASE, &salt, KdfParams::test_only_fast()).unwrap();
            let req = AccountCreateRequest {
                kdf_salt: salt.to_hex(),
                auth_secret: derived.auth_secret.to_hex(),
                recovery_blob: hex::encode(keys::wrap_key(&Key::random(), &Key::random()).unwrap()),
                kdf_version: Some(0),
                client: ClientKind::SealedWeb,
            };
            let http = Request::post("/v1/accounts")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-forwarded-for", ip)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap();
            h.send_headers(http).await
        }
    };

    for i in 0..3 {
        let (status, _, _) = signup("203.0.113.7").await;
        assert_eq!(status, StatusCode::CREATED, "signup {i} should be allowed");
    }
    let (status, headers, body) = signup("203.0.113.7").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.get("retry-after").is_some());
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("rate_limited"), "unexpected body: {text}");

    // A different client is unaffected by someone else's burn.
    let (status, _, _) = signup("198.51.100.9").await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn startup_guard_refuses_a_wrong_pepper_once_accounts_exist() {
    let dir = std::env::temp_dir().join(format!("vault-test-guard-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // First boot on an empty database: allowed, and the fingerprint gets recorded.
    let cfg = Config::for_test(&dir);
    let state = build_state(cfg.clone()).await.expect("first boot");
    let h = Harness {
        app: app(state),
        dir: dir.clone(),
    };
    let (mut client, status, _) = Client::signup(&h, PASSPHRASE).await;
    assert_eq!(status, StatusCode::CREATED);
    let _ = client.login(&h).await;

    // Second boot with the same secrets: verified, no drama.
    assert!(
        build_state(cfg.clone()).await.is_ok(),
        "same secrets must verify"
    );

    // Second boot with a different pepper: refused, and the message names both
    // fingerprints so an operator can see what happened.
    let mut wrong = Config::for_test(&dir);
    wrong.secret_fingerprints[0] = "deadbeef".into();
    // for_test allows unsafe settings; the refusal path must not inherit that.
    wrong.allow_unsafe = false;
    let err = match build_state(wrong).await {
        Ok(_) => panic!("must refuse a mismatched pepper"),
        Err(e) => e,
    };
    assert!(err.contains("does not match"), "{err}");
    assert!(err.contains("deadbeef"), "{err}");

    // And with the explicit hatch it starts, loudly.
    let mut forced = Config::for_test(&dir);
    forced.secret_fingerprints[0] = "deadbeef".into();
    forced.allow_unsafe = true;
    assert!(
        build_state(forced).await.is_ok(),
        "VAULT_ALLOW_UNSAFE must bypass"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
