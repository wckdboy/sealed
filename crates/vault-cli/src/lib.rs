//! `vault` — the no-JavaScript client.
//!
//! Why this exists: in the browser, decryption *is* JavaScript (or WASM) — a web
//! page with no script cannot unwrap a key. So "no JS" on the web is impossible by
//! construction, and the honest alternative is a client that speaks the same
//! protocol without a browser at all. This is that client: same files, same keys,
//! same server, zero script.
//!
//! Design commitments:
//!   * The passphrase is read from a TTY (no echo) or a file; it is never stored.
//!   * Only the *session token* is persisted (`~/.config/vault/session.json`, 0600).
//!     The UKEK is re-derived per command: Argon2id at 64 MiB costs well under a
//!     second and never touches disk.
//!   * Files are encrypted chunk-by-chunk through a temp file, so a 20 GB upload
//!     does not need 20 GB of RAM.
//!   * `vault cat <id>` writes plaintext to stdout: `vault cat f_x | mpv -` is the
//!     whole video player.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde_json::json;
use sha2::Digest;
use vault_core::kdf::{self, Derived, KdfParams, Salt};
use vault_core::keys::Key;
use vault_core::stream::{self, StreamDecryptor, StreamEncryptor};
use vault_core::wire::*;
use vault_core::{ids, recovery};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("{status} {code}: {message}")]
    Api {
        status: u16,
        code: String,
        message: String,
    },
    #[error("not logged in: run `vault login` first")]
    NoSession,
    #[error("crypto: {0}")]
    Crypto(#[from] vault_core::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Persisted session. `kdf_salt` is public (it is served by /auth/prepare); the
/// token is a bearer credential, hence 0600.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub base: String,
    pub digits: String,
    pub token: String,
    pub expires_at: i64,
    pub kdf_salt: String,
}

impl Session {
    pub fn path() -> PathBuf {
        let base = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".config")
            });
        base.join("vault").join("session.json")
    }

    pub fn load() -> Result<Self> {
        let path = Self::path();
        let text = std::fs::read_to_string(&path).map_err(|_| Error::NoSession)?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        {
            let mut f = File::create(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn clear() -> Result<()> {
        match std::fs::remove_file(Self::path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Thin blocking HTTP client. No framework, no async runtime: a CLI does not need
/// one, and fewer moving parts means a smaller audit surface.
#[derive(Clone)]
pub struct Api {
    pub base: String,
    token: Option<String>,
}

impl Api {
    pub fn new(base: impl Into<String>, token: Option<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            token,
        }
    }

    pub fn from_session(s: &Session) -> Self {
        Self::new(s.base.clone(), Some(s.token.clone()))
    }

    fn url(&self, path: &str) -> String {
        if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{}{}", self.base, path)
        }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::blocking::RequestBuilder {
        let mut rb = reqwest::blocking::Client::builder()
            .user_agent(concat!("vault-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("client")
            .request(method, self.url(path));
        if let Some(t) = &self.token {
            rb = rb.bearer_auth(t);
        }
        rb
    }

    fn call<T: DeserializeOwned>(&self, rb: reqwest::blocking::RequestBuilder) -> Result<T> {
        let resp = rb.send()?;
        let status = resp.status();
        let text = resp.text()?;
        if !status.is_success() {
            let (code, message) = serde_json::from_str::<ErrorBody>(&text)
                .map(|b| (b.error, b.message))
                .unwrap_or_else(|_| ("http".into(), text.clone()));
            return Err(Error::Api {
                status: status.as_u16(),
                code,
                message,
            });
        }
        Ok(serde_json::from_str(&text)?)
    }

    pub fn create_account(
        &self,
        salt: &Salt,
        auth_secret: &Key,
        recovery_blob: &[u8],
    ) -> Result<AccountCreateResponse> {
        self.call(
            self.request(reqwest::Method::POST, "/v1/accounts")
                .json(&json!({
                    "kdf_salt": salt.to_hex(),
                    "auth_secret": auth_secret.to_hex(),
                    "recovery_blob": hex::encode(recovery_blob),
                    "kdf_version": KdfParams::default().version(),
                    "client": "cli",
                })),
        )
    }

    pub fn prepare(&self, digits: &str) -> Result<AuthPrepareResponse> {
        self.call(
            self.request(reqwest::Method::POST, "/v1/auth/prepare")
                .json(&json!({ "account_number": digits })),
        )
    }

    pub fn login(&self, digits: &str, auth_secret: &Key) -> Result<AuthResponse> {
        self.call(
            self.request(reqwest::Method::POST, "/v1/auth")
                .json(&json!({
                    "account_number": digits,
                    "auth_secret": auth_secret.to_hex(),
                })),
        )
    }

    pub fn gate(&self) -> Result<GateResponse> {
        self.call(
            self.request(reqwest::Method::POST, "/v1/gate")
                .json(&json!({ "confirmed": true })),
        )
    }

    pub fn me(&self) -> Result<MeResponse> {
        self.call(self.request(reqwest::Method::GET, "/v1/me"))
    }

    pub fn list(&self) -> Result<FileListResponse> {
        self.call(self.request(reqwest::Method::GET, "/v1/files"))
    }

    pub fn keys(&self, file_id: &str) -> Result<KeyResponse> {
        self.call(self.request(reqwest::Method::GET, &format!("/v1/files/{file_id}/keys")))
    }

    pub fn init(&self, req: &FileInitRequest) -> Result<FileInitResponse> {
        self.call(self.request(reqwest::Method::POST, "/v1/files").json(req))
    }

    pub fn upload_blob(&self, signed_path: &str, file: File, len: u64) -> Result<()> {
        let resp = self
            .request(reqwest::Method::PUT, signed_path)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(reqwest::blocking::Body::sized(file, len))
            .send()?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().unwrap_or_default();
            return Err(Error::Api {
                status,
                code: "upload_failed".into(),
                message: text,
            });
        }
        Ok(())
    }

    pub fn complete(&self, file_id: &str) -> Result<()> {
        let _: Ack = self.call(
            self.request(
                reqwest::Method::POST,
                &format!("/v1/files/{file_id}/complete"),
            )
            .json(&json!({})),
        )?;
        Ok(())
    }

    pub fn owner_url(&self, file_id: &str) -> Result<SignedUpload> {
        self.call(self.request(reqwest::Method::GET, &format!("/v1/files/{file_id}/url")))
    }

    pub fn download(&self, signed_path: &str, out: &mut dyn Write) -> Result<u64> {
        let mut resp = self.request(reqwest::Method::GET, signed_path).send()?;
        if !resp.status().is_success() {
            return Err(Error::Api {
                status: resp.status().as_u16(),
                code: "download_failed".into(),
                message: resp.text().unwrap_or_default(),
            });
        }
        Ok(std::io::copy(&mut resp, out)?)
    }
}

/// Derive the two halves from a passphrase. One Argon2id call, per command.
pub fn derive(passphrase: &str, salt_hex: &str) -> Result<Derived> {
    let salt = Salt::from_hex(salt_hex).map_err(|e| Error::Protocol(e.to_string()))?;
    Ok(kdf::derive(passphrase, &salt, KdfParams::default())?)
}

/// Create an account and return everything the user must write down.
pub struct Created {
    pub digits: String,
    pub formatted: String,
    pub fingerprint: String,
    pub words: [String; 24],
}

pub fn signup(base: &str, passphrase: &str) -> Result<Created> {
    let salt = Salt::random();
    let derived = kdf::derive(passphrase, &salt, KdfParams::default())?;
    let phrase = recovery::RecoveryPhrase::generate()?;
    let recovery_blob = phrase.wrap_ukek(&derived.ukek)?;
    let api = Api::new(base, None);
    let resp = api.create_account(&salt, &derived.auth_secret, &recovery_blob)?;

    let words: Vec<String> = phrase.words()?.into_iter().map(|w| w.to_string()).collect();
    let array: [String; 24] = words
        .try_into()
        .map_err(|_| Error::Protocol("recovery phrase must be 24 words".into()))?;
    Ok(Created {
        digits: resp.digits,
        formatted: resp.account_number,
        fingerprint: resp.fingerprint,
        words: array,
    })
}

/// Log in and persist the session token (never the passphrase, never the UKEK).
pub fn login(base: &str, digits: &str, passphrase: &str) -> Result<Session> {
    let api = Api::new(base, None);
    let prepared = api.prepare(digits)?;
    let derived = derive(passphrase, &prepared.kdf_salt)?;
    let auth = api.login(digits, &derived.auth_secret)?;
    let session = Session {
        base: base.trim_end_matches('/').to_string(),
        digits: digits.to_string(),
        token: auth.token,
        expires_at: auth.expires_at,
        kdf_salt: prepared.kdf_salt,
    };
    session.save()?;
    Ok(session)
}

/// Encrypt a file to `tmp` with secretstream framing, returning (plaintext digest,
/// wrapped keys need the FEK, ciphertext length).
pub struct PreparedUpload {
    pub fek: Key,
    pub digest: String,
    pub plaintext_len: u64,
    pub ciphertext_len: u64,
    pub tmp: PathBuf,
}

pub fn prepare_upload(src: &Path, tmp_dir: &Path) -> Result<PreparedUpload> {
    let fek = Key::random();
    let mut enc = StreamEncryptor::new(&fek)?;
    let tmp = tmp_dir.join(format!("{}.coomf1", ids::new_blob_ref()));
    let mut out = BufWriter::new(File::create(&tmp)?);
    out.write_all(&stream::MAGIC)?;
    out.write_all(enc.header())?;

    let mut reader = BufReader::new(File::open(src)?);
    let mut buf = vec![0u8; stream::CHUNK_PLAINTEXT];
    let mut plaintext_len: u64 = 0;
    // Hash while encrypting: one pass, no 20 GB buffer.
    let mut digest = ids::plaintext_digest_init();

    loop {
        let n = read_fill(&mut reader, &mut buf)?;
        if n == 0 {
            // Empty file still needs one chunk carrying the final tag.
            let ct = enc.push(&[], true)?;
            write_chunk(&mut out, &ct)?;
            break;
        }
        plaintext_len += n as u64;
        digest.update(&buf[..n]);
        let more = reader.fill_buf().map(|b| !b.is_empty()).unwrap_or(false);
        let ct = enc.push(&buf[..n], !more)?;
        write_chunk(&mut out, &ct)?;
        if !more {
            break;
        }
    }
    out.flush()?;
    drop(out);

    let ciphertext_len = std::fs::metadata(&tmp)?.len();
    let digest = ids::plaintext_digest_finalize(digest);
    Ok(PreparedUpload {
        fek,
        digest,
        plaintext_len,
        ciphertext_len,
        tmp,
    })
}

fn read_fill(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

fn write_chunk(out: &mut impl Write, ct: &[u8]) -> Result<()> {
    out.write_all(&(ct.len() as u32).to_le_bytes())?;
    out.write_all(ct)?;
    Ok(())
}

/// Decrypt `ciphertext` into `out`, streaming chunk by chunk.
pub fn decrypt_to(fek: &Key, ciphertext: &Path, out: &mut dyn Write) -> Result<u64> {
    let mut f = BufReader::new(File::open(ciphertext)?);
    let mut magic = [0u8; 6];
    f.read_exact(&mut magic)?;
    if magic != stream::MAGIC {
        return Err(Error::Protocol("not a vault blob".into()));
    }
    let mut header = [0u8; stream::HEADER_BYTES];
    f.read_exact(&mut header)?;
    let mut dec = StreamDecryptor::new(fek, &header)?;

    let mut written = 0u64;
    loop {
        let mut len = [0u8; 4];
        match f.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(Error::Protocol("truncated blob (no final chunk)".into()))
            }
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_le_bytes(len) as usize;
        if len > stream::CHUNK_CIPHERTEXT_MAX {
            return Err(Error::Protocol(
                "chunk larger than the format allows".into(),
            ));
        }
        let mut ct = vec![0u8; len];
        f.read_exact(&mut ct)?;
        let (plain, is_final) = dec.pull(&ct)?;
        out.write_all(&plain)?;
        written += plain.len() as u64;
        if is_final {
            return Ok(written);
        }
    }
}

/// What an upload produced.
pub struct Uploaded {
    pub file_id: String,
    pub plaintext_len: u64,
    pub ciphertext_len: u64,
}

/// Encrypt `src` with a fresh FEK and upload it. Public files additionally get a
/// portal-key wrap, which requires an 18+ gated session.
pub fn upload(
    api: &Api,
    session: &Session,
    src: &Path,
    visibility: Visibility,
    mime: String,
    passphrase: &str,
) -> Result<Uploaded> {
    let derived = derive(passphrase, &session.kdf_salt)?;
    let prepared = prepare_upload(src, &std::env::temp_dir())?;

    let mut keys = vec![WrappedKey {
        wrap_type: WrapType::User,
        blob: hex::encode(vault_core::keys::wrap_key(&derived.ukek, &prepared.fek)?),
    }];
    if matches!(visibility, Visibility::Public) {
        let portal = api.gate()?;
        let hex_key = portal
            .portal_key
            .ok_or_else(|| Error::Protocol("server did not release the portal key".into()))?;
        let pkek = Key::from_hex(&hex_key).map_err(|e| Error::Protocol(e.to_string()))?;
        keys.push(WrappedKey {
            wrap_type: WrapType::Portal,
            blob: hex::encode(vault_core::keys::wrap_key(&pkek, &prepared.fek)?),
        });
    }
    if matches!(visibility, Visibility::Passphrase) {
        // Not implemented yet: a passphrase share needs a share record and salt.
        // Refuse rather than silently upload as private.
        return Err(Error::Protocol(
            "passphrase shares are not implemented yet; use private or public".into(),
        ));
    }

    let init = FileInitRequest {
        size: prepared.plaintext_len,
        plaintext_digest: prepared.digest,
        mime,
        duration_ms: None,
        visibility,
        keys,
        thumb_bytes: None,
    };
    let started = api.init(&init)?;
    let file = File::open(&prepared.tmp)?;
    let uploaded = api.upload_blob(&started.upload.path, file, prepared.ciphertext_len);
    let _ = std::fs::remove_file(&prepared.tmp);
    uploaded?;
    api.complete(&started.file_id)?;

    Ok(Uploaded {
        file_id: started.file_id,
        plaintext_len: prepared.plaintext_len,
        ciphertext_len: prepared.ciphertext_len,
    })
}

/// Fetch, decrypt and write to `out`. Returns plaintext bytes written.
pub fn fetch(
    api: &Api,
    session: &Session,
    file_id: &str,
    passphrase: &str,
    out: &mut dyn Write,
) -> Result<u64> {
    let derived = derive(passphrase, &session.kdf_salt)?;
    let keys = api.keys(file_id)?;
    let user_wrap = keys
        .keys
        .iter()
        .find(|k| k.wrap_type == WrapType::User)
        .ok_or_else(|| Error::Protocol("no user-wrapped key on that file".into()))?;
    let blob = hex::decode(&user_wrap.blob).map_err(|e| Error::Protocol(e.to_string()))?;
    let fek = vault_core::keys::unwrap_key(&derived.ukek, &blob)?;

    let url = api.owner_url(file_id)?;
    let tmp = std::env::temp_dir().join(format!("{}.coomf1", ids::new_blob_ref()));
    {
        let mut f = File::create(&tmp)?;
        api.download(&url.path, &mut f)?;
    }
    let n = decrypt_to(&fek, &tmp, out);
    let _ = std::fs::remove_file(&tmp);
    n
}

/// Guess a MIME type from the extension. The server only accepts video/* and
/// image/*, so an unknown extension falls back to video/mp4 rather than erroring.
pub fn guess_mime(path: &Path) -> String {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        _ => "video/mp4",
    }
    .to_string()
}

/// Seek read of a byte range (used by `vault cat --start/--end` for spot checks).
pub fn read_range(path: &Path, start: u64, len: u64) -> Result<Vec<u8>> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(start))?;
    let mut buf = vec![0u8; len as usize];
    let mut filled = 0;
    while filled < buf.len() {
        let n = f.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(buf)
}
