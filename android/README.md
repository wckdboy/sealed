# Sealed (Android) — scaffold, not yet compiled

This directory contains the APK's source layout and the parts that must match the
server and the web client byte for byte. **It has not been compiled**: the
environment that produced the rest of this repo has no JDK, no Android SDK, and no
Gradle, so none of the Kotlin here has been through a compiler. Treat it as a
design artifact plus a starting point, not as working code.

What *is* verified today (see `docs/ROADMAP.md`):

- the wire format (secretstream framing, `CWRP` envelope, KDF split, digests,
  account numbers, recovery phrase) — pinned by `spec/crypto-vectors.json` and
  implemented twice (Rust + TypeScript) with passing cross-checks;
- the HTTP contract — `crates/vault-api/tests/api.rs` and
  `web/src/live.test.ts`.

What is *not* verified:

- every line of Kotlin in this directory;
- the Media3 `DataSource` integration (API surface drift is likely);
- anything Gradle touches.

## To build

```bash
# once, on a machine with Android tooling
sdkmanager "platforms;android-35" "build-tools;35.0.0"
./gradlew :app:assembleDebug     # from android/
```

Then, before trusting it:

1. Port `web/src/conformance.test.ts` to a Kotlin JVM test and make it pass. Until
   that test is green, the APK cannot be assumed to read files the web app wrote.
2. Run the same live flow as `web/src/live.test.ts` against a dev server.
3. Only then add the vault UI.

## Layout

```
app/src/main/java/sh/vault/sealed/
  VaultCrypto.kt        Argon2id split, CWRP envelope, COOMF1 stream, account numbers
  Api.kt                 thin HTTP client for vault-api v1
  SecretStreamSource.kt  Media3 DataSource that decrypts on the fly
  MainActivity.kt        minimal shell: signup, unlock, list, play
```

## Rules the APK must obey

- The UKEK never leaves process memory; no `SharedPreferences`, no file, no log.
- The passphrase is derived to `auth_secret` + `uke k` and the passphrase is
  dropped immediately.
- The recovery phrase is shown once and never persisted (a screenshot is the
  user's business, not ours).
- Every byte format comes from `spec/crypto-vectors.json`, never from a guess.
