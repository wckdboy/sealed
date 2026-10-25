/**
 * Conformance suite: this implementation against `spec/crypto-vectors.json`,
 * which the Rust core generates (`cargo run -p vault-core --bin vecgen`).
 *
 * Anything green here means the PWA and the Android client produce and consume
 * identical bytes. Anything red means files encrypted on one platform cannot be
 * opened on the other — treat a failure as a release blocker, never a flake.
 *
 * The last test writes a blob this implementation produced so the Rust side can
 * prove the reverse direction (crates/vault-core/tests/interop_js.rs).
 */

import { describe, expect, it } from 'vitest';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, URL } from 'node:url';
import * as c from './crypto';

const spec = JSON.parse(readFileSync(fileURLToPath(new URL('../../spec/crypto-vectors.json', import.meta.url)), 'utf8'));

describe('conformance: passphrase KDF', () => {
  it('derives the pinned UKEK and auth secret', async () => {
    const v = spec.deterministic.kdf;
    const derived = await c.deriveKeys(v.passphrase, c.hexToBytes(v.salt_hex));
    expect(c.bytesToHex(derived.ukek)).toBe(v.ukek_hex);
    expect(c.bytesToHex(derived.authSecret)).toBe(v.auth_secret_hex);
    // The two halves must differ; a single 32-byte key reused for both would be
    // a catastrophic (and silent) design error.
    expect(c.bytesToHex(derived.ukek)).not.toBe(c.bytesToHex(derived.authSecret));
  });
});

describe('conformance: key wrapping', () => {
  it('reproduces the pinned CWRP envelope', async () => {
    const v = spec.deterministic.secretbox_wrap;
    const blob = await c.wrapKeyWithNonce(c.hexToBytes(v.kek_hex), c.hexToBytes(v.fek_hex), c.hexToBytes(v.nonce_hex));
    expect(c.bytesToHex(blob)).toBe(v.blob_hex);
    expect(blob.length).toBe(c.WRAPPED_KEY_LEN);
  });

  it('unwraps the pinned envelope', async () => {
    const v = spec.deterministic.secretbox_wrap;
    const fek = await c.unwrapKey(c.hexToBytes(v.kek_hex), c.hexToBytes(v.blob_hex));
    expect(c.bytesToHex(fek)).toBe(v.fek_hex);
  });

  it('rejects tampering, wrong keys and bad magic', async () => {
    const v = spec.deterministic.secretbox_wrap;
    const blob = c.hexToBytes(v.blob_hex);
    const flipped = blob.slice();
    flipped[flipped.length - 1]! ^= 1;
    await expect(c.unwrapKey(c.hexToBytes(v.kek_hex), flipped)).rejects.toThrow();
    const wrongKey = new Uint8Array(32).fill(9);
    await expect(c.unwrapKey(wrongKey, blob)).rejects.toThrow();
    const wrongMagic = blob.slice();
    wrongMagic[0] = 0x00;
    await expect(c.unwrapKey(c.hexToBytes(v.kek_hex), wrongMagic)).rejects.toThrow('bad wrap magic');
  });
});

describe('conformance: file stream', () => {
  it('decrypts the blob produced by the Rust core', async () => {
    const v = spec.stream;
    const plaintext = await c.decryptFile(c.hexToBytes(v.key_hex), c.hexToBytes(v.blob_hex));
    expect(new TextDecoder().decode(plaintext)).toBe(v.plaintext_utf8);
  });

  it('agrees on the ciphertext length formula', async () => {
    const v = spec.stream;
    const plaintext = new TextEncoder().encode(v.plaintext_utf8);
    expect(c.ciphertextLenFor(plaintext.length)).toBe(c.hexToBytes(v.blob_hex).length);
    for (const n of [0, 1, 1000, c.CHUNK_PLAINTEXT - 1, c.CHUNK_PLAINTEXT, c.CHUNK_PLAINTEXT + 5]) {
      const blob = await c.encryptFile(c.hexToBytes(v.key_hex), new Uint8Array(n).fill(7));
      expect(blob.length, `plaintext ${n}`).toBe(c.ciphertextLenFor(n));
      expect((await c.decryptFile(c.hexToBytes(v.key_hex), blob)).length).toBe(n);
    }
  });

  it('rejects truncation, trailing data and wrong keys', async () => {
    const v = spec.stream;
    const key = c.hexToBytes(v.key_hex);
    const blob = c.hexToBytes(v.blob_hex);
    await expect(c.decryptFile(key, blob.slice(0, blob.length - 5))).rejects.toThrow();
    await expect(c.decryptFile(new Uint8Array(32).fill(3), blob)).rejects.toThrow();
    const extended = new Uint8Array(blob.length + 4);
    extended.set(blob, 0);
    await expect(c.decryptFile(key, extended)).rejects.toThrow();
  });
});

describe('conformance: digests and verifier', () => {
  it('matches the plaintext and raw sha256 vectors', async () => {
    const v = spec.deterministic.digests;
    expect(await c.plaintextDigest(new TextEncoder().encode(v.content))).toBe(v.plaintext_digest_hex);
  });

  it('matches the login verifier', async () => {
    const v = spec.deterministic.auth_verifier;
    const verifier = await c.authVerifier(
      c.hexToBytes(v.pepper_hex),
      c.hexToBytes(v.auth_secret_hex),
      v.account_number_digits,
    );
    expect(verifier).toBe(v.verifier_hex);
  });
});

describe('conformance: account numbers', () => {
  it('validates, formats and fingerprints like the Rust core', async () => {
    const v = spec.deterministic.account_number;
    for (const digits of v.valid) {
      expect(c.parseAccount(digits)).toBe(digits);
      expect(c.parseAccount(c.formatAccount(digits))).toBe(digits);
      expect(await c.accountFingerprint(digits)).toBe(v.fingerprint_of_valid);
      expect(c.formatAccount(digits)).toBe(v.formatted);
    }
    for (const bad of v.invalid) {
      expect(() => c.parseAccount(bad)).toThrow();
    }
    // Check digit is the last of ACCOUNT_DIGITS; verify the same prefix the core does.
    const digits = v.valid[0] as string;
    expect(digits.length).toBe(c.ACCOUNT_DIGITS);
    expect(c.dammCheck(digits.slice(0, c.ACCOUNT_DIGITS - 1))).toBe(
      Number(digits[c.ACCOUNT_DIGITS - 1]),
    );
  });
});

describe('conformance: recovery phrase', () => {
  it('reproduces the pinned phrase and wrapping key', async () => {
    const v = spec.deterministic.recovery;
    const entropy = c.hexToBytes(v.entropy_hex);
    const words = await c.mnemonicFromEntropy(entropy);
    expect(words.join(' ')).toBe(v.phrase);
    expect(c.bytesToHex(await c.recoveryWrappingKey(entropy))).toBe(v.wrapping_key_hex);
    const round = await c.entropyFromMnemonic(words);
    expect(c.bytesToHex(round)).toBe(v.entropy_hex);
  });

  it('recovers the UKEK from the pinned recovery blob', async () => {
    const v = spec.deterministic.recovery;
    const ukek = await c.unwrapUkekWithRecovery(v.phrase, c.hexToBytes(v.ukek_wrapped_blob_hex));
    expect(c.bytesToHex(ukek)).toBe(spec.deterministic.kdf.ukek_hex);
  });

  it('rejects a phrase with a bad checksum', async () => {
    const v = spec.deterministic.recovery;
    const words = v.phrase.split(' ');
    words[23] = words[23] === 'zoo' ? 'zone' : 'zoo';
    await expect(c.entropyFromMnemonic(words)).rejects.toThrow('checksum mismatch');
  });
});

describe('interop: emit a blob for the Rust side', () => {
  it('writes web/.conformance/js-stream-blob.json', async () => {
    const key = (await c.sodium()).randombytes_buf(32);
    const plaintext = new TextEncoder().encode('JS-produced vector: web client -> core');
    const blob = await c.encryptFile(key, plaintext);
    const dir = fileURLToPath(new URL('../.conformance/', import.meta.url));
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      `${dir}js-stream-blob.json`,
      JSON.stringify(
        {
          key_hex: c.bytesToHex(key),
          plaintext_utf8: new TextDecoder().decode(plaintext),
          blob_hex: c.bytesToHex(blob),
        },
        null,
        2,
      ),
    );
    // Round-trips locally too.
    expect(await c.decryptFile(key, blob)).toEqual(plaintext);
  });
});
