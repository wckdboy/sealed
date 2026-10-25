/**
 * Sealed Web crypto — the browser half of the shared contract.
 *
 * Every byte format here is pinned by `spec/crypto-vectors.json`, which the Rust
 * core generates and this file must reproduce (`npm test`). If these two ever
 * disagree, the app cannot read files encrypted by the Android client, so the
 * conformance test is the load-bearing test in the repo.
 *
 * Primitives (all libsodium, no WebCrypto for anything but hashing/HMAC):
 *   file body   XChaCha20-Poly1305 secretstream, 4 MiB chunks, COOMF1 framing
 *   key wrap    XSalsa20-Poly1305 secretbox, CWRP envelope
 *   passphrase  Argon2id13, 64 MiB / 3 passes, 64 bytes split into UKEK + auth
 *   recovery    BIP39 24 words over 256-bit entropy
 */

import sodiumDefault from 'libsodium-wrappers-sumo';
import {
  bytesToHex,
  CHUNK_PLAINTEXT,
  TAG_BYTES,
  LEN_PREFIX,
  SALT_BYTES,
  WRAP_MAGIC,
  STREAM_MAGIC,
} from './codec';

// Re-exported so tests and callers can treat this module as the whole surface.
export * from './codec';
import type { Sodium } from 'libsodium-wrappers-sumo';
import wordlistRaw from './data/english.txt?raw';


export const KDF_OPS = 3;
export const KDF_MEM_BYTES = 64 * 1024 * 1024;

const enc = new TextEncoder();
const dec = new TextDecoder();

let cached: Sodium | null = null;

/** Await libsodium's WASM/asm.js init exactly once. */
export async function sodium(): Promise<Sodium> {
  if (!cached) {
    const mod = sodiumDefault as unknown as { default?: Sodium } & Sodium;
    const s = (mod.default ?? mod) as Sodium;
    await s.ready;
    cached = s;
  }
  return cached;
}


function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * SHA-256 via libsodium, not WebCrypto.
 *
 * `crypto.subtle` only exists in a **secure context** (https, or http on
 * localhost). A self-hosted instance reached over plain http — a LAN address, a
 * bare VPS IP, or a proxy that has not got its certificate yet — has
 * `crypto.subtle === undefined`, and the first digest then throws
 * "Cannot read properties of undefined (reading 'digest')" with no hint about why.
 * libsodium's wasm works in any context, produces byte-identical SHA-256, and is
 * already loaded for everything else.
 */
async function sha256Digest(parts: Uint8Array[]): Promise<Uint8Array> {
  const s = await sodium();
  return s.crypto_hash_sha256(concat(parts));
}

/** HMAC-SHA-256 via libsodium; see sha256Digest for why this is not WebCrypto. */
export async function hmacSha256(key: Uint8Array, parts: Uint8Array[]): Promise<Uint8Array> {
  const s = await sodium();
  return s.crypto_auth_hmacsha256(concat(parts), key);
}

// ---------------------------------------------------------------- key wrapping

/** Wrap a 32-byte key under `kek`: CWRP | ver(1) | nonce(24) | secretbox(48). */
export async function wrapKey(kek: Uint8Array, target: Uint8Array): Promise<Uint8Array> {
  const s = await sodium();
  const nonce = s.randombytes_buf(24);
  return wrapKeyWithNonce(kek, target, nonce);
}

/** Deterministic-nonce variant. Only for conformance vectors. */
export async function wrapKeyWithNonce(
  kek: Uint8Array,
  target: Uint8Array,
  nonce: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  if (kek.length !== 32) throw new Error('kek must be 32 bytes');
  if (target.length !== 32) throw new Error('target key must be 32 bytes');
  if (nonce.length !== 24) throw new Error('nonce must be 24 bytes');
  const ct = s.crypto_secretbox_easy(target, nonce, kek);
  return concat([enc.encode(WRAP_MAGIC), new Uint8Array([1]), nonce, ct]);
}

export async function unwrapKey(kek: Uint8Array, blob: Uint8Array): Promise<Uint8Array> {
  const s = await sodium();
  if (blob.length < 4 + 1 + 24 + 16) throw new Error('wrapped key too short');
  if (dec.decode(blob.slice(0, 4)) !== WRAP_MAGIC) throw new Error('bad wrap magic');
  if (blob[4] !== 1) throw new Error(`unsupported wrap version ${blob[4]}`);
  const nonce = blob.slice(5, 29);
  const ct = blob.slice(29);
  const plain = s.crypto_secretbox_open_easy(ct, nonce, kek);
  if (plain.length !== 32) throw new Error('wrapped key is not 32 bytes');
  return plain;
}


// ----------------------------------------------------------------- file crypto

/** Plaintext bytes -> COOMF1 ciphertext blob. */
export async function encryptFile(key: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const s = await sodium();
  const { state, header } = s.crypto_secretstream_xchacha20poly1305_init_push(key);
  const parts: Uint8Array[] = [enc.encode(STREAM_MAGIC), header];

  const chunkCount = plaintext.length === 0 ? 1 : Math.ceil(plaintext.length / CHUNK_PLAINTEXT);
  for (let i = 0; i < chunkCount; i++) {
    const chunk = plaintext.slice(i * CHUNK_PLAINTEXT, (i + 1) * CHUNK_PLAINTEXT);
    const isFinal = i === chunkCount - 1;
    const ct = s.crypto_secretstream_xchacha20poly1305_push(
      state,
      chunk,
      null,
      isFinal
        ? s.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : s.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    );
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, ct.length, true);
    parts.push(len, ct);
  }
  return concat(parts);
}

/** COOMF1 ciphertext blob -> plaintext. Rejects truncation and trailing data. */
export async function decryptFile(key: Uint8Array, blob: Uint8Array): Promise<Uint8Array> {
  const s = await sodium();
  if (blob.length < 6 + 24) throw new Error('blob too short');
  if (dec.decode(blob.slice(0, 6)) !== STREAM_MAGIC) throw new Error('bad stream magic');
  const header = blob.slice(6, 30);
  const state = s.crypto_secretstream_xchacha20poly1305_init_pull(header, key);

  const out: Uint8Array[] = [];
  let cursor = 30;
  for (;;) {
    if (cursor === blob.length) throw new Error('stream ended before the final chunk');
    if (blob.length - cursor < LEN_PREFIX) throw new Error('malformed chunk length');
    const len = new DataView(blob.buffer, blob.byteOffset + cursor, 4).getUint32(0, true);
    cursor += LEN_PREFIX;
    if (len > CHUNK_PLAINTEXT + TAG_BYTES || blob.length - cursor < len) throw new Error('bad chunk length');
    const { message, tag } = s.crypto_secretstream_xchacha20poly1305_pull(
      state,
      blob.slice(cursor, cursor + len),
      null,
    );
    cursor += len;
    out.push(message);
    if (tag === s.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
      if (cursor !== blob.length) throw new Error('trailing data after final chunk');
      return concat(out);
    }
  }
}


// ------------------------------------------------------------------ derivation

export interface Derived {
  ukek: Uint8Array;
  authSecret: Uint8Array;
}

/** Argon2id(passphrase, salt) -> 64 bytes -> UKEK | auth_secret. */
export async function deriveKeys(passphrase: string, salt: Uint8Array): Promise<Derived> {
  const s = await sodium();
  if (salt.length !== SALT_BYTES) throw new Error('salt must be 16 bytes');
  const out = s.crypto_pwhash(
    64,
    passphrase,
    salt,
    KDF_OPS,
    KDF_MEM_BYTES,
    s.crypto_pwhash_ALG_ARGON2ID13,
  );
  return { ukek: out.slice(0, 32), authSecret: out.slice(32, 64) };
}

export async function freshSalt(): Promise<Uint8Array> {
  const s = await sodium();
  return s.randombytes_buf(SALT_BYTES);
}

/** Login verifier: HMAC-SHA256(pepper, "vault/auth-verifier/v1" || auth || digits). */
export async function authVerifier(
  pepper: Uint8Array,
  authSecret: Uint8Array,
  digits: string,
): Promise<string> {
  const mac = await hmacSha256(pepper, [
    enc.encode('vault/auth-verifier/v1'),
    authSecret,
    enc.encode(digits),
  ]);
  return bytesToHex(mac);
}

/** Domain-separated digest of a plaintext, as sent to the server for screening. */
export async function plaintextDigest(bytes: Uint8Array): Promise<string> {
  const d = await sha256Digest([enc.encode('vault/plaintext-sha256/v1'), bytes]);
  return bytesToHex(d);
}

// --------------------------------------------------------------- account numbers

export async function accountFingerprint(digits: string): Promise<string> {
  const d = await sha256Digest([enc.encode('vault/acct-fingerprint/v1'), enc.encode(digits)]);
  return bytesToHex(d.slice(0, 3)).toUpperCase();
}

// -------------------------------------------------------------- recovery phrase

const WORDLIST: string[] = wordlistRaw.split('\n').filter((w) => w.length > 0);

export const WORD_COUNT = 24;

export async function generateRecoveryEntropy(): Promise<Uint8Array> {
  const s = await sodium();
  return s.randombytes_buf(32);
}

/** 256-bit entropy + 8-bit checksum -> 24 BIP39 words. */
export async function mnemonicFromEntropy(entropy: Uint8Array): Promise<string[]> {
  if (entropy.length !== 32) throw new Error('entropy must be 32 bytes');
  const checksum = (await sha256Digest([entropy]))[0]!;
  const bits = new Uint8Array(33);
  bits.set(entropy, 0);
  bits[32] = checksum;

  const words: string[] = [];
  let bitPos = 0;
  for (let w = 0; w < WORD_COUNT; w++) {
    let idx = 0;
    for (let b = 0; b < 11; b++) {
      const byte = bits[bitPos >> 3]!;
      const bit = (byte >> (7 - (bitPos & 7))) & 1;
      idx = (idx << 1) | bit;
      bitPos++;
    }
    words.push(WORDLIST[idx]!);
  }
  return words;
}

export async function entropyFromMnemonic(words: string[]): Promise<Uint8Array> {
  if (words.length !== WORD_COUNT) throw new Error('expected 24 words');
  const bits = new Uint8Array(33);
  let bitPos = 0;
  for (const raw of words) {
    const idx = WORDLIST.indexOf(raw.toLowerCase().trim());
    if (idx < 0) throw new Error(`unknown word: ${raw}`);
    for (let b = 10; b >= 0; b--) {
      if ((idx >> b) & 1) bits[bitPos >> 3] = (bits[bitPos >> 3] ?? 0) | (1 << (7 - (bitPos & 7)));
      bitPos++;
    }
  }
  const entropy = bits.slice(0, 32);
  const expected = (await sha256Digest([entropy]))[0]!;
  if (expected !== bits[32]!) throw new Error('checksum mismatch');
  return entropy;
}

/** SHA-256("vault/recovery-key/v1" || entropy) — 256-bit, no KDF cost. */
export async function recoveryWrappingKey(entropy: Uint8Array): Promise<Uint8Array> {
  return sha256Digest([enc.encode('vault/recovery-key/v1'), entropy]);
}

export async function wrapUkekWithRecovery(entropy: Uint8Array, ukek: Uint8Array): Promise<Uint8Array> {
  return wrapKey(await recoveryWrappingKey(entropy), ukek);
}

export async function unwrapUkekWithRecovery(phrase: string, blob: Uint8Array): Promise<Uint8Array> {
  const entropy = await entropyFromMnemonic(phrase.split(/\s+/).filter(Boolean));
  return unwrapKey(await recoveryWrappingKey(entropy), blob);
}
