/**
 * Live end-to-end smoke test against a running `vault-api`.
 *
 * Skipped unless `VAULT_LIVE_BASE` is set, so `npm test` stays hermetic:
 *
 *   VAULT_LIVE_BASE=http://127.0.0.1:8099 npx vitest run src/live.test.ts
 *
 * This is the test that proves the product claim: a browser encrypts a file, the
 * server stores bytes it cannot read, a *different* account can stream a public
 * file using only the portal key, and the owner can pull their own file back and
 * decrypt it. Every assertion here is on real HTTP and real ciphertext.
 */

import { describe, expect, it } from 'vitest';
import { Api } from './api';
import * as c from './crypto';

const BASE = process.env.VAULT_LIVE_BASE;

describe.skipIf(!BASE)('live api', () => {
  const api = new Api(BASE ?? '');

  async function newAccount(passphrase: string) {
    const salt = await c.freshSalt();
    const derived = await c.deriveKeys(passphrase, salt);
    const entropy = await c.generateRecoveryEntropy();
    const phrase = (await c.mnemonicFromEntropy(entropy)).join(' ');
    const recoveryBlob = await c.wrapUkekWithRecovery(entropy, derived.ukek);
    const created = await api.createAccount({
      kdf_salt: c.bytesToHex(salt),
      auth_secret: c.bytesToHex(derived.authSecret),
      recovery_blob: c.bytesToHex(recoveryBlob),
      kdf_version: 1,
      client: 'sealed_web',
    });

    const prepared = await api.prepareAuth(created.digits);
    expect(prepared.kdf_salt).toBe(c.bytesToHex(salt));

    const rederived = await c.deriveKeys(passphrase, c.hexToBytes(prepared.kdf_salt));
    expect(c.bytesToHex(rederived.ukek)).toBe(c.bytesToHex(derived.ukek));

    const client = new Api(BASE ?? '');
    const auth = await client.login(created.digits, c.bytesToHex(rederived.authSecret));
    client.setToken(auth.token);
    const gate = await client.gate();
    return {
      client,
      digits: created.digits,
      ukek: rederived.ukek,
      portalKey: c.hexToBytes(gate.portal_key ?? ''),
      phrase,
      recoveryBlob,
    };
  }

  it('signup, encrypt, upload, download, decrypt, and public streaming', async () => {
    const owner = await newAccount('harbor violet tractor cinder');
    expect(owner.digits).toMatch(/^\d{16}$/);

    // A 2.5 MiB payload exercises a partial second chunk.
    const plaintext = new Uint8Array(2_500_000);
    for (let i = 0; i < plaintext.length; i++) plaintext[i] = (i * 31) % 256;

    const s = await c.sodium();
    const fek = s.randombytes_buf(32);
    const ciphertext = await c.encryptFile(fek, plaintext);
    expect(ciphertext.length).toBe(c.ciphertextLenFor(plaintext.length));

    const init = await owner.client.initFile({
      size: plaintext.length,
      plaintext_digest: await c.plaintextDigest(plaintext),
      mime: 'video/mp4',
      visibility: 'private',
      keys: [{ wrap_type: 'user', blob: c.bytesToHex(await c.wrapKey(owner.ukek, fek)) }],
    });
    await owner.client.putBytes(init.upload.path, ciphertext);
    await owner.client.complete(init.file_id);

    const listed = await owner.client.listFiles();
    const file = listed.files.find((f) => f.file_id === init.file_id);
    expect(file?.status).toBe('ready');
    expect(file?.size).toBe(plaintext.length);

    // Owner reads it back through a signed URL.
    const keys = await owner.client.fileKeys(init.file_id);
    const userWrap = keys.keys.find((k) => k.wrap_type === 'user')!;
    const unwrapped = await c.unwrapKey(owner.ukek, c.hexToBytes(userWrap.blob));
    const url = await owner.client.fileUrl(init.file_id);
    const fetched = await owner.client.getBytes(url.path);
    expect(fetched.length).toBe(ciphertext.length);
    expect(await c.decryptFile(unwrapped, fetched)).toEqual(plaintext);

    // The bytes must be cacheable by a CDN and seekable by a player: a real
    // request with a Range header must come back 206 with the exact slice.
    const ranged = await fetch(BASE + url.path, { headers: { Range: 'bytes=100-199' } });
    expect(ranged.status).toBe(206);
    expect(ranged.headers.get('accept-ranges')).toBe('bytes');
    expect(ranged.headers.get('content-range')).toBe(`bytes 100-199/${ciphertext.length}`);
    const cacheControl = ranged.headers.get('cache-control') ?? '';
    expect(cacheControl).toContain('public');
    expect(cacheControl).toContain('s-maxage=');
    const slice = new Uint8Array(await ranged.arrayBuffer());
    expect(slice.length).toBe(100);
    expect(slice).toEqual(ciphertext.slice(100, 200));

    // ETag revalidation: a conditional request must not resend the body.
    const etag = ranged.headers.get('etag');
    expect(etag).toBeTruthy();
    const notModified = await fetch(BASE + url.path, { headers: { 'If-None-Match': etag! } });
    expect(notModified.status).toBe(304);

    // Public file: wrapped under the same portal key every gated session gets.
    const pubPlaintext = new TextEncoder().encode('public stream test '.repeat(500));
    const pubFek = s.randombytes_buf(32);
    const pubCiphertext = await c.encryptFile(pubFek, pubPlaintext);
    const pubInit = await owner.client.initFile({
      size: pubPlaintext.length,
      plaintext_digest: await c.plaintextDigest(pubPlaintext),
      mime: 'video/mp4',
      visibility: 'public',
      keys: [
        { wrap_type: 'user', blob: c.bytesToHex(await c.wrapKey(owner.ukek, pubFek)) },
        { wrap_type: 'portal', blob: c.bytesToHex(await c.wrapKey(owner.portalKey, pubFek)) },
      ],
    });
    await owner.client.putBytes(pubInit.upload.path, pubCiphertext);
    await owner.client.complete(pubInit.file_id);

    // A second, unrelated account can stream it after the gate, with no key from
    // the owner — only the portal key.
    const stranger = await newAccount('another person entirely here');
    const manifest = await stranger.client.publicManifest(pubInit.file_id);
    expect(manifest.portal_key.length).toBe(c.WRAPPED_KEY_LEN * 2);
    const strangerFek = await c.unwrapKey(stranger.portalKey, c.hexToBytes(manifest.portal_key));
    const streamed = await stranger.client.getBytes(manifest.blob.path);
    expect(await c.decryptFile(strangerFek, streamed)).toEqual(pubPlaintext);

    // Private files are invisible to the stranger.
    await expect(stranger.client.publicManifest(init.file_id)).rejects.toThrow();

    // Recovery phrase restores the UKEK from the server-held blob.
    const restored = await c.unwrapUkekWithRecovery(owner.phrase, owner.recoveryBlob);
    expect(c.bytesToHex(restored)).toBe(c.bytesToHex(owner.ukek));
  });
});
