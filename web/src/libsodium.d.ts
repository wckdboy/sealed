// Minimal hand-written types for the libsodium sumo build we use. The package
// ships a broken ESM entry and no .d.ts, so we declare exactly what we call
// rather than pretend to have a full binding.
declare module 'libsodium-wrappers-sumo' {
  export interface SecretStreamState {
    readonly _brand?: 'secretstream-state';
  }

  export interface Sodium {
    ready: Promise<void>;

    readonly crypto_secretstream_xchacha20poly1305_TAG_MESSAGE: number;
    readonly crypto_secretstream_xchacha20poly1305_TAG_FINAL: number;
    readonly crypto_pwhash_ALG_ARGON2ID13: number;

    randombytes_buf(length: number): Uint8Array;

    crypto_hash_sha256(data: Uint8Array): Uint8Array;
    crypto_auth_hmacsha256(message: Uint8Array, key: Uint8Array): Uint8Array;

    crypto_pwhash(
      keyLength: number,
      password: string | Uint8Array,
      salt: Uint8Array,
      opsLimit: number,
      memLimit: number,
      algorithm: number,
    ): Uint8Array;

    crypto_secretbox_easy(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
    crypto_secretbox_open_easy(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;

    crypto_secretstream_xchacha20poly1305_init_push(key: Uint8Array): {
      state: SecretStreamState;
      header: Uint8Array;
    };
    crypto_secretstream_xchacha20poly1305_push(
      state: SecretStreamState,
      message: Uint8Array,
      ad: Uint8Array | null,
      tag: number,
    ): Uint8Array;
    crypto_secretstream_xchacha20poly1305_init_pull(header: Uint8Array, key: Uint8Array): SecretStreamState;
    crypto_secretstream_xchacha20poly1305_pull(
      state: SecretStreamState,
      ciphertext: Uint8Array,
      ad: Uint8Array | null,
    ): { message: Uint8Array; tag: number };
  }

  const sodium: Sodium & { default?: Sodium };
  export default sodium;
}
