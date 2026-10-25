/**
 * Pure helpers: no crypto, no libsodium, ~2 KB. Imported by the UI shell so that
 * formatting an account number does not drag a 1 MB crypto module into first
 * paint. Anything that needs libsodium lives in `crypto.ts`, which is
 * dynamically imported on the first action that needs it.
 */

export const WRAP_MAGIC = 'CWRP';
export const STREAM_MAGIC = 'COOMF1';
export const CHUNK_PLAINTEXT = 4 * 1024 * 1024;
export const TAG_BYTES = 17;
export const LEN_PREFIX = 4;
export const SALT_BYTES = 16;
export const WRAPPED_KEY_LEN = 4 + 1 + 24 + 32 + 16;

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) throw new Error('invalid hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Exact ciphertext length for a plaintext of `n` bytes (server-side check). */
export function ciphertextLenFor(plaintextLen: number): number {
  const chunks = plaintextLen === 0 ? 1 : Math.ceil(plaintextLen / CHUNK_PLAINTEXT);
  return 6 + 24 + chunks * (LEN_PREFIX + TAG_BYTES) + plaintextLen;
}

const DAMM: number[][] = [
  [0, 3, 1, 7, 5, 9, 8, 6, 4, 2],
  [7, 0, 9, 2, 1, 5, 4, 8, 6, 3],
  [4, 2, 0, 6, 8, 7, 1, 3, 5, 9],
  [1, 7, 5, 0, 9, 8, 3, 4, 2, 6],
  [6, 1, 2, 3, 0, 4, 5, 9, 7, 8],
  [3, 6, 7, 4, 2, 0, 9, 5, 8, 1],
  [5, 8, 6, 9, 7, 2, 0, 1, 3, 4],
  [8, 9, 4, 5, 3, 6, 2, 0, 1, 7],
  [9, 4, 3, 8, 6, 1, 7, 2, 0, 5],
  [2, 5, 8, 1, 4, 3, 6, 7, 9, 0],
];

export function dammCheck(digits: string): number {
  let interim = 0;
  for (const ch of digits) interim = DAMM[interim]![Number(ch)]!;
  return interim;
}

/** Normalise user input to 12 validated digits. Throws on anything else. */
export const ACCOUNT_DIGITS = 16;

export function parseAccount(input: string): string {
  const trimmed = input.trim().replace(/^vault:acct:/, '');
  const digits = trimmed.replace(/[\s\-._]/g, '');
  if (digits.length !== ACCOUNT_DIGITS || /[^0-9]/.test(digits)) {
    throw new Error(`expected ${ACCOUNT_DIGITS} digits`);
  }
  const check = dammCheck(digits.slice(0, ACCOUNT_DIGITS - 1));
  if (check !== Number(digits[ACCOUNT_DIGITS - 1])) throw new Error('check digit mismatch');
  // Same rule as the Rust core (account::is_degenerate): all-identical digits are
  // refused even though e.g. "0000…" is check-digit valid.
  if (/^(\d)\1+$/.test(digits)) throw new Error('degenerate number');
  return digits;
}

export function formatAccount(digits: string): string {
  return digits.match(/.{1,4}/g)!.join(' ');
}
