// Minimal typed client for vault-api. No framework: the PWA is a few screens.

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export interface AccountCreateResponse {
  account_number: string;
  digits: string;
  fingerprint: string;
  recovery_acknowledged: boolean;
}

export interface AuthResponse {
  token: string;
  expires_at: number;
  tier: string;
  storage_used: number;
  storage_quota: number;
  gate_passed: boolean;
  fingerprint: string;
}

export interface FileSummary {
  file_id: string;
  mime: string;
  size: number;
  duration_ms: number | null;
  visibility: 'private' | 'public' | 'passphrase';
  status: 'pending' | 'ready' | 'quarantined' | 'dead';
  created_at: number;
  view_count: number;
  thumb_ref: string | null;
}

export interface WrappedKey {
  wrap_type: 'user' | 'portal' | 'passphrase';
  blob: string;
}

export interface SignedUrl {
  path: string;
  expires_at: number;
  token: string;
}

export interface InitResponse {
  file_id: string;
  blob_ref: string;
  status: string;
  upload: SignedUrl;
}

export interface PublicManifest {
  file_id: string;
  mime: string;
  size: number;
  duration_ms: number | null;
  created_at: number;
  view_count: number;
  portal_key: string;
  thumb_ref: string | null;
  blob: SignedUrl;
}

export class Api {
  constructor(readonly base: string, private token: string | null = null) {}

  setToken(token: string | null) {
    this.token = token;
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (this.token) headers['authorization'] = `Bearer ${this.token}`;
    const res = await fetch(this.base + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    const parsed = text ? JSON.parse(text) : null;
    if (!res.ok) {
      const code = (parsed && parsed.error) || 'error';
      const message = (parsed && parsed.message) || res.statusText;
      throw new ApiError(res.status, code, message);
    }
    return parsed as T;
  }

  createAccount(payload: {
    kdf_salt: string;
    auth_secret: string;
    recovery_blob: string;
    kdf_version?: number;
    client: 'sealed_web';
  }) {
    return this.call<AccountCreateResponse>('POST', '/v1/accounts', payload);
  }

  prepareAuth(accountNumber: string) {
    return this.call<{ kdf_salt: string; kdf_ops: number; kdf_mem_bytes: number; kdf_version: number }>(
      'POST',
      '/v1/auth/prepare',
      { account_number: accountNumber },
    );
  }

  login(accountNumber: string, authSecretHex: string) {
    return this.call<AuthResponse>('POST', '/v1/auth', {
      account_number: accountNumber,
      auth_secret: authSecretHex,
    });
  }

  gate() {
    return this.call<{ gate_passed: boolean; gate_at: number; portal_key?: string }>('POST', '/v1/gate', {
      confirmed: true,
    });
  }

  me() {
    return this.call<{
      fingerprint: string;
      account_number: string;
      tier: string;
      storage_used: number;
      storage_quota: number;
      gate_passed: boolean;
      created_at: number;
      strikes: number;
      ban_flag: boolean;
    }>('GET', '/v1/me');
  }

  initFile(payload: {
    size: number;
    plaintext_digest: string;
    mime: string;
    duration_ms?: number;
    visibility: 'private' | 'public' | 'passphrase';
    keys: WrappedKey[];
  }) {
    return this.call<InitResponse>('POST', '/v1/files', payload);
  }

  async putBytes(path: string, bytes: Uint8Array): Promise<void> {
    const res = await fetch(this.base + path, {
      method: 'PUT',
      headers: { 'content-type': 'application/octet-stream' },
      body: bytes as unknown as BodyInit,
    });
    if (!res.ok) {
      const text = await res.text();
      throw new ApiError(res.status, 'upload_failed', text || res.statusText);
    }
  }

  complete(fileId: string) {
    return this.call<{ ok: boolean }>('POST', `/v1/files/${fileId}/complete`, {});
  }

  listFiles() {
    return this.call<{ files: FileSummary[] }>('GET', '/v1/files');
  }

  fileKeys(fileId: string) {
    return this.call<{ file_id: string; keys: WrappedKey[] }>('GET', `/v1/files/${fileId}/keys`);
  }

  fileUrl(fileId: string) {
    return this.call<SignedUrl>('GET', `/v1/files/${fileId}/url`);
  }

  publicManifest(fileId: string) {
    return this.call<PublicManifest>('GET', `/v1/p/${fileId}`);
  }

  async getBytes(path: string): Promise<Uint8Array> {
    const res = await fetch(this.base + path);
    if (!res.ok) throw new ApiError(res.status, 'download_failed', res.statusText);
    return new Uint8Array(await res.arrayBuffer());
  }
}
