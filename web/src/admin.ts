/**
 * Operator panel: `/admin` (hash route) in the same bundle.
 *
 * It talks to `/v1/admin/*` with a bearer token that the operator pastes once and
 * which is kept in `sessionStorage` — never in a cookie, never in localStorage, so
 * closing the tab ends the session. The panel never asks for a user's passphrase
 * because it could not use one: operators can see metadata and take moderation
 * actions, not decrypt anything.
 */

import { bytes, el, panel, showError, when } from './dom';
import { brand, loadBrand } from './brand';

const TOKEN_KEY = 'vault.admin.token';

interface Stats {
  accounts: number;
  banned: number;
  storage_used: number;
  files: number;
  plaintext_bytes: number;
  quarantined: number;
  open_reports: number;
  tiers: Record<string, number>;
  blob_bytes: number;
  screening: string;
  secrets: Record<string, string>;
}

interface AccountRow {
  id: number;
  account_number: string;
  tier: string;
  storage_used: number;
  storage_quota: number;
  created_at: number;
  strikes: number;
  banned: boolean;
  recovery_ack: boolean;
  last_seen: number | null;
}

interface FileRow {
  id: string;
  blob_ref: string;
  owner: string;
  plaintext_size: number;
  mime: string;
  visibility: string;
  quarantined: boolean;
  views: number;
  created_at: number;
}

interface ReportRow {
  id: string;
  file_id: string;
  reason: string;
  detail: string | null;
  owner: string | null;
  quarantined: boolean;
  created_at: number;
}

type Tab = 'overview' | 'accounts' | 'files' | 'reports' | 'brand';

function token(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      ...(init.headers ?? {}),
      authorization: `Bearer ${token() ?? ''}`,
    },
  });
  const text = await res.text();
  const body = text ? JSON.parse(text) : {};
  if (!res.ok) {
    const err = new Error(body.message ?? `HTTP ${res.status}`) as Error & { code?: string };
    err.code = body.error ?? `http_${res.status}`;
    throw err;
  }
  return body as T;
}

function stat(label: string, value: string, hint?: string): HTMLElement {
  return el(
    'div',
    { class: 'stat' },
    el('span', { class: 'stat-value' }, value),
    el('span', { class: 'stat-label' }, label),
    ...(hint ? [el('span', { class: 'stat-hint' }, hint)] : []),
  );
}

function table(headers: string[], rows: HTMLElement[]): HTMLElement {
  return el(
    'div',
    { class: 'table-wrap' },
    el(
      'table',
      { class: 'table' },
      el('thead', {}, el('tr', {}, ...headers.map((h) => el('th', {}, h)))),
      el('tbody', {}, ...rows),
    ),
  );
}

function cell(...children: (Node | string)[]): HTMLElement {
  return el('td', {}, ...children);
}

// ------------------------------------------------------------------ sections

async function overview(host: HTMLElement) {
  const s = await call<Stats>('/v1/admin/stats');
  host.replaceChildren(
    el(
      'div',
      { class: 'stats' },
      stat('accounts', String(s.accounts), `${s.banned} banned`),
      stat('files', String(s.files), `${s.quarantined} quarantined`),
      stat('plaintext stored', bytes(s.plaintext_bytes), `${bytes(s.blob_bytes)} ciphertext on disk`),
      stat('open reports', String(s.open_reports), s.open_reports ? 'needs review' : 'all clear'),
    ),
    panel(
      el('h2', {}, 'Instance health'),
      el(
        'div',
        { class: 'kv' },
        el('span', {}, 'screening'),
        el('span', { class: s.screening === 'configured' ? 'ok' : 'warn' }, s.screening),
        el('span', {}, 'pepper source'),
        el('span', { class: 'mono' }, s.secrets.pepper ?? '—'),
        el('span', {}, 'portal key source'),
        el('span', { class: 'mono' }, `${s.secrets.portal ?? '—'}${s.secrets.portal === 'env-derived' ? ' (derived)' : ''}`),
        el('span', {}, 'tiers'),
        el('span', { class: 'mono' }, Object.entries(s.tiers).map(([t, n]) => `${t}:${n}`).join('  ') || 'none'),
      ),
      el(
        'p',
        { class: 'muted' },
        'Operators see metadata and can act on reports. Nobody — including you — can decrypt a user file: the keys never leave the browser.',
      ),
    ),
  );
}

async function accounts(host: HTMLElement) {
  const q = el('input', { type: 'text', placeholder: 'filter by account number…' });
  const body = el('div');
  const load = async () => {
    const data = await call<{ total: number; items: AccountRow[] }>(
      `/v1/admin/accounts?limit=50&q=${encodeURIComponent((q as HTMLInputElement).value)}`,
    );
    body.replaceChildren(
      el('p', { class: 'muted' }, `${data.items.length} of ${data.total} accounts`),
      table(
        ['account', 'tier', 'used', 'last seen', 'state', ''],
        data.items.map((a) =>
          el(
            'tr',
            {},
            cell(el('span', { class: 'mono' }, a.account_number)),
            cell(a.tier),
            cell(`${bytes(a.storage_used)} / ${a.storage_quota ? bytes(a.storage_quota) : '0'}`),
            cell(when(a.last_seen)),
            cell(
              a.banned ? el('span', { class: 'badge quarantined' }, 'banned') : el('span', { class: 'badge ready' }, 'active'),
              a.recovery_ack ? '' : el('span', { class: 'badge pending' }, 'no recovery ack'),
            ),
            cell(
              el(
                'div',
                { class: 'row' },
                el('select', { class: 'mini', 'data-id': String(a.id) }, ...['basic', 'premium1', 'premium2'].map((t) =>
                  el('option', { value: t, ...(t === a.tier ? { selected: true } : {}) }, t),
                )),
                el('button', { class: 'secondary mini', 'data-ban': String(a.id) }, a.banned ? 'unban' : 'ban'),
              ),
            ),
          ),
        ),
      ),
    );

    body.querySelectorAll('select.mini').forEach((sel) => {
      sel.addEventListener('change', async () => {
        const id = (sel as HTMLElement).dataset.id!;
        try {
          await call(`/v1/admin/accounts/${id}`, {
            method: 'PATCH',
            body: JSON.stringify({ tier: (sel as HTMLSelectElement).value }),
          });
          await load();
        } catch (err) {
          alert(showError(err));
        }
      });
    });
    body.querySelectorAll('button[data-ban]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const id = (btn as HTMLElement).dataset.ban!;
        const row = data.items.find((a) => a.id === Number(id));
        if (!row) return;
        if (!confirm(`${row.banned ? 'Unban' : 'Ban'} ${row.account_number}?`)) return;
        try {
          await call(`/v1/admin/accounts/${id}`, {
            method: 'PATCH',
            body: JSON.stringify({ banned: !row.banned }),
          });
          await load();
        } catch (err) {
          alert(showError(err));
        }
      });
    });
  };
  q.addEventListener('input', () => void load());
  host.replaceChildren(panel(el('h2', {}, 'Accounts'), q), body);
  await load();
}

async function files(host: HTMLElement) {
  const data = await call<{ items: FileRow[] }>('/v1/admin/files?limit=50');
  const refresh = () => void files(host);
  host.replaceChildren(
    panel(
      el('h2', {}, 'Files'),
      el(
        'p',
        { class: 'muted' },
        'Quarantine kills the file at the origin. The CDN keeps its copy for the configured TTL — purge the path too.',
      ),
    ),
    table(
      ['file', 'owner', 'size', 'visibility', 'state', ''],
      data.items.map((f) =>
        el(
          'tr',
          {},
          cell(el('span', { class: 'mono' }, f.id), el('div', { class: 'muted mono' }, f.blob_ref.slice(0, 18) + '…')),
          cell(el('span', { class: 'mono' }, f.owner)),
          cell(bytes(f.plaintext_size)),
          cell(f.visibility),
          cell(f.quarantined ? el('span', { class: 'badge quarantined' }, 'quarantined') : el('span', { class: 'badge ready' }, 'live')),
          cell(
            f.quarantined
              ? ''
              : el(
                  'button',
                  { class: 'secondary mini', 'data-q': f.id },
                  'quarantine',
                ),
          ),
        ),
      ),
    ),
  );
  host.querySelectorAll('button[data-q]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = (btn as HTMLElement).dataset.q!;
      const reason = prompt('Reason (recorded in the mod log):', 'report upheld');
      if (reason === null) return;
      try {
        const res = await call<{ purge_path: string; cdn_ttl_seconds: number }>(
          `/v1/admin/files/${id}/quarantine`,
          { method: 'POST', body: JSON.stringify({ reason }) },
        );
        alert(`Quarantined.\nPurge at the CDN: ${res.purge_path}\nEdge copies persist up to ${res.cdn_ttl_seconds}s.`);
        refresh();
      } catch (err) {
        alert(showError(err));
      }
    });
  });
}

async function reports(host: HTMLElement) {
  const data = await call<{ items: ReportRow[] }>('/v1/admin/reports');
  host.replaceChildren(
    panel(el('h2', {}, 'Open reports')),
    data.items.length === 0
      ? el('p', { class: 'muted' }, 'No open reports.')
      : table(
          ['reported', 'reason', 'owner', 'state', ''],
          data.items.map((r) =>
            el(
              'tr',
              {},
              cell(el('span', { class: 'mono' }, r.file_id.slice(0, 16) + '…'), el('div', { class: 'muted' }, when(r.created_at))),
              cell(r.reason, r.detail ? el('div', { class: 'muted' }, r.detail.slice(0, 80)) : ''),
              cell(el('span', { class: 'mono' }, r.owner ?? '—')),
              cell(r.quarantined ? el('span', { class: 'badge quarantined' }, 'quarantined') : el('span', { class: 'badge pending' }, 'live')),
              cell(
                el(
                  'div',
                  { class: 'row' },
                  ...['quarantined', 'dismissed', 'warned'].map((action) =>
                    el('button', { class: 'secondary mini', 'data-r': r.id, 'data-a': action }, action),
                  ),
                ),
              ),
            ),
          ),
        ),
  );
  host.querySelectorAll('button[data-r]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = (btn as HTMLElement).dataset.r!;
      const action = (btn as HTMLElement).dataset.a!;
      try {
        await call(`/v1/admin/reports/${id}/resolve`, { method: 'POST', body: JSON.stringify({ action }) });
        await reports(host);
      } catch (err) {
        alert(showError(err));
      }
    });
  });
}

async function brandPanel(host: HTMLElement) {
  const doc = await call<Record<string, string>>('/v1/admin/brand');
  const name = el('input', { type: 'text', value: doc.name ?? brand.name });
  const tagline = el('input', { type: 'text', value: doc.tagline ?? brand.tagline });
  const accent = el('input', { type: 'color', value: doc.accent ?? brand.accent, class: 'color' });
  const logo = el('input', { type: 'text', value: doc.logo ?? '', placeholder: '◈ (optional mark)' });
  const out = el('div');

  const save = el('button', {}, 'Save branding');
  save.addEventListener('click', async () => {
    try {
      const updated = await call<Record<string, string>>('/v1/admin/brand', {
        method: 'PATCH',
        body: JSON.stringify({
          name: (name as HTMLInputElement).value,
          tagline: (tagline as HTMLInputElement).value,
          accent: (accent as HTMLInputElement).value,
          logo: (logo as HTMLInputElement).value,
        }),
      });
      out.replaceChildren(el('p', { class: 'ok' }, `Saved. This instance now calls itself ${updated.name}.`));
      await loadBrand();
    } catch (err) {
      out.replaceChildren(el('div', { class: 'err' }, showError(err)));
    }
  });

  host.replaceChildren(
    panel(
      el('h2', {}, 'Branding'),
      el('p', { class: 'muted' }, 'Renaming is a saved setting, not a rebuild: every client reads it on load. Only cosmetic fields live here — nothing that could invalidate an account or a file.'),
      el('label', {}, 'Name', name),
      el('label', {}, 'Tagline', tagline),
      el('label', {}, 'Accent', accent),
      el('label', {}, 'Mark', logo),
      el('div', { class: 'row' }, save),
      out,
    ),
  );
}

// ---------------------------------------------------------------------- shell

export function mountAdmin(host: HTMLElement) {
  if (!token()) {
    const input = el('input', { type: 'password', placeholder: 'admin token (VAULT_ADMIN_TOKEN)' });
    const go = el('button', {}, 'Enter');
    go.addEventListener('click', () => {
      const value = (input as HTMLInputElement).value.trim();
      if (!value) return;
      sessionStorage.setItem(TOKEN_KEY, value);
      mountAdmin(host);
    });
    (input as HTMLInputElement).addEventListener('keydown', (e) => {
      if ((e as KeyboardEvent).key === 'Enter') (go as HTMLButtonElement).click();
    });
    host.replaceChildren(
      panel(
        el('h2', {}, 'Operator sign-in'),
        el('p', { class: 'muted' }, 'Paste the token from VAULT_ADMIN_TOKEN. It is kept in this tab only. If the variable is unset on the server, this page does not exist.'),
        el('label', {}, 'Token', input),
        el('div', { class: 'row' }, go),
      ),
    );
    return;
  }

  const host2 = el('div', { class: 'app admin' });
  const nav = el('nav', { class: 'admin-nav' });
  const body = el('div', { class: 'admin-body' });
  let current: Tab = 'overview';

  const render = async () => {
    nav.querySelectorAll('button').forEach((b) => {
      b.className = (b as HTMLElement).dataset.tab === current ? 'chip active' : 'chip';
    });
    body.replaceChildren(el('p', { class: 'muted' }, 'loading…'));
    try {
      if (current === 'overview') await overview(body);
      else if (current === 'accounts') await accounts(body);
      else if (current === 'files') await files(body);
      else if (current === 'reports') await reports(body);
      else await brandPanel(body);
    } catch (err) {
      const message = showError(err);
      body.replaceChildren(
        el('div', { class: 'err' }, message),
        message.startsWith('http_401') || message.includes('admin token')
          ? el('button', { class: 'secondary', id: 'signout' }, 'Sign out')
          : '',
      );
      const signout = body.querySelector('#signout');
      signout?.addEventListener('click', () => {
        sessionStorage.removeItem(TOKEN_KEY);
        mountAdmin(host);
      });
    }
  };

  for (const tab of ['overview', 'accounts', 'files', 'reports', 'brand'] as Tab[]) {
    const b = el('button', { class: 'chip', 'data-tab': tab }, tab);
    b.addEventListener('click', () => {
      current = tab;
      void render();
    });
    nav.append(b);
  }

  host2.append(nav, body);
  host.replaceChildren(host2);
  void render();
}
