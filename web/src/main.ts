/**
 * Sealed Web: a working vertical slice of the product.
 *
 * Sign up -> account number + 24 words -> unlock -> encrypt locally -> upload
 * ciphertext -> fetch it back through a signed URL -> decrypt in the tab -> play.
 *
 * There is no server-side "decrypt" path anywhere in this file because there is
 * no server-side key. If this tab loses the UKEK, the files are gone: that is the
 * product promise, not a bug.
 */

import { Api, type FileSummary, type WrappedKey } from './api';
import { applyBrand, brand, loadBrand } from './brand';
import { formatAccount, parseAccount } from './codec';
import { bytes, el, panel, showError } from './dom';

// libsodium is ~1 MB of the bundle and is only needed once the user actually does
// something cryptographic. `import()` keeps it out of first paint: the shell ships
// a few KB and the crypto module is fetched on the first signup/unlock/upload/play.
const loadCrypto = () => import('./crypto');

// Production builds are served by the API itself, so the base is the current
// origin (empty prefix). `vite dev` runs on another port, hence the dev default.
// VITE_API_BASE overrides both.
const API_BASE =
  (import.meta.env.VITE_API_BASE as string | undefined) ??
  (import.meta.env.DEV ? 'http://localhost:8080' : '');
const app = document.getElementById('app') as HTMLElement;
const who = document.getElementById('who') as HTMLElement;

interface State {
  api: Api;
  digits: string | null;
  fingerprint: string | null;
  ukek: Uint8Array | null;
  portalKey: Uint8Array | null;
  playerUrl: string | null;
}

const state: State = {
  api: new Api(API_BASE),
  digits: null,
  fingerprint: null,
  ukek: null,
  portalKey: null,
  playerUrl: null,
};

let content: HTMLElement;

function setWho() {
  who.textContent = state.fingerprint
    ? `account ${state.fingerprint}${state.digits ? ` · ${formatAccount(state.digits)}` : ''}`
    : 'not unlocked';
}

// --------------------------------------------------------------------- signup

function renderSignup(container: HTMLElement) {
  const pass = el('input', { type: 'password', placeholder: 'at least 3 words or 20 characters' });
  const out = el('div');
  const submit = el('button', {}, 'Create account');

  submit.addEventListener('click', async () => {
    out.replaceChildren();
    submit.disabled = true;
    try {
      const passphrase = (pass as HTMLInputElement).value;
      if (passphrase.length < 12) throw new Error('passphrase is too short');

      const c = await loadCrypto();
      const salt = await c.freshSalt();
      const derived = await c.deriveKeys(passphrase, salt);
      const entropy = await c.generateRecoveryEntropy();
      const words = await c.mnemonicFromEntropy(entropy);
      const recoveryBlob = await c.wrapUkekWithRecovery(entropy, derived.ukek);

      const created = await state.api.createAccount({
        kdf_salt: c.bytesToHex(salt),
        auth_secret: c.bytesToHex(derived.authSecret),
        recovery_blob: c.bytesToHex(recoveryBlob),
        kdf_version: 1,
        client: 'sealed_web',
      });

      state.digits = created.digits;
      state.fingerprint = created.fingerprint;
      state.ukek = derived.ukek;
      setWho();

      const ack = el('input', { type: 'checkbox' });
      const go = el('button', { class: 'secondary', disabled: true }, 'Open my vault');
      (ack as HTMLInputElement).addEventListener('change', () => {
        (go as HTMLButtonElement).disabled = !(ack as HTMLInputElement).checked;
      });
      go.addEventListener('click', () => unlockVault(created.digits, passphrase));

      out.append(
        panel(
          el('h2', {}, 'Write this down. It is the only way back in.'),
          el('div', { class: 'account mono' }, created.account_number),
          el('p', { class: 'muted' }, `fingerprint ${created.fingerprint} — check it matches next time`),
          el('h2', {}, 'Recovery phrase (24 words)'),
          el('div', { class: 'words' }, ...words.map((w, i) => el('span', {}, el('b', {}, String(i + 1)), w))),
          el('p', { class: 'muted' }, `Anyone with these words can recover your vault. Nobody at ${brand.name} can.`),
          el('label', {}, ack, ' I have written down both the account number and the phrase'),
          el('div', { class: 'row' }, go),
        ),
      );
    } catch (err) {
      out.append(el('div', { class: 'err' }, showError(err)));
    } finally {
      submit.disabled = false;
    }
  });

  container.replaceChildren(
    panel(
      el('h2', {}, 'No email. No name. Just a number.'),
      el('p', { class: 'muted' },
        `${brand.name} generates a 16-digit account number and a 24-word recovery phrase. Your passphrase never leaves this tab.`),
      el('label', {}, 'Passphrase', pass),
      el('div', { class: 'row' }, submit),
    ),
    out,
  );
}

// --------------------------------------------------------------------- unlock

function renderUnlock(container: HTMLElement) {
  const acct = el('input', { type: 'text', placeholder: '4827 3910 5649 0182' });
  const pass = el('input', { type: 'password', placeholder: 'your passphrase' });
  const out = el('div');
  const submit = el('button', {}, 'Unlock');
  submit.addEventListener('click', async () => {
    out.replaceChildren();
    submit.disabled = true;
    try {
      const digits = parseAccount((acct as HTMLInputElement).value);
      await unlockVault(digits, (pass as HTMLInputElement).value);
    } catch (err) {
      out.append(el('div', { class: 'err' }, showError(err)));
    } finally {
      submit.disabled = false;
    }
  });
  container.replaceChildren(
    panel(
      el('h2', {}, 'Unlock an existing vault'),
      el('p', { class: 'muted' }, 'The passphrase is used locally to derive your key. Nothing is sent but a derived verifier.'),
      el('label', {}, 'Account number', acct),
      el('label', {}, 'Passphrase', pass),
      el('div', { class: 'row' }, submit),
      out,
    ),
  );
}

async function unlockVault(digits: string, passphrase: string) {
  try {
    const c = await loadCrypto();
    const prepared = await state.api.prepareAuth(digits);
    const derived = await c.deriveKeys(passphrase, c.hexToBytes(prepared.kdf_salt));

    const auth = await state.api.login(digits, c.bytesToHex(derived.authSecret));
    state.api.setToken(auth.token);
    state.digits = digits;
    state.fingerprint = auth.fingerprint;
    state.ukek = derived.ukek;
    setWho();

    const gate = await state.api.gate();
    state.portalKey = gate.portal_key ? c.hexToBytes(gate.portal_key) : null;

    await renderVault();
  } catch (err) {
    content.replaceChildren(
      panel(el('h2', {}, 'Could not unlock'), el('div', { class: 'err' }, showError(err))),
    );
  }
}

// ---------------------------------------------------------------------- vault

async function renderVault(flash?: string) {
  const list = await state.api.listFiles();
  const me = await state.api.me();

  const fileInput = el('input', { type: 'file', accept: 'video/*,image/*' });
  const publicToggle = el('input', { type: 'checkbox' });
  const status = el('div');
  const upload = el('button', {}, 'Encrypt & upload');

  upload.addEventListener('click', async () => {
    const file = (fileInput as HTMLInputElement).files?.[0];
    status.replaceChildren();
    if (!file) {
      status.append(el('div', { class: 'err' }, 'pick a file first'));
      return;
    }
    upload.disabled = true;
    try {
      status.append(el('div', { class: 'muted' }, 'reading…'));
      const c = await loadCrypto();
      const plaintext = new Uint8Array(await file.arrayBuffer());

      status.append(el('div', { class: 'muted' }, 'deriving file key and encrypting…'));
      const s = await c.sodium();
      const fek = s.randombytes_buf(32);
      const blob = await c.encryptFile(fek, plaintext);
      const digest = await c.plaintextDigest(plaintext);

      const isPublic = (publicToggle as HTMLInputElement).checked;
      const keys: WrappedKey[] = [
        { wrap_type: 'user', blob: c.bytesToHex(await c.wrapKey(state.ukek!, fek)) },
      ];
      if (isPublic) {
        if (!state.portalKey) throw new Error('portal key missing: confirm 18+ first');
        keys.push({ wrap_type: 'portal', blob: c.bytesToHex(await c.wrapKey(state.portalKey, fek)) });
      }

      const init = await state.api.initFile({
        size: plaintext.length,
        plaintext_digest: digest,
        mime: file.type || 'video/mp4',
        visibility: isPublic ? 'public' : 'private',
        keys,
      });

      status.append(el('div', { class: 'muted' }, `uploading ${bytes(blob.length)} of ciphertext…`));
      await state.api.putBytes(init.upload.path, blob);
      await state.api.complete(init.file_id);

      await renderVault(`stored ${init.file_id} · ${bytes(blob.length)} of ciphertext on the server`);
    } catch (err) {
      status.append(el('div', { class: 'err' }, showError(err)));
    } finally {
      upload.disabled = false;
    }
  });

  const rows = list.files.map((f: FileSummary) => {
    const play = el('button', { class: 'secondary' }, 'Play');
    play.addEventListener('click', () => playFile(f));
    return el(
      'div',
      { class: 'file' },
      el(
        'div',
        {},
        el('div', {}, `${f.mime} · ${bytes(f.size)}`),
        el(
          'div',
          { class: 'meta' },
          `${new Date(f.created_at * 1000).toLocaleString()} · ${f.visibility}`,
          el('span', { class: `badge ${f.status}` }, f.status),
        ),
      ),
      play,
    );
  });

  content.replaceChildren(
    panel(
      el('h2', {}, 'Vault'),
      ...(flash ? [el('div', { class: 'ok' }, flash)] : []),
      el('p', { class: 'muted' },
        `${bytes(me.storage_used)} of ${bytes(me.storage_quota)} used · tier ${me.tier} · ${me.gate_passed ? '18+ confirmed' : 'not gated'}`),
      el('div', { class: 'files' }, ...(rows.length ? rows : [el('p', { class: 'muted' }, 'no files yet')])),
    ),
    panel(
      el('h2', {}, 'Add a file'),
      el('label', {}, 'File (video or image)', fileInput),
      el('label', {}, publicToggle, ' Publish to the public feed (wrap under the portal key)'),
      el('div', { class: 'row' }, upload),
      status,
    ),
    panel(
      el('h2', {}, 'Player'),
      el('p', { class: 'muted' }, 'Pick a file above: ciphertext is fetched with a signed URL and decrypted here, in memory.'),
    ),
  );
}

async function playFile(f: FileSummary) {
  try {
    const c = await loadCrypto();
    const keys = await state.api.fileKeys(f.file_id);
    const userWrap = keys.keys.find((k) => k.wrap_type === 'user');
    if (!userWrap) throw new Error('no user-wrapped key on this file');
    const fek = await c.unwrapKey(state.ukek!, c.hexToBytes(userWrap.blob));

    const url = await state.api.fileUrl(f.file_id);
    const ciphertext = await state.api.getBytes(url.path);
    const plaintext = await c.decryptFile(fek, ciphertext);

    if (state.playerUrl) URL.revokeObjectURL(state.playerUrl);
    const blob = new Blob([plaintext as unknown as BlobPart], { type: f.mime });
    state.playerUrl = URL.createObjectURL(blob);

    const player = content.querySelectorAll('.panel');
    const last = player[player.length - 1];
    const video = el('video', { controls: true, autoplay: true, src: state.playerUrl });
    if (last) last.replaceChildren(el('h2', {}, `Now playing · ${bytes(plaintext.length)} decrypted`), video);
  } catch (err) {
    window.alert(showError(err));
  }
}

// ----------------------------------------------------------------------- boot

/**
 * A plain-http origin is not a broken install, but it is a mode with consequences:
 * the browser refuses install/offline (service workers need a secure context) and
 * may refuse clipboard access. Encryption itself no longer depends on it — the
 * crypto layer uses libsodium, not WebCrypto — so say what still works, once.
 */
function insecureBanner() {
  if (window.isSecureContext) return;
  const note = el(
    'div',
    { class: 'notice' },
    el('strong', {}, 'Plain HTTP. '),
    'Encryption and uploads work here, but installing to a home screen, offline caching ' +
      'and browser keychain storage need HTTPS. Put a certificate in front before real use.',
  );
  app.before(note);
}

async function boot() {
  applyBrand();
  await loadBrand(API_BASE);
  insecureBanner();
  setWho();

  if (location.hash.replace('#', '') === 'admin') {
    const { mountAdmin } = await import('./admin');
    mountAdmin(app);
    document.getElementById('who')!.textContent = 'operator';
    return;
  }

  const signupTab = el('button', { class: 'tab active' }, 'New account');
  const unlockTab = el('button', { class: 'tab secondary' }, 'Unlock');
  content = el('div');

  const select = (which: 'signup' | 'unlock') => {
    signupTab.className = `tab${which === 'signup' ? ' active' : ' secondary'}`;
    unlockTab.className = `tab${which === 'unlock' ? ' active' : ' secondary'}`;
    if (which === 'signup') renderSignup(content);
    else renderUnlock(content);
  };

  signupTab.addEventListener('click', () => select('signup'));
  unlockTab.addEventListener('click', () => select('unlock'));

  app.replaceChildren(el('div', { class: 'tabs' }, signupTab, unlockTab), content);
  document.getElementById('api-base')!.textContent = `api: ${API_BASE}`;
  select('signup');
}

window.addEventListener('hashchange', () => location.reload());
void boot();
