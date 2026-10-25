# Trust & Safety runbook

Print this. Rehearse it once before launch. Every step is timestamped in
`mod_log`; if it is not in `mod_log`, it did not happen.

## 0. What the system gives you

- `POST /v1/reports` with `reason=csam|underage` **auto-quarantines** the file and
  freezes the uploader's account immediately (no human in the loop).
- A hash match at upload **refuses the upload**, increments strikes, bans the
  account, and writes `mod_log(action='quarantine_on_hash_match')`.
- Quarantined files are unservable: `GET /v1/blobs/...` returns 404 for any
  non-`ready` status, even with a valid signature.
- Nothing is deleted automatically. Evidence retention is manual and deliberate.

### Queries you will need

```sql
-- open reports, newest first
SELECT id, file_id, reason, created_at, state FROM reports
 WHERE state = 'open' ORDER BY created_at DESC;
-- everything that happened to a file
SELECT * FROM mod_log WHERE subject = ? ORDER BY created_at DESC;
-- a frozen account's files
SELECT f.id, f.status, f.plaintext_size, f.created_at
  FROM files f JOIN accounts a ON a.id = f.owner_id
 WHERE a.ban_flag = 1 ORDER BY f.created_at DESC;
-- counts for the weekly report (no digests, no user ids)
SELECT reason, COUNT(*) FROM reports WHERE created_at > strftime('%s','now','-7 days') GROUP BY reason;
```

## 1. CSAM report or hash match (act within 1 hour)

1. **Confirm the quarantine is in place** (status `quarantined`, account
   `ban_flag = 1`). If it is not, quarantine by hand:
   ```sql
   UPDATE files SET status='quarantined' WHERE id = ?;
   UPDATE accounts SET ban_flag=1, strikes=strikes+1 WHERE id = (SELECT owner_id FROM files WHERE id = ?);
   INSERT INTO mod_log (actor, action, subject, evidence_ref, detail, created_at)
   VALUES ('<you>', 'manual_quarantine', ?, NULL, 'manual step 1', strftime('%s','now'));
   ```
2. **Do not download, view, or forward the file.** You cannot decrypt a private
   file, and you must not try. For a *public* file you hold the PKEK; do not use
   it for this — the hash/report is the evidence.
3. **Preserve:** copy the `files` row, `file_keys` rows, `mod_log` rows, and the
   ciphertext blob to the legal-hold location. Keep them for **90 days** minimum,
   longer if instructed by counsel or law enforcement.
4. **Report** to NCMEC CyberTipline (`https://report.cybertip.org`) with: the
   file id, the plaintext digest we received, timestamps, uploader account number
   (an identifier, not a person), and the fact that the content is
   client-side-encrypted and was matched by hash or reported by a user. Attach
   the preserved metadata, not the file.
5. **Log the report** in `mod_log` with the CyberTipline reference as
   `evidence_ref`, then set `reports.state='actioned'`.
6. **Never** contact the uploader about the content. The account is frozen;
   support answers only "this account is under review".
7. If law enforcement makes a preservation request: preserve, do not disclose,
   escalate to counsel. We cannot decrypt private files and must say so in
   writing.

## 2. Non-consensual intimate imagery (NCII) report

1. Quarantine the file (`status='quarantined'`), do **not** ban on first report.
2. Notify the uploader: one line, no detail, 24 h to respond.
3. If upheld: ban, keep quarantined, `mod_log(action='ncii_upheld')`.
4. Owner request ("take my image down"): action within 24 h, no argument, no
   proof demand beyond a plausible statement. Mark `status='dead'`.
5. If the reporter supplies the original: hash both versions into the local deny
   list so re-uploads are caught (`VAULT_HASH_LISTS` entry, restart or reload).

## 3. Copyright / DMCA notice

1. Acknowledge within 48 h (the `/dmca` page states this).
2. Log the notice verbatim in `mod_log(action='dmca_notice')` with the requester's
   reference as `evidence_ref`.
3. Quarantine → verify the notice has all six §512 elements → mark `dead`.
4. Counter-notice: 10 business days, then restore unless the claimant filed suit.
5. Repeat infringers: 3 strikes = ban, per ToS.

## 4. Abuse that is not illegal

Spam, scraping, hotlinking, quota evasion: no evidence preservation needed.
Throttle, warn, then ban. Log with `action='abuse'`.

## 5. Weekly hygiene

- Count open reports; anything older than 72 h is a failure.
- Check `mod_log` for `quarantine_on_hash_match` — any hit means the hash lists
  are working; zero hits for a month means the lists are probably stale.
- Verify `VAULT_HASH_LISTS` files were updated (check mtime vs the feed's
  publication date).
- Sample 10 public files and confirm the 18+ gate is actually being enforced
  (`GET /v1/p/<id>` without a session must be 403).

## 6. What you must never do

- Never decrypt a reported file to "check" it.
- Never delete ciphertext before the retention window ends — it is the only
  evidence that the file existed and what it hashed to.
- Never promise a user that content is unrecoverable while a wrapped key exists
  server-side (the recovery blob is exactly that).
- Never tell a claimant "we cannot see it, so we cannot act". We act on hashes,
  reports, and account behaviour; that is the whole design.
