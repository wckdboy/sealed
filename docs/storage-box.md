# Attaching a Hetzner Storage Box

The short version: **do not mount it.** Local NVMe is the primary store, the box is
an off-box replica. `scripts/storagebox.sh` sets that up in one command.

## Why not a mount

| Problem with mounting (SMB/NFS/SSHFS) | Consequence |
|---|---|
| Hetzner documents SMB failures on files **over 4 GB** | this service accepts 20 GB uploads |
| A network filesystem in the write path | a box hiccup becomes a corrupted ciphertext blob |
| Latency on every range request | video seeking goes through the network twice |
| Latency/lock behaviour under concurrency | SQLite over a network FS is a corruption risk |

The box is 1 TB for €3.20/month (BX11) with 10 snapshots and 100 sub-accounts
*(verified)*. It is a replica target, not a disk.

## Attach it

```bash
# 1. one SSH key for the box, no passphrase (systemd cannot type)
ssh-keygen -t ed25519 -f ~/.ssh/vault_box -C vault-box
# 2. Hetzner console → Storage Box → Sub-accounts → create an *SSH* sub-account
#    (Samba/WebDAV sub-accounts cannot be used with rsync over SSH)
# 3. paste the public key into that sub-account
# 4. run the setup
sudo ./scripts/storagebox.sh setup \
  --host u123456.your-storagebox.de \
  --user u123456-sub1 \
  --key  ~/.ssh/vault_box \
  --data /var/lib/vault
```

`--dry-run` prints every file and command without touching anything.

What it creates:

| Thing | Why |
|---|---|
| `~/.ssh/config` alias `vaultbox`, **port 23** | rsync/SSH on a Storage Box is port 23, not 22 |
| remote `vault/{blobs,db,snapshots}` | one tree, obvious layout |
| `vault-rsync.timer` (nightly, `--delete-delay`) | `--delete-delay` removes only after a completed transfer, so an interrupted run cannot leave the mirror emptier than the source |
| `vault-borg.timer` (hourly, dedup) | the database is small and changes constantly; Borg dedupe makes hourly archives cheap and keeps 7 daily / 4 weekly / 6 monthly |

The secrets volume is **not** copied. Back it up separately (`docs/ops.md`): a
stolen copy of this box must never contain the pepper.

## Verify, then rehearse

```bash
sudo ./scripts/storagebox.sh verify
# connectivity, remote layout, mirror size, last rsync run, last 5 Borg archives
```

An unrehearsed backup is not a backup. Do this once, today:

```bash
sudo ./scripts/storagebox.sh restore-db --archive latest --to /tmp/vault.restored.db
sqlite3 /tmp/vault.restored.db 'select count(*) from accounts'
```

Two failure modes worth naming:

1. **Borg passphrase in `/etc/vault/borg.passphrase`** — keep a copy somewhere that
   is not the Storage Box, or the archives are ciphertext you own and cannot open.
2. **Firewall** — outbound `tcp/23` to the box only. If the firewall has no rule for
   it, the timer fails silently at 03:30 and nobody notices until a restore.

## Costs and growth

Blobs grow linearly with uploads. At 100 GB/day of uploads you outgrow BX11 in ten
days; check the box usage weekly (`du -sh vault/blobs` over SSH) and move to the next
size rather than letting rsync fail nightly. The database is megabytes for
thousands of accounts — keep it local and let Borg ship the copies.
