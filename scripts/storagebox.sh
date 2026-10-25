#!/usr/bin/env bash
# Attach a Hetzner Storage Box to the VPS as a *replica*, not as live storage.
#
# Why not mount it: Hetzner documents SMB failures on files over 4 GB and this
# service accepts 20 GB uploads; a network filesystem in the write path also turns
# every disk hiccup into a corrupted ciphertext blob. So: local NVMe is the primary,
# the box holds an rsync mirror of the blobs plus Borg archives of the database.
#
# SSH/rsync/Borg reach a Storage Box on **port 23**, not 22, and only sub-accounts of
# type SSH are usable for this.
#
#   ./scripts/storagebox.sh setup  --host u123456.your-storagebox.de \
#                                  --user u123456-sub1 --key ~/.ssh/vault_box
#   ./scripts/storagebox.sh verify
#
# `setup` is idempotent and prints what it would do with --dry-run.

set -euo pipefail

PROG=$(basename "$0")
DATA_DIR=${VAULT_DATA_DIR:-/var/lib/vault}
REMOTE_ROOT=${VAULT_BOX_ROOT:-vault}
ALIAS=vaultbox
BORG_PASSPHRASE_FILE=${BORG_PASSPHRASE_FILE:-/etc/vault/borg.passphrase}

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warn\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m error\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [[ ${DRY_RUN:-0} == 1 ]]; then printf '    would run: %s\n' "$*"; else "$@"; fi; }

# write_file PATH < content — shows the file under --dry-run instead of writing it.
write_file() {
  local path=$1
  if [[ ${DRY_RUN:-0} == 1 ]]; then
    printf '    would write %s:\n' "$path"
    sed 's/^/      /'
  else
    cat > "$path"
  fi
}

# append_file PATH < content
append_file() {
  local path=$1
  if [[ ${DRY_RUN:-0} == 1 ]]; then
    printf '    would append to %s:\n' "$path"
    sed 's/^/      /'
  else
    cat >> "$path"
  fi
}

usage() {
  cat <<EOF
$PROG — attach a Hetzner Storage Box as an off-box replica

  $PROG setup --host HOST --user USER [--key PATH] [--data DIR] [--dry-run]
  $PROG verify
  $PROG restore-db --archive NAME [--to FILE]

setup creates the SSH alias, the remote layout, and two systemd timers
(blobs nightly via rsync, database via Borg). Nothing is mounted.
EOF
}

need() {
  command -v "$1" >/dev/null 2>&1 && return 0
  if [[ ${DRY_RUN:-0} == 1 ]]; then warn "$1 not installed (fine for a dry run)"; return 0; fi
  die "$1 is required but not installed (apt install $1)"
}

cmd_setup() {
  local host='' user='' key="$HOME/.ssh/id_ed25519"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --host) host=${2:?}; shift 2;;
      --user) user=${2:?}; shift 2;;
      --key)  key=${2:?}; shift 2;;
      --data) DATA_DIR=${2:?}; shift 2;;
      --dry-run) DRY_RUN=1; shift;;
      *) die "unknown option $1";;
    esac
  done
  [[ -n $host && -n $user ]] || { usage; exit 2; }
  need ssh; need rsync
  [[ -f $key ]] || die "ssh key not found: $key (create one: ssh-keygen -t ed25519 -f $key -C vault-box)"
  [[ -d $DATA_DIR ]] || die "data dir not found: $DATA_DIR (set --data or VAULT_DATA_DIR)"

  log "1/5  ~/.ssh/config alias '$ALIAS' (port 23, key auth, no agent forwarding)"
  local ssh_cfg="$HOME/.ssh/config"
  run mkdir -p "$HOME/.ssh"; run chmod 700 "$HOME/.ssh"
  if grep -q "^Host $ALIAS$" "$ssh_cfg" 2>/dev/null; then
    log "     alias already present, leaving it alone"
  else
    append_file "$ssh_cfg" <<EOF

Host $ALIAS
    HostName $host
    User $user
    Port 23
    IdentityFile $key
    IdentitiesOnly yes
    StrictHostKeyChecking accept-new
    ServerAliveInterval 30
EOF
    run chmod 600 "$ssh_cfg"
  fi

  log "2/5  connectivity on port 23"
  if [[ ${DRY_RUN:-0} == 1 ]]; then
    printf '    would run: ssh %s true\n' "$ALIAS"
  else
    ssh "$ALIAS" true || die "cannot reach $host:23 as $user — check the sub-account type (must be SSH) and that the key is authorised"
    log "     ok"
  fi

  log "3/5  remote layout: $REMOTE_ROOT/{blobs,db,snapshots}"
  for d in blobs db snapshots; do
    run ssh "$ALIAS" "mkdir -p $REMOTE_ROOT/$d"
  done

  log "4/5  blobs: nightly rsync mirror (delete-delay, no --delete before transfer)"
  write_file /etc/systemd/system/vault-rsync.service <<EOF
[Unit]
Description=Mirror vault blobs to the Storage Box
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
# --delete-delay deletes only after the transfer completes, so an interrupted run
# cannot leave the mirror emptier than the source.
ExecStart=/usr/bin/rsync -a --delete-delay --partial --info=stats1 --no-owner --no-group \\
    $DATA_DIR/blobs/ $ALIAS:$REMOTE_ROOT/blobs/
Nice=10
IOSchedulingClass=idle

[Install]
WantedBy=multi-user.target
EOF
  write_file /etc/systemd/system/vault-rsync.timer <<EOF
[Unit]
Description=Nightly blob mirror to the Storage Box

[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF

  log "5/5  database: Borg archive with retention (encrypted at rest on the box)"
  if ! command -v borg >/dev/null 2>&1; then
    warn "borg is not installed — skipping the database timer (apt install borgbackup)"
  else
    if [[ ! -f $BORG_PASSPHRASE_FILE ]]; then
      warn "no $BORG_PASSPHRASE_FILE: create it with 'openssl rand -base64 32 > $BORG_PASSPHRASE_FILE && chmod 600 $BORG_PASSPHRASE_FILE'"
      warn "store a copy of that passphrase somewhere that is NOT the Storage Box, or the archives are unreadable"
    fi
    write_file /etc/systemd/system/vault-borg.service <<EOF
[Unit]
Description=Borg archive of the vault database
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=BORG_PASSCOMMAND=cat $BORG_PASSPHRASE_FILE
Environment=BORG_REPO=ssh://$ALIAS/./$REMOTE_ROOT/db
ExecStartPre=-/usr/bin/borg init --encryption=repokey-blake2
ExecStart=/usr/bin/borg create --stats --compression zstd,8 ::{now:%Y-%m-%dT%H:%M} $DATA_DIR/vault.db
ExecStartPost=/usr/bin/borg prune --keep-daily 7 --keep-weekly 4 --keep-monthly 6
EOF
    write_file /etc/systemd/system/vault-borg.timer <<EOF
[Unit]
Description=Hourly-incremental database archive (Borg dedupes)

[Timer]
OnCalendar=*-*-* *:15:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
  fi

  log "enabling timers"
  run systemctl daemon-reload
  run systemctl enable --now vault-rsync.timer
  [[ -x /usr/bin/borg ]] && run systemctl enable --now vault-borg.timer

  cat <<EOF

Done. Two rules that make this a backup instead of a decoration:

  1. Run the restore once, now:  $PROG restore-db --archive latest
  2. Keep a copy of $BORG_PASSPHRASE_FILE somewhere that is not the Storage Box.

The secrets volume is deliberately NOT copied here. Back it up separately
(docs/ops.md): a stolen backup of the box must never contain the pepper.
EOF
}

cmd_verify() {
  need ssh
  log "connectivity"
  ssh -o BatchMode=yes "$ALIAS" "echo ok from \$(hostname)" || die "unreachable"
  log "layout"
  ssh "$ALIAS" "ls -la $REMOTE_ROOT 2>/dev/null" || warn "no $REMOTE_ROOT yet — run setup"
  log "blob mirror size"
  ssh "$ALIAS" "du -sh $REMOTE_ROOT/blobs 2>/dev/null || true"
  log "last rsync run"
  systemctl status vault-rsync.service --no-pager -n 3 2>/dev/null || warn "no vault-rsync.service"
  if command -v borg >/dev/null 2>&1; then
    log "borg archives"
    BORG_PASSCOMMAND="cat $BORG_PASSPHRASE_FILE" BORG_REPO="ssh://$ALIAS/./$REMOTE_ROOT/db" \
      borg list --last 5 2>/dev/null || warn "cannot list archives (missing borg, passphrase, or repo)"
  fi
}

cmd_restore_db() {
  local archive='' to="$DATA_DIR/vault.restored.db"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --archive) archive=${2:?}; shift 2;;
      --to) to=${2:?}; shift 2;;
      *) die "unknown option $1";;
    esac
  done
  [[ -n $archive ]] || { usage; exit 2; }
  need borg
  log "extracting vault.db from $archive to $to"
  local tmp; tmp=$(mktemp -d)
  BORG_PASSCOMMAND="cat $BORG_PASSPHRASE_FILE" BORG_REPO="ssh://$ALIAS/./$REMOTE_ROOT/db" \
    borg extract --list --target "$tmp" "::$archive" "${DATA_DIR#/}/vault.db"
  mv "$tmp${DATA_DIR}/vault.db" "$to"
  rm -rf "$tmp"
  log "restored to $to — verify with: sqlite3 $to 'select count(*) from accounts'"
}

case "${1:-}" in
  setup) shift; cmd_setup "$@";;
  verify) shift; cmd_verify "$@";;
  restore-db) shift; cmd_restore_db "$@";;
  -h|--help|'') usage;;
  *) die "unknown command $1 (see --help)";;
esac
