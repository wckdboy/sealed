#!/usr/bin/env bash
# Publish this codebase to the public mirror under its neutral brand.
#
#   scripts/publish-public.sh git@github.com:OWNER/NAME.git [--verify] [--dry-run]
#
# The mirror is a build artefact, never a place to edit (ADR 0010):
#   * content comes from `git archive HEAD`, so only committed files ship;
#   * brand/public.json replaces brand/brand.json, the public README is rendered
#     from brand/README.public.md, the private business plan is dropped;
#   * remaining brand prose is rewritten and the script FAILS if any survives;
#   * --verify runs the Rust and web test suites inside the mirror before pushing.
#
# Never point this at the private repo. It force-pushes.
set -euo pipefail

REMOTE="${1:-}"
shift || true
VERIFY=0
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --verify) VERIFY=1 ;;
    --dry-run) DRY_RUN=1 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done
if [ -z "$REMOTE" ]; then
  echo "usage: $0 <git-remote-url> [--verify] [--dry-run]" >&2
  exit 2
fi

SRC="$(git rev-parse --show-toplevel)"
cd "$SRC"

if ! git diff --quiet HEAD -- 2>/dev/null; then
  echo "warning: working tree has changes; only committed content is published" >&2
fi

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

echo "==> exporting HEAD"
git archive HEAD | tar -x -C "$OUT"

echo "==> applying public brand"
cp "$OUT/brand/public.json" "$OUT/brand/brand.json"
rm -f "$OUT/brand/public.json"
# Not part of the public product: the commercial plan, and the instance/brand
# charter (it names Sealed as the official instance, which the mirror must not do).
rm -f "$OUT/docs/MASTER-PLAN.md"
rm -f "$OUT/docs/instance-and-brand.md"

echo "==> rendering README + rewriting brand prose"
python3 - "$OUT" <<'PY'
import json, pathlib, re, sys

out = pathlib.Path(sys.argv[1])
brand = json.loads((out / "brand/brand.json").read_text())
name, app = brand["name"], brand["app"]
slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
owner_host = brand["homepage"].split("//")[-1].strip("/")

subs = [
    ("Sealed", name),
    ("Sealed", app),
    ("example.invalid", owner_host),
    ("api.example.invalid", f"api.{owner_host}"),
    ("sealed", slug),
    ("SEALED", name.upper()),
    ("sealed", slug),
    ("sealed", slug),
]

text_ext = {".rs", ".ts", ".js", ".json", ".md", ".toml", ".yml", ".yaml", ".kts",
            ".kt", ".xml", ".html", ".css", ".txt", ".sh", ".example", ""}
skip_dirs = {"target", "node_modules", ".git", "dist", ".conformance"}

for path in out.rglob("*"):
    if path.is_dir() or any(p in skip_dirs for p in path.parts):
        continue
    if path.suffix.lower() not in text_ext and path.name not in {".gitignore", ".dockerignore", "Makefile", "Dockerfile"}:
        continue
    try:
        text = path.read_text()
    except (UnicodeDecodeError, OSError):
        continue
    original = text
    for a, b in subs:
        text = text.replace(a, b)
    if text != original:
        path.write_text(text)

readme = (out / "brand/README.public.md").read_text()
readme = (readme.replace("{{NAME}}", name)
                .replace("{{APP}}", app)
                .replace("{{SLUG}}", slug)
                .replace("{{TAGLINE}}", brand["tagline"][:1].upper() + brand["tagline"][1:]))
(out / "README.md").write_text(readme)
(out / "brand/README.public.md").unlink()
print(f"    brand: {name} / {app} (slug {slug})")
PY

echo "==> scanning for surviving brand strings"
if grep -rniE "sealed|sealed" "$OUT" \
     --exclude-dir={target,node_modules,dist,.conformance} \
     --exclude=LICENSE > /tmp/brand-residual.txt 2>/dev/null; then
  echo "FAIL: brand strings survived the rename:" >&2
  head -20 /tmp/brand-residual.txt >&2
  exit 1
fi
echo "    clean"

if [ "$VERIFY" = "1" ]; then
  echo "==> verifying the mirror builds and passes its own tests"
  # Reuse one target dir across publishes: the mirror lives in a throwaway path, so
  # without this every verification recompiles the whole dependency graph (~6 min).
  MIRROR_TARGET="${MIRROR_CARGO_TARGET:-${XDG_CACHE_HOME:-$HOME/.cache}/vault-mirror-target}"
  mkdir -p "$MIRROR_TARGET"
  ( cd "$OUT" && CARGO_TARGET_DIR="$MIRROR_TARGET" cargo test --all --quiet )
  ( cd "$OUT/web" && npm ci --no-audit --no-fund >/dev/null && npx tsc --noEmit && npx vitest run --silent )
  echo "    mirror verified"
fi

echo "==> committing"
SHORT="$(git -C "$SRC" rev-parse --short HEAD)"
( cd "$OUT"
  git init -q -b main
  git add -A
  if [ -n "${PUBLISH_GIT_NAME:-}" ] && [ -n "${PUBLISH_GIT_EMAIL:-}" ]; then
    git -c user.name="$PUBLISH_GIT_NAME" -c user.email="$PUBLISH_GIT_EMAIL" \
        commit -q -m "sync: upstream $SHORT"
  else
    git commit -q -m "sync: upstream $SHORT"
  fi
)

if [ "$DRY_RUN" = "1" ]; then
  echo "==> dry run: mirror prepared at $OUT (not pushed)"
  trap - EXIT
  exit 0
fi

echo "==> pushing to $REMOTE"
git -C "$OUT" remote add origin "$REMOTE" 2>/dev/null || git -C "$OUT" remote set-url origin "$REMOTE"
git -C "$OUT" push -f origin main
echo "done: $(git -C "$OUT" rev-parse --short HEAD) -> $REMOTE"
