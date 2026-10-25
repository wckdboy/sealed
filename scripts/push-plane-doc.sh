#!/usr/bin/env bash
# Push docs/instance-and-brand.md into Plane as a page.
#
# I (the agent) have no Plane credentials in this environment, so this script is
# the hand-off: it uses only documented Plane endpoints and fails loudly on any
# unexpected response instead of pretending it worked.
#
#   PLANE_API_KEY=plane_api_xxx PLANE_WORKSPACE=my-team \
#     scripts/push-plane-doc.sh --project <project_id>
#
#   PLANE_API_KEY=... PLANE_WORKSPACE=my-team scripts/push-plane-doc.sh --wiki
#
# Documented endpoints (developers.plane.so, checked 2026-10-25):
#   project page : POST /api/v1/workspaces/{slug}/projects/{id}/pages/
#                  body: name (required), description_html (required), access (0 public, 1 private)
#   workspace wiki page (v2): POST /api/v2/workspaces/{slug}/pages/
#   list wiki pages:          GET  /api/v1/workspaces/{slug}/pages/
#
# Auth: `X-API-Key: <personal access token>` (Profile Settings → Personal Access
# Tokens). Cloud base URL is https://api.plane.so; self-hosted instances need
# PLANE_BASE_URL set to their own origin.
set -euo pipefail

DOC="$(cd "$(dirname "$0")/.." && pwd)/docs/instance-and-brand.md"
BASE="${PLANE_BASE_URL:-https://api.plane.so}"
WS="${PLANE_WORKSPACE:-}"
KEY="${PLANE_API_KEY:-}"
MODE=""
TARGET=""
TITLE="Sealed — instance and brand charter"
ACCESS="${PLANE_PAGE_ACCESS:-1}"   # 1 = private by default

while [ $# -gt 0 ]; do
  case "$1" in
    --project) MODE=project; TARGET="${2:-}"; shift 2 ;;
    --wiki) MODE=wiki; shift ;;
    --title) TITLE="${2:-}"; shift 2 ;;
    --public) ACCESS=0; shift ;;
    --dry-run) MODE="${MODE:-wiki}"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -f "$DOC" ] || { echo "missing $DOC" >&2; exit 1; }
[ -n "$WS" ] || { echo "set PLANE_WORKSPACE (the slug in app.plane.so/<slug>/)" >&2; exit 1; }

# Minimal Markdown -> HTML. Good enough for headings, lists, code, tables, bold and
# inline code; deliberately not a general Markdown implementation.
TO_HTML=$(mktemp)
trap 'rm -f "$TO_HTML"' EXIT
python3 - "$DOC" > "$TO_HTML" <<'PY'
import html, re, sys

lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
out, para, in_code, in_list, table = [], [], False, None, []

def inline(s: str) -> str:
    s = html.escape(s, quote=False)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', s)
    return s

def flush_para():
    if para:
        out.append("<p>" + inline(" ".join(para)) + "</p>")
        para.clear()

def flush_table():
    global table
    if not table:
        return
    rows = [r for r in table if not re.match(r"^\|[\s:\-|]+\|$", r)]
    cells = [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows]
    out.append("<table><tbody>")
    for i, row in enumerate(cells):
        tag = "th" if i == 0 else "td"
        out.append("<tr>" + "".join(f"<{tag}>{inline(c)}</{tag}>" for c in row) + "</tr>")
    out.append("</tbody></table>")
    table = []

def flush_list():
    global in_list
    if in_list:
        out.append(f"</{in_list}>")
        in_list = None

for line in lines:
    if line.startswith("```"):
        flush_para(); flush_table(); flush_list()
        out.append("</code></pre>" if in_code else "<pre><code>")
        in_code = not in_code
        continue
    if in_code:
        out.append(html.escape(line))
        continue
    if line.startswith("|"):
        flush_para(); flush_list()
        table.append(line)
        continue
    flush_table()

    stripped = line.strip()
    if not stripped:
        flush_para(); flush_list()
        continue
    m = re.match(r"^(#{1,6})\s+(.*)$", stripped)
    if m:
        flush_para(); flush_list()
        level = len(m.group(1))
        out.append(f"<h{level}>{inline(m.group(2))}</h{level}>")
        continue
    if stripped.startswith("- ") or stripped.startswith("* "):
        flush_para()
        if in_list != "ul":
            flush_list(); out.append("<ul>"); in_list = "ul"
        item = stripped[2:]
        task = re.match(r"^\[( |x)\]\s*(.*)$", item)
        if task:
            box = "☑" if task.group(1) == "x" else "☐"
            item = f"{box} {task.group(2)}"
        out.append(f"<li>{inline(item)}</li>")
        continue
    m = re.match(r"^\d+\.\s+(.*)$", stripped)
    if m:
        flush_para()
        if in_list != "ol":
            flush_list(); out.append("<ol>"); in_list = "ol"
        out.append(f"<li>{inline(m.group(1))}</li>")
        continue
    if stripped.startswith(">"):
        flush_para(); flush_list()
        out.append(f"<blockquote>{inline(stripped.lstrip('> '))}</blockquote>")
        continue
    if in_list:
        flush_list()
    para.append(stripped)

flush_para(); flush_table(); flush_list()
print("\n".join(out))
PY

BODY_FILE=$(mktemp)
trap 'rm -f "$TO_HTML" "$BODY_FILE"' EXIT
python3 - "$TO_HTML" "$TITLE" "$ACCESS" > "$BODY_FILE" <<'PY'
import json, sys
html_body = open(sys.argv[1], encoding="utf-8").read()
print(json.dumps({"name": sys.argv[2], "description_html": html_body, "access": int(sys.argv[3])}))
PY

if [ -z "${PLANE_API_KEY:-}" ]; then
  echo "PLANE_API_KEY is not set. Create one in Plane: Profile Settings → Personal Access Tokens." >&2
  echo "Rendered $(wc -c < "$TO_HTML") bytes of HTML from $DOC:" >&2
  echo "  (dry run — nothing was sent)" >&2
  echo "  title: $TITLE"
  echo "  target: ${MODE}${TARGET:+ / $TARGET} on $BASE workspace $WS"
  exit 0
fi

case "$MODE" in
  project)
    [ -n "$TARGET" ] || { echo "--project needs a project id" >&2; exit 2; }
    URL="$BASE/api/v1/workspaces/$WS/projects/$TARGET/pages/"
    ;;
  wiki)
    URL="$BASE/api/v2/workspaces/$WS/pages/"
    ;;
  *)
    echo "choose --project <id> or --wiki" >&2; exit 2 ;;
esac

echo "POST $URL"
RESP=$(mktemp)
CODE=$(curl -sS -o "$RESP" -w '%{http_code}' -X POST "$URL" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  --data-binary "@$BODY_FILE")

echo "HTTP $CODE"
if [ "$CODE" -lt 200 ] || [ "$CODE" -ge 300 ]; then
  echo "Plane rejected the request. Response:" >&2
  head -c 2000 "$RESP" >&2
  rm -f "$RESP"
  exit 1
fi

python3 - "$RESP" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print("created page id:", d.get("id"))
print("name:", d.get("name"))
print("workspace/project:", d.get("workspace") or d.get("project_id"))
PY
rm -f "$RESP"
echo "Verify in Plane, and read it back once to confirm the body landed (the API accepts"
echo "writes without echoing the rendered HTML back)."
