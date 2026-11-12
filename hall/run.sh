#!/usr/bin/env bash
# Hall of Shame batch runner. Runs `tattle run` over the curated list in hall/tools.json.
#
#   hall/run.sh [--allow-network] [--out DIR] [--only ID[,ID...]] [--dry-run]
#
# * Only runs tools already installed under hall/work/node_modules/.bin (or on PATH). It never
#   installs anything. Install by hand after confirming the package names in tools.json.
# * Probes are --version/--help only. Tools marked `network: true` are skipped without --allow-network.
# * Each tool gets its own TATTLE_HOME under DIR/<id>/ so receipts are easy to attribute.
# * This script makes no network calls itself. Nothing is published or posted.
# Then:  node hall/build-table.mjs DIR HALL_OF_SHAME.md
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$HERE/receipts"
ALLOW_NET=0
DRY=0
ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --allow-network) ALLOW_NET=1 ;;
    --dry-run) DRY=1 ;;
    --out) OUT="$2"; shift ;;
    --only) ONLY="$2"; shift ;;
    -h|--help) sed -n '2,13p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

TATTLE="$ROOT/dist/cli.js"
[ -f "$TATTLE" ] || { echo "build first: npm run build" >&2; exit 1; }

# portable timeout: GNU timeout, Homebrew gtimeout, or a perl alarm fallback
with_timeout() {
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then timeout "$secs" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$secs" "$@"
  else perl -e 'alarm shift; exec @ARGV' "$secs" "$@"; fi
}

# id<TAB>bin<TAB>network<TAB>timeout<TAB>args (JSON array)
ROWS="$(node -e '
const c = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
for (const t of c.tools) console.log([t.id, t.bin, t.network === true ? 1 : 0, t.timeoutSeconds ?? c.timeoutSeconds ?? 30, JSON.stringify(t.args ?? ["--version"])].join("\t"));
' "$HERE/tools.json")"

mkdir -p "$OUT"
ran=0; skipped=0; failed=0
while IFS=$'\t' read -r id bin net secs args; do
  [ -n "$id" ] || continue
  if [ -n "$ONLY" ] && ! [[ ",$ONLY," == *",$id,"* ]]; then continue; fi
  if [ "$net" = 1 ] && [ "$ALLOW_NET" != 1 ]; then echo "skip  $id (network: true, pass --allow-network)"; skipped=$((skipped+1)); continue; fi
  exe=""
  if [ -x "$HERE/work/node_modules/.bin/$bin" ]; then exe="$HERE/work/node_modules/.bin/$bin"
  elif command -v "$bin" >/dev/null 2>&1; then exe="$(command -v "$bin")"; fi
  if [ -z "$exe" ]; then echo "skip  $id ($bin not installed)"; skipped=$((skipped+1)); continue; fi
  mapfile_args=()
  while IFS= read -r a; do mapfile_args+=("$a"); done < <(node -e 'for (const a of JSON.parse(process.argv[1])) console.log(a)' "$args")
  if [ "$DRY" = 1 ]; then echo "dry   $id: tattle run --quiet -- $exe ${mapfile_args[*]}  (timeout ${secs}s)"; continue; fi
  home="$OUT/$id"
  rm -rf "$home"; mkdir -p "$home"
  echo "run   $id"
  TATTLE_HOME="$home" with_timeout "$secs" node "$TATTLE" run --quiet -- "$exe" "${mapfile_args[@]}" >"$home/stdout.txt" 2>"$home/stderr.txt"
  rc=$?
  if ls "$home"/receipts/*/receipt.json >/dev/null 2>&1; then ran=$((ran+1)); else echo "fail  $id (no receipt, exit $rc; see $home/stderr.txt)"; failed=$((failed+1)); fi
done <<< "$ROWS"
echo "done: ran=$ran skipped=$skipped failed=$failed -> $OUT"
echo "next: node hall/build-table.mjs \"$OUT\" HALL_OF_SHAME.md"
