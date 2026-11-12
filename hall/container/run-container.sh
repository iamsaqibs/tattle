#!/usr/bin/env bash
# Host launcher. Builds the throwaway image and runs the batch in it. Mounts ONLY hall/work/container-out.
# No home dir, no credentials, no host env vars. Receipts stay local (hall/work is gitignored).
#   DOCKER=/path/to/docker hall/container/run-container.sh [--build-only] [ID,ID...]
set -eu
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DOCKER="${DOCKER:-docker}"
W="$ROOT/hall/work"; OUTD="$W/container-out"
git -C "$ROOT" check-ignore -q "$OUTD" || { echo "refusing: $OUTD is not gitignored" >&2; exit 1; }
(cd "$ROOT" && npm run build >/dev/null && npm pack --pack-destination "$W" >/dev/null)
CTX="$W/image-ctx"; rm -rf "$CTX"; mkdir -p "$CTX"
cp "$W"/iamsaqibs-tattle-*.tgz "$CTX/tattle.tgz"
cp "$HERE/Dockerfile" "$HERE/batch.sh" "$ROOT/hall/tools.json" "$CTX/"
"$DOCKER" build -t tattle-hall:local "$CTX"
"$DOCKER" image inspect --format '{{.Id}}' tattle-hall:local > "$W/image-digest.txt"
[ "${1:-}" = "--build-only" ] && exit 0
mkdir -p "$OUTD"
"$DOCKER" run --rm --pull=never -v "$OUTD:/out" tattle-hall:local "${1:-}"
