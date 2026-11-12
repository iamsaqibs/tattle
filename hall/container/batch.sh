#!/usr/bin/env bash
# Runs INSIDE the container. For each tool in tools.json: install it (observed), then run each probe
# observed, with an empty HOME, stdin from /dev/null, a timeout and no credentials.
# usage: hall-batch [ID,ID...]     output: /out/<id>/ (one TATTLE_HOME per tool) + /out/run.log
set -u
ONLY="${1:-}"
OUT=/out
mkdir -p "$OUT"
LOG="$OUT/run.log"; [ -n "$ONLY" ] || : >"$LOG"
TMO="${PROBE_TIMEOUT:-60}"        # per probe
INSTALL_TMO="${INSTALL_TIMEOUT:-300}"  # installs of large packages exceed 60s
ROWS="$(node -e '
const c = JSON.parse(require("fs").readFileSync("/opt/hall/tools.json", "utf8"));
for (const t of c.tools) console.log([t.id, t.package, t.bin, JSON.stringify(t.probes)].join("\t"));
')"
while IFS=$'\t' read -r id pkg bin probes; do
  [ -n "$id" ] || continue
  if [ -n "$ONLY" ] && ! [[ ",$ONLY," == *",$id,"* ]]; then continue; fi
  tdir="$OUT/$id"; rm -rf "$tdir"; mkdir -p "$tdir"
  prefix="/opt/hall/prefix/$id"; mkdir -p "$prefix"
  run() { # name, then command... (install uses INSTALL_TMO) ; fresh empty HOME each time
    local name="$1"; shift
    local h; h="$(mktemp -d /tmp/home.XXXXXX)"
    env -i PATH="$prefix/bin:/usr/local/bin:/usr/bin:/bin" HOME="$h" TERM=dumb TATTLE_HOME="$tdir" \
      npm_config_prefix="$prefix" NO_COLOR=1 \
      timeout --kill-after=5 "$([ "$name" = install ] && echo "$INSTALL_TMO" || echo "$TMO")" tattle run --quiet -- "$@" </dev/null >"$tdir/$name.stdout" 2>"$tdir/$name.stderr"
    local rc=$?
    echo "$id	$name	exit=$rc" | tee -a "$LOG"
    rm -rf "$h"
  }
  run install npm install -g "$pkg"
  if [ ! -e "$prefix/bin/$bin" ]; then echo "$id	NOTE	$bin not found after install; probes skipped" | tee -a "$LOG"; continue; fi
  for name in $(node -e 'console.log(Object.keys(JSON.parse(process.argv[1])).join(" "))' "$probes"); do
    mapfile -t pargs < <(node -e 'for (const a of JSON.parse(process.argv[1])[process.argv[2]]) console.log(a)' "$probes" "$name")
    run "$name" "$bin" "${pargs[@]}"
  done
done <<< "$ROWS"
echo "batch finished" | tee -a "$LOG"
