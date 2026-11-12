#!/usr/bin/env bash
# Hostname allowlist stage: records which host forms a network rule accepts,
# then measures the shape that filters by hostname (loopback CONNECT proxy).
#
# Host-side checks: a hostname, literal IP, or CIDR in a network rule is
# rejected at render, so safehouse exits. Those are recorded as denials.
#
# Sandbox checks: with profiles/allowlist.sb loaded, egress is closed except for
# the resolver socket and 127.0.0.1:18090, where tools/proxy-allowlist.py runs on
# the host. Allowlisted hostnames tunnel through it; everything else fails.
#
# Exit code 0 = every expectation held.

set -u

PKG="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$PKG/rig/allowlist"
PROXY="$PKG/tools/proxy-allowlist.py"
PROFILE="$PKG/profiles/allowlist.sb"
PORT=18090
ALLOW="captive.apple.com"
RESULTS="$STAGE/results.txt"
SVER="$(safehouse --version 2>/dev/null | awk '{print $NF}')"

[ "$(uname -s)" = "Darwin" ] || { echo "FAIL: macOS required"; exit 1; }
command -v safehouse >/dev/null || { echo "FAIL: safehouse not on PATH"; exit 1; }
command -v python3 >/dev/null || { echo "FAIL: python3 not on PATH"; exit 1; }

mkdir -p "$STAGE"
: > "$RESULTS"

PASS=0; FAIL=0; FAILED=""

judge() { # expect name rc snippet cmd
  local exp="$1" name="$2" rc="$3" snip="$4" cmd="$5" outcome show line
  case "$exp" in
    allow) [ "$rc" -eq 0 ] && outcome=PASS || outcome=FAIL ;;
    deny)  [ "$rc" -ne 0 ] && outcome=PASS || outcome=FAIL ;;
  esac
  show="$(printf '%s' "$snip" | tr '\t\n' '  ' | head -c 140)"
  [ -n "$show" ] || show="(no output)"
  if [ "$outcome" = PASS ]; then PASS=$((PASS+1)); else
    FAIL=$((FAIL+1)); FAILED="$FAILED
  FAIL[$exp/$name] rc=$rc $show"
  fi
  line="$(printf 'P\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "S-ALLOWLIST" "$name" "$exp" "$rc" "$outcome" "$show" "$cmd")"
  printf '%s\n' "$line" >> "$RESULTS"
  printf '%-4s %-45s %s\n' "$outcome" "$name" "$show"
}

run() { # expect name command
  local exp="$1" name="$2" cmd="$3" out rc
  out="$(cd "$STAGE" && safehouse --append-profile="$PROFILE" -- /bin/sh -c "$cmd" 2>&1)"
  rc=$?
  judge "$exp" "$name" "$rc" "$(printf '%s' "$out" | tail -2)" "$cmd"
}

render() { # expect name rule  (host-side policy render)
  local exp="$1" name="$2" rule="$3" file out rc
  file="$STAGE/render-$(printf '%s' "$name" | tr ' ' '-').sb"
  printf '(deny network-outbound (remote ip))\n%s\n' "$rule" > "$file"
  out="$(safehouse --append-profile="$file" -- true 2>&1)"; rc=$?
  if [ "$exp" = deny ] && printf '%s' "$out" | grep -q "host must be \* or localhost"; then
    rc=1
  elif [ "$exp" = deny ]; then
    rc=0
  fi
  judge "$exp" "$name" "$rc" "$out" "safehouse --append-profile=$rule -- true"
}

if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
  echo "FAIL: 127.0.0.1:$PORT is already in use; stop that listener first"
  exit 1
fi

echo "proxy: allow=$ALLOW on 127.0.0.1:$PORT"
python3 "$PROXY" --port "$PORT" --allow "$ALLOW" > "$STAGE/proxy.log" 2>&1 &
PROXY_PID=$!
trap 'kill "$PROXY_PID" 2>/dev/null' EXIT INT TERM

READY=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then READY=1; break; fi
  sleep 0.3
done
[ "$READY" = 1 ] || { echo "FAIL: proxy did not start; see ${STAGE#"$PKG"/}/proxy.log"; exit 1; }

echo "== host forms a network rule accepts"
render deny "hostname in a network rule" '(allow network-outbound (remote ip "captive.apple.com:443"))'
render deny "literal IP in a network rule" '(allow network-outbound (remote ip "17.253.254.8:443"))'
render deny "CIDR in a network rule" '(allow network-outbound (remote ip "17.253.0.0/16:443"))'

echo "== what works: allowlist enforced at the loopback proxy"
run allow "curl via proxy: allowlisted host" \
  "HTTPS_PROXY=http://127.0.0.1:$PORT curl -sS --max-time 12 -o /dev/null -w '%{http_code}\n' https://captive.apple.com"
run deny  "curl via proxy: host not on the list" \
  "HTTPS_PROXY=http://127.0.0.1:$PORT curl -sS --max-time 12 -o /dev/null -w '%{http_code}\n' https://opencode.ai"
run deny  "curl direct: proxy bypassed" \
  "curl -sS --max-time 8 -o /dev/null -w '%{http_code}\n' https://captive.apple.com"
run allow "python urllib via proxy" \
  "HTTPS_PROXY=http://127.0.0.1:$PORT python3 -c 'import urllib.request;print(urllib.request.urlopen(\"https://captive.apple.com\",timeout=10).status)'"
run allow "python resolves the allowlisted hostname" \
  "python3 -c 'import socket;print(socket.gethostbyname(\"captive.apple.com\"))'"
run allow "proxy port reachable" \
  "nc -z -G 3 127.0.0.1 $PORT && echo OPEN"
run deny  "other loopback port closed" \
  "nc -z -G 3 127.0.0.1 18091 && echo OPEN"
run deny  "raw TCP to port 22" \
  "nc -z -G 3 github.com 22 && echo OPEN"

mkdir -p "$PKG/reports"
"$PKG/tools/gen-report.sh" "$RESULTS" "$PKG/reports/eval-report-${SVER}-allowlist.csv" "$SVER" "$PKG/rig"

printf 'summary: pass=%d fail=%d\n' "$PASS" "$FAIL"
[ -n "$FAILED" ] && printf 'FAILED PROBES:%s\n' "$FAILED"
[ "$FAIL" -eq 0 ] || { echo "ALLOWLIST EVAL FAILED"; exit 1; }
echo "ALLOWLIST EVAL PASSED"
