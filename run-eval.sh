#!/usr/bin/env bash
# agent-safehouse-eval: validate Agent Safehouse claims as a runnable eval.
# Simulates a system with a fake home directory inside this package, seeds it
# with FAKE credentials only, runs a ~200-probe battery of unique checks inside
# `safehouse bash`, and judges every probe against the claim it tests.
#
# Requirements: macOS + Agent Safehouse (`brew install eugene1g/safehouse/agent-safehouse`).
# Touches nothing outside this directory except /tmp and the Darwin temp dir.
# Output rule: never emit the runner's username. The package prefix is stripped
# from every emitted path (rig/..., reports/...) and the real home folds into ~.
# Exit code: 0 = every probe matched its expectation, 1 = at least one failed.

set -u

# Flags:
#   --cleanup              move the rig into rig/.trash/ after the run
#   --version V            label the run with version V (report file name).
#                          Defaults to what `safehouse --version` reports.
#                          A mismatch with the installed binary is a warning,
#                          not an error.
VERSION_ARG=""
CLEANUP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --cleanup) CLEANUP=1 ;;
    --version=*) VERSION_ARG="${1#--version=}" ;;
    --version)
      shift
      [ $# -gt 0 ] || { echo "FAIL: --version needs a value"; exit 1; }
      VERSION_ARG="$1"
      ;;
    *) echo "FAIL: unknown argument: $1 (usage: ./run-eval.sh [--version V] [--cleanup])"; exit 1 ;;
  esac
  shift
done

PKG="$(cd "$(dirname "$0")" && pwd)"
RIG="$PKG/rig"
FAKEHOME="$RIG/home"
WORK="$RIG/work"
SIBLING="$RIG/sibling"
TRASH="$RIG/.trash"
RESULTS="$RIG/results.txt"
OVERRIDE_SRC="$PKG/profiles/override.sb"
BATTERY="$PKG/probes/battery.sh"
REPORTS="$PKG/reports"

banner() { printf '\n== %s\n' "$1"; }

banner "preconditions"
[ "$(uname -s)" = "Darwin" ] || { echo "FAIL: macOS required"; exit 1; }
command -v safehouse >/dev/null || { echo "FAIL: safehouse not on PATH (brew install eugene1g/safehouse/agent-safehouse)"; exit 1; }
command -v sandbox-exec >/dev/null || { echo "FAIL: sandbox-exec not found"; exit 1; }
[ "$(id -u)" -ne 0 ] || { echo "FAIL: run as a normal user, not root"; exit 1; }
SAFEHOUSE_VERSION="$(safehouse --version 2>/dev/null | awk '{print $NF}')"
if [ -n "$VERSION_ARG" ]; then
  case "$VERSION_ARG" in
    ""|*[!A-Za-z0-9._-]*) echo "FAIL: bad version '$VERSION_ARG' (letters, digits, ., _, - only)"; exit 1 ;;
  esac
  [ "$SAFEHOUSE_VERSION" = "$VERSION_ARG" ] \
    || echo "WARN: safehouse on PATH reports $SAFEHOUSE_VERSION, run labeled $VERSION_ARG"
  SAFEHOUSE_VERSION="$VERSION_ARG"
fi
echo "safehouse: $SAFEHOUSE_VERSION"

banner "build rig (fake credentials only)"
# File-deletion policy: never rm; move stale rigs into .trash/.
mkdir -p "$TRASH"
for d in home work sibling; do
  [ -e "$RIG/$d" ] && mv "$RIG/$d" "$TRASH/$d-$(date +%s)"
done

# Fake home. Paths are relative to the package so the eval is portable.
for d in ".ssh" ".local/share/opencode" ".local/state" ".cache" ".Trash" ".kube" \
         ".config/opencode" ".config/agent-safehouse" ".config/gh" ".config/git" \
         ".config/github-copilot" ".cursor" ".gemini" ".agents" ".claude" ".codex" \
         ".aws" ".docker" \
         "Downloads" "Library/Cookies" "Library/Keychains" "Library/Safari" \
         "Library/Containers" "Library/Group Containers" "Library/Mail" \
         "Library/Calendars" "Library/Application Support/MobileSync" \
         "Library/Application Support/com.apple.TCC" "Library/Application Support/Google/Chrome" \
         "Library/Saved Application State" "Library/Preferences" "Library/LaunchAgents" \
         "Library/Messages"; do
  mkdir -p "$FAKEHOME/$d"
done
mkdir -p "$WORK/apps/web" "$WORK/apps/web/config" "$WORK/secrets" "$WORK/.certs" "$SIBLING"

echo "FAKE-SSH-PRIVATE-KEY"      > "$FAKEHOME/.ssh/id_ed25519"
echo "FAKE-AUTHORIZED-KEYS"      > "$FAKEHOME/.ssh/authorized_keys"
echo "FAKE-SSH-CONFIG"           > "$FAKEHOME/.ssh/config"
echo '{"FAKE":"token"}'          > "$FAKEHOME/.local/share/opencode/auth.json"
sqlite3 "$FAKEHOME/.local/share/opencode/opencode.db" "CREATE TABLE t(x); INSERT INTO t VALUES('FAKE-SESSION-SECRET');" 2>/dev/null \
  || echo "FAKE-DB" > "$FAKEHOME/.local/share/opencode/opencode.db"
echo "FAKE-HISTORY"              > "$FAKEHOME/.zsh_history"
echo "FAKE-CHAT"                 > "$FAKEHOME/Library/Messages/chat.db"
echo '{"FAKE":"registry-login"}' > "$FAKEHOME/.docker/config.json"
echo "FAKE-CLAUDE-CRED"          > "$FAKEHOME/.claude/.credentials.json"
echo "FAKE-CLAUDE-ROOT-JSON"     > "$FAKEHOME/.claude.json"
echo '{"OPENAI_API_KEY":"FAKE"}' > "$FAKEHOME/.codex/auth.json"
echo "FAKE-AWS"                  > "$FAKEHOME/.aws/credentials"
echo "FAKE-NETRC"                > "$FAKEHOME/.netrc"
echo "FAKE-NPMRC"                > "$FAKEHOME/.npmrc"
echo "FAKE-GITCONFIG"            > "$FAKEHOME/.gitconfig"
echo "FAKE-GIT-CREDENTIALS"      > "$FAKEHOME/.git-credentials"
echo "FAKE-GH-TOKEN"             > "$FAKEHOME/.config/gh/hosts.yml"
echo "FAKE-KUBE-CONFIG"          > "$FAKEHOME/.kube/config"
echo "FAKE-CURSOR-AUTH"          > "$FAKEHOME/.cursor/auth.json"
echo "FAKE-GEMINI-CRED"          > "$FAKEHOME/.gemini/oauth_creds.json"
echo "FAKE-COPILOT-TOKEN"        > "$FAKEHOME/.config/github-copilot/token.json"
echo "FAKE-AGENT-RULES"          > "$FAKEHOME/.agents/rules.md"
echo "FAKE-GIT-INCLUDE-CONFIG"   > "$FAKEHOME/.config/git/config"
echo "FAKE-ENV-IN-AGENT-CONFIG"  > "$FAKEHOME/.config/opencode/.env"
echo '{"model":"fake"}'          > "$FAKEHOME/.config/opencode/opencode.json"

echo "# demo project"     > "$WORK/README.md"
echo "print('hi')"        > "$WORK/app.py"
echo "FAKE-ROOT-DOTENV"   > "$WORK/.env"
echo "FAKE-ENV-LOCAL"     > "$WORK/.env.local"
echo "FAKE-ENVRC"         > "$WORK/.envrc"
echo "FAKE-NESTED-DOTENV" > "$WORK/apps/web/.env"
echo "FAKE-ENV-PROD"      > "$WORK/apps/web/config/.env.production"
echo "FAKE-SECRET-DIR"    > "$WORK/secrets/db.txt"
echo "FAKE-CERT"          > "$WORK/.certs/server.pem"
echo "FAKE-SIBLING-CODE"  > "$SIBLING/file.txt"

# The override file, loaded verbatim via --append-profile.
mkdir -p "$FAKEHOME/.config/agent-safehouse"
cp "$OVERRIDE_SRC" "$FAKEHOME/.config/agent-safehouse/local-overrides.sb"
echo "rig ready: fake home + workdir + sibling seeded with fake data"

banner "verify safehouse renders the fake home and the override compiles"
EXPLAIN="$(cd "$WORK" && HOME="$FAKEHOME" safehouse --explain --stdout \
  --append-profile="$FAKEHOME/.config/agent-safehouse/local-overrides.sb" 2>&1)"
printf '%s\n' "$EXPLAIN" | grep -q "define HOME_DIR \"$FAKEHOME\"" \
  || { echo "FAIL: policy did not compile or HOME_DIR did not render as the fake home"; printf '%s\n' "$EXPLAIN" | tail -8; exit 1; }
echo "policy compiles, HOME_DIR renders as the fake home. OK"

banner "host-side baselines (checked again after the run)"
MARKER_BEFORE="$(defaults read com.apple.dock sbx-eval-marker 2>&1)"
CRON_BEFORE="$(crontab -l 2>&1)"
echo "defaults marker: ${MARKER_BEFORE:0:40}"

banner "run battery inside safehouse"
# Random fake identity for username-shaped probes. Never the runner's own.
FAKEUSER="eval-user-$RANDOM$RANDOM"
cd "$WORK" || exit 1
# Spot-check list: sample two representative paths per system tree, expectation,
# and operation. One probe per unique signal.
"$PKG/tools/gen-spot.sh" "$FAKEHOME" "$WORK" "$SIBLING" "$RIG/spot-list.txt" \
  || { echo "FAIL: spot list generation"; exit 1; }
# The battery and its probe list must be readable from inside the sandbox: the
# package dir sits in the runner's home, which the policy denies. The workdir
# is the granted tree.
cp "$BATTERY" "$WORK/battery.sh" || exit 1
cp "$RIG/spot-list.txt" "$WORK/probe-list.txt" || exit 1
HOME="$FAKEHOME" safehouse \
  --append-profile="$FAKEHOME/.config/agent-safehouse/local-overrides.sb" \
  bash "$WORK/battery.sh" "$FAKEHOME" "$WORK" "$SIBLING" "$(getconf DARWIN_USER_TEMP_DIR)" "$FAKEUSER" "$WORK/probe-list.txt" \
  > "$RESULTS" 2>&1
BATTERY_RC=$?

# Rewrite the runner's paths out of the raw results in place: package prefix
# stripped, real home folded into ~. Everything downstream (console dump,
# report) reads the sanitized file.
perl -pi -e "s|\Q$PKG\E/||g; s|\Q$HOME\E|~|g" "$RESULTS"

banner "host-side escape checks"
ARTIFACT_FAIL=0
for f in "$RIG/escape-proof.txt" "$SIBLING/escape-proof.txt" "$SIBLING/new.txt"; do
  if [ -e "$f" ]; then echo "ESCAPE ARTIFACT FOUND: ${f#"$PKG"/}"; ARTIFACT_FAIL=1; fi
done
[ -e "$SIBLING/cron-escape" ] && { echo "ESCAPE ARTIFACT FOUND: cron wrote outside"; ARTIFACT_FAIL=1; }
for stolen in "$WORK"/stolen* "$WORK"/link.key; do
  [ -e "$stolen" ] || continue
  # grep follows symlinks into the (fake) target; a symlink itself carries no
  # key bytes, and reading through it inside the sandbox is probe sym-cat.
  if [ -f "$stolen" ] && [ ! -L "$stolen" ] && grep -q "FAKE-SSH-PRIVATE-KEY" "$stolen" 2>/dev/null; then
    echo "COPY-OUT LEAK: ${stolen#"$PKG"/} contains the fake key"; ARTIFACT_FAIL=1
  fi
done
MARKER_AFTER="$(defaults read com.apple.dock sbx-eval-marker 2>&1)"
[ "$MARKER_BEFORE" = "$MARKER_AFTER" ] || { echo "PREFERENCES WRITE LANDED ON HOST (defaults)"; ARTIFACT_FAIL=1; }
CRON_AFTER="$(crontab -l 2>&1)"
[ "$CRON_BEFORE" = "$CRON_AFTER" ] || { echo "CRONTAB CHANGED BY SANDBOX"; ARTIFACT_FAIL=1; }
[ "$ARTIFACT_FAIL" -eq 0 ] && echo "no escape artifacts, host state unchanged"

banner "verdict"
REPORT="$REPORTS/eval-report-$SAFEHOUSE_VERSION.csv"
mkdir -p "$REPORTS"
"$PKG/tools/gen-report.sh" "$RESULTS" "$REPORT" "$SAFEHOUSE_VERSION" "$RIG"
if grep -q "$(id -un)" "$REPORT"; then
  echo "EVAL FAILED: report contains the runner's username"
  exit 1
fi
sed -n '/#### RESULT/,$p' "$RESULTS" || true
echo "full probe output: ${RESULTS#"$PKG"/}"
echo "csv report:        ${REPORT#"$PKG"/}"
if [ "$BATTERY_RC" -ne 0 ] || [ "$ARTIFACT_FAIL" -ne 0 ]; then
  echo "EVAL FAILED: see failures above and in ${RESULTS#"$PKG"/}"
  exit 1
fi
echo "ALL CLAIMS HELD. Every probe matched its expectation and no artifact escaped."

banner "cleanup"
echo "rig kept in place for inspection: ${RIG#"$PKG"/}"
echo "remove it with: ./run-eval.sh --cleanup"
if [ "$CLEANUP" -eq 1 ]; then
  mkdir -p "$TRASH"
  [ -e "$FAKEHOME" ] && mv "$FAKEHOME" "$TRASH/home-$(date +%s)"
  [ -e "$WORK" ] && mv "$WORK" "$TRASH/work-$(date +%s)"
  [ -e "$SIBLING" ] && mv "$SIBLING" "$TRASH/sibling-$(date +%s)"
  echo "rig moved to ${TRASH#"$PKG"/}"
fi
