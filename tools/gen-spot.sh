#!/bin/bash
# Host-side spot-check generator. One probe per unique signal: for each system
# tree and expectation, emit at most two representative paths instead of every
# file in the tree. Each tree's policy is uniform, so sampling two paths per
# (tree, expectation, operation) tests the same signal the full walk tested.
# Content never reaches the report: the battery captures stderr only.
# Args: 1=fake home 2=workdir 3=sibling 4=out file
FH="$1"; WORK="$2"; SIBLING="$3"; OUT="$4"
: > "$OUT"

add() { # expect op prefix path  (max 2 per expect+op+prefix)
  # Filenames are attacker-shaped data at the parsing boundary of the
  # battery: pipes, quotes, and newlines break the "expect|op|path" split.
  # The sampled trees are root-owned, so this is hardening, not a live hole.
  case "$4" in
    *'|'*|*$'\n'*|*'"'*|*"'"*) return ;;
  esac
  local key="$1|$2|$3"
  [ "$(grep -cF "$key" "$OUT" 2>/dev/null)" -ge 2 ] && return
  echo "$1|$2|$4" >> "$OUT"
}

# Reads "expect|path" lines on stdin; $1 is the tree path prefix.
tree_rules() {
  local prefix="$1" expect p
  while IFS='|' read -r expect p; do
    [ -z "$p" ] && continue
    if [ -d "$p" ]; then add "$expect" ls "$prefix" "$p"; else add "$expect" cat "$prefix" "$p"; fi
  done
}

# /etc: default-deny outside a small whitelist (S1 covers hosts, resolv.conf,
# passwd, sudoers, master.passwd). Spot-check that arbitrary other files are
# denied too. -L because /etc is a symlink to /private/etc.
find -L /etc -maxdepth 2 -type f 2>/dev/null | while IFS= read -r f; do
  case "$f" in
    /etc/hosts|/etc/resolv.conf|/etc/passwd|/etc/sudoers|/etc/master.passwd) continue ;;
    *) echo "deny|$f" ;;
  esac
done | tree_rules "/etc/"
find -L /etc -maxdepth 2 -type d 2>/dev/null | while IFS= read -r d; do
  case "$d" in
    /etc/sudoers.d|/etc/kcpassword.d) echo "deny|$d" ;;
    *) echo "allow|$d" ;;
  esac
done | tree_rules "/etc/"

# /Library/Preferences: readable per Unix perms, closed by the sandbox.
find /Library/Preferences -maxdepth 2 2>/dev/null | while IFS= read -r p; do
  [ "$p" = "/Library/Preferences" ] && continue
  case "$p" in
    */.GlobalPreferences.plist|*/com.apple.networkd.plist|*/Logging|*/Logging/*) e=any ;;
    *) e=deny ;;
  esac
  echo "$e|$p"
done | tree_rules "/Library/Preferences/"

# /private/var/db: dir listable, contents closed.
find /private/var/db -maxdepth 2 2>/dev/null | while IFS= read -r p; do
  [ "$p" = "/private/var/db" ] && continue
  echo "any|$p"
done | tree_rules "/private/var/db/"

# /private/var/log: same pattern.
find /private/var/log -maxdepth 2 2>/dev/null | while IFS= read -r p; do
  [ "$p" = "/private/var/log" ] && continue
  echo "any|$p"
done | tree_rules "/private/var/log/"

# /Library/Application Support: closed by the sandbox.
find "/Library/Application Support" -maxdepth 2 2>/dev/null | while IFS= read -r p; do
  [ "$p" = "/Library/Application Support" ] && continue
  echo "deny|$p"
done | tree_rules "/Library/Application Support/"

# Sibling repo and workdir-adjacent trees (two unique signals, one probe
# each). Paths are relative to the workdir, the sandbox cwd, so the list
# never carries the runner's home path; the kernel resolves the same files.
add deny cat "$SIBLING/" "../sibling/file.txt"
add deny ls "$SIBLING/" "../sibling"

# /Users: listing is allowed, contents are not.
add nodata ls "/Users" "/Users"
