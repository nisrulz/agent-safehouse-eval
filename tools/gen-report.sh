#!/usr/bin/env bash
# Converts battery output (P-lines) into a CSV report:
# check,result,observed — one row per probe, values CSV-quoted.
# Args: 1=results.txt 2=report.csv 3=safehouse version 4=rig dir
RESULTS="$1"; REPORT="$2"; SVER="${3:-unknown}"; RIG="${4:-rig}"

# Never emit the runner's username: strip the package path prefix from probe
# output, then fold the real home into ~. Applied again here so the report
# stays clean even when fed raw, unsanitized results. Paths pass via ENV so
# nothing is interpolated into the perl program.
PKG="$(dirname "$RIG")"
CLEAN="$RIG/results-clean.txt"
PKG="$PKG" RH="$HOME" perl -pe 's{\Q$ENV{PKG}\E/}{}g; s{\Q$ENV{RH}\E}{~}g' "$RESULTS" > "$CLEAN"
RESULTS="$CLEAN"

# grep -c prints its own 0 on no matches; empty only when the file is missing.
TOTAL=$(grep -c '^P' "$RESULTS" 2>/dev/null || true); TOTAL="${TOTAL:-0}"
PASS=$(grep '^P' "$RESULTS" | grep -c 'PASS' || true); PASS="${PASS:-0}"
FAIL=$(grep '^P' "$RESULTS" | grep -c 'FAIL' || true); FAIL="${FAIL:-0}"
ANY=$(grep '^P' "$RESULTS" | grep -c 'ANY' || true); ANY="${ANY:-0}"

{
  printf 'check,result,observed\n'
  grep '^P' "$RESULTS" | awk -F'\t' '
    function safe(s) { return (s ~ /^[=+@-]/) ? sprintf("%c", 39) s : s }
    {
      c = safe($8); o = safe($7)
      gsub(/"/, "\"\"", c)
      gsub(/"/, "\"\"", o)
      printf "\"%s\",%s,\"%s\"\n", c, $6, o
    }'
} > "$REPORT"
echo "report written: ${REPORT#"$PKG"/} (probes: $TOTAL, pass: $PASS, fail: $FAIL, any: $ANY)"
