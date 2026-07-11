#!/usr/bin/env bash
#
# libspdm/mayhem/test.sh — RUN libspdm's OWN cmocka unit tests (built CLEAN by mayhem/build.sh into
# mayhem-tests/bin) and emit a CTRF summary. exit 0 iff no test failed.
#
# PATCH-grade oracle: these are libspdm's self-contained cmocka known-answer tests (the same set
# OSS-Fuzz's run_tests.sh runs) — test_spdm_common / test_spdm_crypt / test_spdm_secured_message /
# test_spdm_requester / test_spdm_responder. Each exercises the SPDM state machine + message
# encode/decode and asserts exact protocol behavior, so a no-op / "exit(0)" patch cannot pass. This
# script only RUNS the pre-built binaries (cmocka prints "[ PASSED ] N test(s)" / "[ FAILED ]");
# it never compiles. The binaries must run from the bin/ dir (sample keys are copied there).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

BINDIR="$SRC/mayhem-tests/bin"

# Representative self-contained subset (cmocka, no network, no sanitizers).
TESTS=(
  test_spdm_common
  test_spdm_crypt
  test_spdm_secured_message
  test_spdm_requester
  test_spdm_responder
)

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -d "$BINDIR" ]; then
  echo "missing $BINDIR — run mayhem/build.sh first" >&2
  emit_ctrf "cmocka" 0 1 0; exit 2
fi

cd "$BINDIR"
PASSED=0; FAILED=0
for t in "${TESTS[@]}"; do
  if [ ! -x "./$t" ]; then
    echo "WARN: $t not built — counting as failure" >&2
    FAILED=$(( FAILED + 1 )); continue
  fi
  echo "=== running $t ==="
  out="$("./$t" 2>&1)"; rc=$?
  echo "$out"
  # cmocka summary lines:  [  PASSED  ] N test(s).   /   [  FAILED  ] N test(s).
  p=$(printf '%s\n' "$out" | sed -n 's/.*\[[[:space:]]*PASSED[[:space:]]*\][[:space:]]*\([0-9][0-9]*\) test.*/\1/p' | awk '{s+=$1} END{print s+0}')
  f=$(printf '%s\n' "$out" | sed -n 's/.*\[[[:space:]]*FAILED[[:space:]]*\][[:space:]]*\([0-9][0-9]*\) test.*/\1/p' | awk '{s+=$1} END{print s+0}')
  PASSED=$(( PASSED + p ))
  FAILED=$(( FAILED + f ))
  # A nonzero exit with no parsed failure count still counts as a failure.
  if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then
    echo "WARN: $t exited $rc with no parsed FAILED count — counting one failure" >&2
    FAILED=$(( FAILED + 1 ))
  fi
done

emit_ctrf "cmocka" "$PASSED" "$FAILED" 0
