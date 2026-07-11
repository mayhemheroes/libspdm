#!/usr/bin/env bash
#
# libspdm/mayhem/build.sh — build a representative subset of DMTF/libspdm's SPDM message-parsing
# fuzz harnesses as sanitized libFuzzer targets (+ standalone reproducers), AND libspdm's own
# cmocka unit-test binaries (built clean, for mayhem/test.sh to RUN).
#
# libspdm ships ~69 OSS-Fuzz harnesses under unit_test/fuzzing/{test_requester,test_responder,
# test_secured_message,...}. Each fuzzer = one per-command harness .c (implementing
# libspdm_run_test_harness()) + the shared driver spdm_unit_fuzzing_common/{common,algo,
# toolchain_harness}.c. The driver's toolchain_harness.c exposes LLVMFuzzerTestOneInput() when
# -DTEST_WITH_LIBFUZZER is set (libFuzzer build) and a file-reading main() otherwise. Each harness
# drives a full SPDM requester/responder state machine and feeds the fuzz input in as an
# attacker-controlled SPDM request/response message that libspdm PARSES (message decode is the
# fuzzed surface).
#
# We integrate a high-value REPRESENTATIVE SUBSET (12) rather than all ~69 to stay under the Mayhem
# concurrent-analysis quota — the core SPDM responder request-parsers (VERSION/CAPABILITIES/
# ALGORITHMS/DIGESTS/CERTIFICATE/CHALLENGE_AUTH/MEASUREMENTS/KEY_EXCHANGE), the matching requester
# response-parsers (GET_VERSION/GET_CERTIFICATE/CHALLENGE), and the secured-message decoder.
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN/OUT). libspdm builds with CMake using its OWN bundled mbedtls/cryptlib
# submodules (replicating the OSS-Fuzz build: TOOLCHAIN=LIBFUZZER, CRYPTO=mbedtls). The LIBFUZZER
# toolchain already compiles+links with -fsanitize=fuzzer,address (so the libspdm message parsers
# ARE instrumented); we inject UBSan + halting via CMAKE_C_FLAGS (clang's driver also links the
# UBSan runtime). $OUT (default /mayhem) receives one binary per harness + a -standalone reproducer.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO extra sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS: DWARF ≤ 3 for Mayhem triage (clang-19 plain -g emits DWARF-5; be explicit).
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${OUT:=/mayhem}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE STANDALONE_FUZZ_MAIN OUT MAYHEM_JOBS

cd "$SRC"
mkdir -p "$OUT"

# The 12 integrated harnesses (CMake target names == output binary names == seed dir names).
HARNESSES=(
  test_spdm_responder_version
  test_spdm_responder_capabilities
  test_spdm_responder_algorithms
  test_spdm_responder_digests
  test_spdm_responder_certificate
  test_spdm_responder_challenge_auth
  test_spdm_responder_measurements
  test_spdm_responder_key_exchange
  test_spdm_requester_get_version
  test_spdm_requester_get_certificate
  test_spdm_requester_challenge
  test_spdm_decode_secured_message
)

# The LIBFUZZER toolchain hardcodes -fsanitize=fuzzer,address at compile+link. We ADD UBSan (+halting,
# +frame pointers) through CMAKE_C_FLAGS — clang uses CMAKE_C_FLAGS on the link line too, so the UBSan
# runtime is linked and __ubsan_handle_* resolve. (We do NOT override CMAKE_EXE_LINKER_FLAGS via -D:
# the toolchain re-set()s it for real targets anyway, and a fuzzer link flag there breaks CMake's
# compiler-id try-compile.) The injected flags are the non-asan/non-fuzzer part of SANITIZER_FLAGS.
#
# BENIGN-UB RELAXATION: libspdm's pervasive status macro LIBSPDM_STATUS_CONSTRUCT(severity,...) =
# ((severity) << 28 | ...) (include/library/spdm_return_status.h:55) left-shifts the error severity
# (0x8) by 28, which overflows signed int. This fires on essentially EVERY error path — i.e. on
# nearly every malformed fuzz input — so with halting UBSan it floods and the harness "crashes"
# instantly before fuzzing (e.g. the get_version/decode_secured_message harnesses abort on a single
# byte). Disable the two sub-checks this macro trips (signed-integer-overflow, shift) so the
# meaningful UB (oob, etc.) still halts while this intentional status-code arithmetic does not.
CFLAGS_INJECT="-fsanitize=undefined -fno-sanitize=signed-integer-overflow,shift -fno-sanitize-recover=all -fno-omit-frame-pointer $DEBUG_FLAGS"

# ── 1) libFuzzer build (replicates OSS-Fuzz: TOOLCHAIN=LIBFUZZER, CRYPTO=mbedtls) ──────────────────
BUILD="$SRC/mayhem-build"
rm -rf "$BUILD"; mkdir -p "$BUILD"; pushd "$BUILD" >/dev/null
cmake -DARCH=x64 -DTOOLCHAIN=LIBFUZZER -DTARGET=Release -DCRYPTO=mbedtls \
      -DCMAKE_C_FLAGS="$CFLAGS_INJECT" "$SRC"
make copy_sample_key -j"$MAYHEM_JOBS" || true
make "${HARNESSES[@]}" -j"$MAYHEM_JOBS"
popd >/dev/null

# Compile the standalone main (LLVMFuzzerTestOneInput file-runner) once, sanitized.
SA_OBJ="$BUILD/standalone_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SA_OBJ"

# ── 2) emit each harness: libFuzzer target -> $OUT/<name>, + standalone reproducer ────────────────
for h in "${HARNESSES[@]}"; do
  # libFuzzer binary built by CMake (-fsanitize=fuzzer,address + injected UBSan)
  cp "$BUILD/bin/$h" "$OUT/$h"

  # standalone: REUSE CMake's exact recorded link command (link.txt) for this target — it has the
  # correct per-target static-lib set (e.g. device_secret_lib_null vs _sample; linking all of lib/*.a
  # would clash). Swap the libFuzzer engine (-fsanitize=fuzzer,address) for our $SANITIZER_FLAGS, add
  # StandaloneFuzzTargetMain (provides main() -> LLVMFuzzerTestOneInput, exported by
  # toolchain_harness.c.o under -DTEST_WITH_LIBFUZZER), and retarget -o to <name>-standalone.
  objdir="$(find "$BUILD" -type d -name "$h.dir" | head -1)"
  linktxt="$objdir/link.txt"
  if [ ! -f "$linktxt" ]; then echo "ERROR: no link.txt for $h" >&2; exit 1; fi
  # The link.txt paths (CMakeFiles/<h>.dir/... and ../../../../lib/...) are relative to the target's
  # makefile dir = the dir CONTAINING CMakeFiles (objdir is .../CMakeFiles/<h>.dir).
  tgtdir="$(dirname "$(dirname "$objdir")")"
  # Take the FIRST link command (the one producing bin/<h>). Swap the libFuzzer engine for our
  # $SANITIZER_FLAGS and retarget -o to <name>-standalone, adding StandaloneFuzzTargetMain.
  cmd="$(head -1 "$linktxt")"
  cmd="${cmd/-fsanitize=fuzzer,address/$SANITIZER_FLAGS $DEBUG_FLAGS}"
  cmd="${cmd/-o ..\/..\/..\/..\/bin\/$h/-o $OUT/$h-standalone $SA_OBJ}"
  ( cd "$tgtdir" && eval "$cmd" )
  echo "built $h (+ standalone)"
done

# ── 3) libspdm's OWN cmocka unit tests, built CLEAN (TOOLCHAIN=CLANG, no sanitizers) so test.sh
#       only RUNS them (honest PATCH oracle, no sanitizer/benign-UB noise). Mirrors OSS-Fuzz
#       run_tests.sh. We build a representative self-contained subset. ────────────────────────────
TESTBUILD="$SRC/mayhem-tests"
rm -rf "$TESTBUILD"; mkdir -p "$TESTBUILD"; pushd "$TESTBUILD" >/dev/null
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake -DARCH=x64 -DTOOLCHAIN=CLANG -DTARGET=Release -DCRYPTO=mbedtls "$SRC"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS make copy_sample_key -j"$MAYHEM_JOBS" || true
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  make test_spdm_common test_spdm_crypt test_spdm_secured_message \
       test_spdm_requester test_spdm_responder -j"$MAYHEM_JOBS"
popd >/dev/null
echo "built libspdm cmocka unit tests in mayhem-tests/bin"

echo "build.sh complete:"
ls -la "$OUT"/test_spdm_* 2>&1 | head -40 || true
