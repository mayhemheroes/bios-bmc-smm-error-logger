#!/usr/bin/env bash
#
# bios-bmc-smm-error-logger/mayhem/test.sh — RUN the repo's OWN gtest suite (built by
# mayhem/build.sh with normal, non-sanitized flags into mayhem-tests/) and emit a CTRF summary.
# exit 0 iff no test failed.
#
# PATCH-grade oracle: these are the project's real gtest unit tests over the exact code the fuzzer
# exercises — buffer.cpp (CircularBufferHeader parse, wraparound queue read, bounds checks),
# pci_handler.cpp (the shared-memory DataInterface), the RDE dictionary manager, and the RDE command
# handler (rde_handler). They assert concrete decoded values and error returns, so a no-op /
# "return 0" patch to the parser cannot pass. This script only RUNS the pre-built suite via
# `meson test`; it never compiles.
#
# Anti-reward-hacking: after running via meson, we ALSO run each test binary directly and verify that
# gtest emitted real "[ RUN      ]" lines. A neutered binary (one patched to exit(0)) produces no
# gtest output — so the direct-run count provides a behavioral floor. The CTRF "passed" count uses
# the direct gtest invocation counts (gtest lines parsed), so a no-op patch cannot fake them.
#
# The repo's 5th suite, external_storer_file, is intentionally NOT run here: its gtest fixtures
# construct sdbusplus::bus::new_default() (a live openbmc *system* DBus connection) in their ctor and
# throw org.freedesktop.DBus.Error.FileNotFound in any sandbox without a system bus. That suite is a
# DBus integration test, not part of the fuzzed binary-parse path, so excluding it keeps test.sh a
# deterministic functional oracle over the code the fuzzer actually drives.
set -uo pipefail
SUITES="pci_handler rde_dictionary_manager buffer rde_handler"
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "${SRC:-/mayhem}"

BUILDDIR="${SRC:-/mayhem}/mayhem-tests"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-${SRC:-/mayhem}/ctrf-report.json}" <<JSON
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

if [ ! -d "$BUILDDIR" ]; then
  echo "missing $BUILDDIR — run mayhem/build.sh first" >&2
  emit_ctrf "meson-test" 0 1 0; exit 2
fi
if ! command -v meson >/dev/null 2>&1; then
  echo "meson not available — cannot run the test suite" >&2
  emit_ctrf "meson-test" 0 1 0; exit 2
fi

echo "=== running meson test ($SUITES) in $BUILDDIR ==="
out="$(env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS meson test -C "$BUILDDIR" --print-errorlogs $SUITES 2>&1)"; rc=$?
echo "$out"

# meson prints:  Ok: N / Expected Fail: N / Fail: N / Unexpected Pass: N / Skipped: N / Timeout: N
PASSED=$(printf '%s\n' "$out" | sed -n 's/^Ok:[[:space:]]*\([0-9][0-9]*\).*/\1/p'              | tail -1)
EXPFAIL=$(printf '%s\n' "$out" | sed -n 's/^Expected Fail:[[:space:]]*\([0-9][0-9]*\).*/\1/p'  | tail -1)
FAIL=$(printf '%s\n' "$out" | sed -n 's/^Fail:[[:space:]]*\([0-9][0-9]*\).*/\1/p'              | tail -1)
UNEXP=$(printf '%s\n' "$out" | sed -n 's/^Unexpected Pass:[[:space:]]*\([0-9][0-9]*\).*/\1/p'  | tail -1)
SKIP=$(printf '%s\n' "$out" | sed -n 's/^Skipped:[[:space:]]*\([0-9][0-9]*\).*/\1/p'           | tail -1)
TIMEOUT=$(printf '%s\n' "$out" | sed -n 's/^Timeout:[[:space:]]*\([0-9][0-9]*\).*/\1/p'        | tail -1)
: "${PASSED:=0}" "${EXPFAIL:=0}" "${FAIL:=0}" "${UNEXP:=0}" "${SKIP:=0}" "${TIMEOUT:=0}"

PASS_TOTAL=$(( PASSED + EXPFAIL ))
FAIL_TOTAL=$(( FAIL + UNEXP + TIMEOUT ))

# ── Direct behavioral verification ───────────────────────────────────────────────────────────────
# Run each test binary directly and count gtest "[ RUN      ]" and "[       OK ]" lines. A neutered
# binary (patched/LD_PRELOAD to exit 0) emits NO gtest output, so a zero run-count is a hard fail.
# This makes the oracle behavioral: "tests ran" means gtest actually executed cases and printed output,
# not merely that a binary returned 0.
DIRECT_RUN=0
DIRECT_OK=0
DIRECT_FAIL=0

for suite in $SUITES; do
  # meson stores test binaries in the build dir with the same name as the meson test target.
  bin="$(find "$BUILDDIR" -maxdepth 4 -name "$suite" -type f -executable 2>/dev/null | head -1)"
  if [ -z "$bin" ]; then
    echo "WARN: could not find binary for suite '$suite' — skipping direct check" >&2
    continue
  fi
  echo "--- direct run: $bin ---"
  dout="$("$bin" 2>&1)" || true
  echo "$dout"
  r=$(printf '%s\n' "$dout" | grep -c '^\[ RUN      \]' || true)
  o=$(printf '%s\n' "$dout" | grep -c '^\[       OK \]' || true)
  f=$(printf '%s\n' "$dout" | grep -c '^\[  FAILED  \]' || true)
  DIRECT_RUN=$(( DIRECT_RUN + r ))
  DIRECT_OK=$(( DIRECT_OK + o ))
  DIRECT_FAIL=$(( DIRECT_FAIL + f ))
done

echo "Direct gtest totals: RUN=$DIRECT_RUN  OK=$DIRECT_OK  FAILED=$DIRECT_FAIL"

# If we ran any suites but got zero "[ RUN      ]" lines, the binaries are not functioning correctly.
if [ "$DIRECT_RUN" -eq 0 ]; then
  echo "FAIL: no gtest '[ RUN      ]' lines detected — test binaries produced no output (neutered or broken)" >&2
  emit_ctrf "meson-test" 0 1 0
  exit 1
fi

# Merge: use direct counts as the authoritative pass/fail numbers (behavioral), meson as the
# suite-level summary. We report failed = max(FAIL_TOTAL, DIRECT_FAIL) to catch both.
FINAL_FAIL=$(( FAIL_TOTAL > DIRECT_FAIL ? FAIL_TOTAL : DIRECT_FAIL ))
FINAL_PASS=$(( DIRECT_OK ))

# If meson produced no parseable summary, fall back to its exit code.
if [ "$(( PASS_TOTAL + FAIL_TOTAL + SKIP ))" -eq 0 ]; then
  echo "could not parse meson test summary; using meson exit code $rc and direct gtest counts" >&2
  [ "$rc" -eq 0 ] && [ "$DIRECT_RUN" -gt 0 ] && [ "$DIRECT_FAIL" -eq 0 ] && {
    emit_ctrf "meson-test" "$DIRECT_OK" 0 0; exit 0
  }
  emit_ctrf "meson-test" 0 1 0; exit 1
fi

emit_ctrf "meson-test" "$FINAL_PASS" "$FINAL_FAIL" "$SKIP"
