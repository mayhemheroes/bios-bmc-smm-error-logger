#!/usr/bin/env bash
#
# bios-bmc-smm-error-logger/mayhem/build.sh — build the openbmc BIOS<->BMC shared-memory
# error-log binary parser as a sanitized libFuzzer target (+ a standalone reproducer) and the
# repo's OWN gtest suite for mayhem/test.sh.
#
# Fuzzed surface: the RDE / circular-buffer parser. We use an ADDITIVE harness
# (mayhem/harnesses/rde_fuzz.cpp) rather than the repo's src/fuzzer.cpp: the in-tree fuzzer opens a
# live DBus connection (sdbusplus request_name) in its init path and therefore aborts on the first
# input outside a real openbmc system bus — it never iterates in a sandbox. Our harness drives the
# SAME parse path (BufferImpl over an in-memory region -> readLoop -> CircularBufferHeader validate +
# wraparound queue read + error-log entry decode -> RdeCommandHandler / libbej), publishing through a
# mock ExternalStorer (no DBus, no filesystem). We pre-seed a valid header so validation is reached.
#
# Build contract from the org base ENV: CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN. The whole project (lib + rde) is compiled WITH $SANITIZER_FLAGS so the parser
# itself is instrumented; coverage is added with -fsanitize=fuzzer-no-link and the libFuzzer runtime
# is linked only into the fuzz binary. We build with libstdc++ (clang default on Debian) to match the
# base image's libFuzzer runtime ABI. Output binaries land in /mayhem (= $OUT).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS: DWARF ≤ 3 required — Mayhem triage can't read DWARF ≥ 4 (§6.2 item 10).
# Thread after $SANITIZER_FLAGS so it wins over any -g the sanitizer flags add.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
export DEBUG_FLAGS
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${OUT:=/mayhem}"
export SANITIZER_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS OUT

cd "$SRC"
git config --global --add safe.directory "$SRC" 2>/dev/null || true

COV="-fsanitize=fuzzer-no-link"
# -Wno-unknown-warning-option: the openbmc deps pass -Werror=character-conversion, a warning name
# this clang build doesn't know — without this the promotion-to-error fails -Werror subprojects.
# -Wno-c99-extensions: SD_BUS_ERROR_NULL expands to a compound literal (C99) which -Wpedantic in
# sdbusplus's own meson.build promotes to an error under clang C++23 — suppress it in the dep chain.
# These relaxations target the openbmc dep chain only, NOT the fuzzed parser logic.
CPP_ARGS="-Wno-unknown-warning-option -Wno-error=deprecated-declarations -Wno-c99-extensions $SANITIZER_FLAGS $DEBUG_FLAGS $COV"
LINK_ARGS="$SANITIZER_FLAGS $DEBUG_FLAGS"

# ── 1) Fetch meson subprojects (openbmc stdplus/sdbusplus/libbej/phosphor-dbus-interfaces + json) ──
# Guard: only download if any of the primary subproject dirs are missing (makes re-runs offline-safe;
# on re-run inside the commit image the dirs already exist so we skip the network fetch entirely).
if [ ! -d subprojects/sdbusplus ] || [ ! -d subprojects/stdplus ] || \
   [ ! -d subprojects/libbej ] || [ ! -d subprojects/phosphor-dbus-interfaces ] || \
   [ ! -d subprojects/nlohmann_json ]; then
  meson subprojects download
fi

# ── 2) Patch clang-19 / c++23 header hygiene issues in the openbmc subprojects (missing includes,
#       std::move_only_function not in this libstdc++/clang combo, stray std forward-declarations).
#       Idempotent; touches ONLY subproject headers, never bios-bmc-smm-error-logger's own sources. ──
fixhdr() {
  local f
  f=subprojects/stdexec/include/stdexec/__detail/__utility.hpp
  [ -f "$f" ] && ! grep -q '#include <new>' "$f" && sed -i '1i#include <new>' "$f" || true
  f=subprojects/stdplus/include/stdplus/function_view.hpp
  [ -f "$f" ] && ! grep -q '#include <concepts>' "$f" && sed -i '1i#include <cstddef>\n#include <concepts>\n#include <type_traits>\n#include <memory>' "$f" || true
  f=subprojects/stdplus/include/stdplus/debug/lifetime.hpp
  [ -f "$f" ] && ! grep -q '#include <cstddef>' "$f" && sed -i '1i#include <cstddef>' "$f" || true
  f=subprojects/stdplus/include/stdplus/hash.hpp
  if [ -f "$f" ] && ! grep -q '#include <functional>' "$f"; then sed -i '1i#include <functional>' "$f"; sed -i '/^namespace std$/,/}/ { /template <class Key>/d; /struct hash;/d; }' "$f"; fi
  f=subprojects/stdplus/include/stdplus/net/addr/ip.hpp
  if [ -f "$f" ] && ! grep -q '#include <format>' "$f"; then sed -i '1i#include <format>' "$f"; sed -i '/template <typename T, typename CharT>/d;/struct formatter;/d' "$f"; fi
  f=subprojects/stdplus/include/stdplus/net/addr/subnet.hpp
  if [ -f "$f" ] && ! grep -q '#include <format>' "$f"; then sed -i '1i#include <format>' "$f"; sed -i '/template <typename T, typename CharT>/d;/struct formatter;/d' "$f"; fi
  f=subprojects/stdplus/include/stdplus/str/cat.hpp
  [ -f "$f" ] && ! grep -q '#include <algorithm>' "$f" && sed -i '1i#include <algorithm>' "$f" || true
  f=subprojects/sdbusplus/include/sdbusplus/asio/connection.hpp
  [ -f "$f" ] && sed -i 's/std::move_only_function/std::function/g' "$f" || true
  f=subprojects/sdbusplus/src/async/barrier.cpp
  [ -f "$f" ] && ! grep -q '#include <algorithm>' "$f" && sed -i '1i#include <algorithm>' "$f" || true
}
fixhdr

# ── 3) Configure + build the project's static libs (instrumented). -Dfuzzing=true builds the libs
#       with coverage and also produces read_loop.cpp.o, which our additive harness links against.
#       -Dstdplus:gtest=disabled stops stdplus pulling googletest (which it would otherwise build as
#       an instrumented shared lib that fails to link the sanitizer runtime). ──────────────────────
BUILD="$SRC/mayhem-build"
rm -rf "$BUILD"
COMMON_OPTS=(-Dfuzzing=true -Dtests=disabled -Ddefault_library=static
             -Dgoogletest:default_library=static -Dstdplus:gtest=disabled -Dstdplus:examples=false
             -Dcpp_args="$CPP_ARGS" -Dc_args="$SANITIZER_FLAGS" -Dcpp_link_args="$LINK_ARGS")
meson setup "$BUILD" "${COMMON_OPTS[@]}" || { fixhdr; meson setup --reconfigure "$BUILD" "${COMMON_OPTS[@]}"; }
# stdexec arrives during the first configure; ensure its <new> fix landed, then build.
fixhdr
ninja -C "$BUILD" -v -j"$MAYHEM_JOBS"

# ── 4) Compile the additive harness reusing the EXACT include flags meson used for read_loop.cpp
#       (robust across subproject layout changes), then link it as the libFuzzer target. ───────────
INCFLAGS="$(python3 - "$BUILD" <<'PY'
import json,sys,shlex
b=sys.argv[1]
db=json.load(open(b+"/compile_commands.json"))
ent=next((e for e in db if e.get("file","").endswith("read_loop.cpp")), None) \
   or next((e for e in db if e.get("file","").endswith("buffer.cpp")), None)
toks=shlex.split(ent["command"]); out=[]; i=0
while i<len(toks):
    t=toks[i]
    if t.startswith("-I"):
        out.append(t if len(t)>2 else t+toks[i+1])
        if len(t)==2: i+=1
    elif t=="-isystem":
        out.append(t+toks[i+1]); i+=1
    elif t.startswith("-isystem"):
        out.append(t)
    i+=1
print(" ".join(out))
PY
)"

cd "$BUILD"
$CXX -std=c++23 $SANITIZER_FLAGS $DEBUG_FLAGS $COV $INCFLAGS \
    -c "$SRC/mayhem/harnesses/rde_fuzz.cpp" -o mayhem_rde_fuzz.o

ARCHIVES="src/libbios_bmc_smm_error_logger.a src/rde/librde.a"
RLOOP="$(find src -name 'read_loop.cpp.o' | head -1)"
ALLA="$(find subprojects -name '*.a' | tr '\n' ' ')"
SYSLIBS="$(pkg-config --libs libsystemd 2>/dev/null) -lpthread"

$CXX -std=c++23 $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    mayhem_rde_fuzz.o "$RLOOP" \
    -Wl,--start-group $ARCHIVES $ALLA -Wl,--end-group \
    $SYSLIBS \
    -o "$OUT/rde_fuzz"
echo "built rde_fuzz (libFuzzer)"

# ── 5) Standalone run-once reproducer (no libFuzzer runtime; reads one input file). ───────────────
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o standalone_main.o
set +e
$CXX -std=c++23 $SANITIZER_FLAGS $DEBUG_FLAGS \
    mayhem_rde_fuzz.o standalone_main.o "$RLOOP" \
    -Wl,--start-group $ARCHIVES $ALLA -Wl,--end-group \
    $SYSLIBS \
    -o "$OUT/rde_fuzz-standalone"
[ "$?" -eq 0 ] && echo "built rde_fuzz-standalone" || echo "WARNING: standalone link failed (non-fatal); libFuzzer target stands" >&2
set -e

# ── 6) Build the repo's OWN gtest suite with NORMAL flags (clean tree) so test.sh only RUNS it. ───
cd "$SRC"
TESTBUILD="$SRC/mayhem-tests"
rm -rf "$TESTBUILD"
set +e
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  meson setup "$TESTBUILD" \
    -Dtests=enabled -Dfuzzing=false -Ddefault_library=static \
    -Dgoogletest:default_library=static -Dstdplus:gtest=disabled -Dstdplus:examples=false \
    -Dcpp_args="-Wno-unknown-warning-option -Wno-error=deprecated-declarations -Wno-error=sign-compare -Wno-c99-extensions" \
  && env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS ninja -C "$TESTBUILD" -j"$MAYHEM_JOBS"
[ "$?" -eq 0 ] && echo "built gtest suite in mayhem-tests/" \
              || echo "WARNING: gtest suite build failed — mayhem/test.sh will report the failure" >&2
set -e

echo "build.sh complete:"
ls -la "$OUT/rde_fuzz" "$OUT/rde_fuzz-standalone" 2>&1 || true
