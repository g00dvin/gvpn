#!/usr/bin/env bash
# Cross-build the gost engine as a STATIC archive (libgost.a) for an Android ABI,
# linked against a cross-built OpenSSL (see build-openssl-android.sh). Emits
# libgost.a + a pkg-config file (gostengine.pc) under $PREFIX so cgo can pick it
# up via PKG_CONFIG_PATH, exactly like the OpenSSL build.
#
# The engine sources are compiled with -DBUILDING_ENGINE_AS_LIBRARY, which makes
# gost_eng.c expose the public entry point `void ENGINE_load_gost(void)` (its
# "library form") instead of the dynamic loadable-module bind/check functions.
# core/gosttls (android build tag) calls ENGINE_load_gost() then ENGINE_by_id.
#
# Inputs via environment (all optional except ANDROID_NDK_HOME and OPENSSL_PREFIX):
#   ANDROID_NDK_HOME     path to the NDK (required)
#   OPENSSL_PREFIX       cross-built OpenSSL install for this ABI (required;
#                        provides include/ + lib/libcrypto.a from build-openssl-android.sh)
#   GOST_ENGINE_VERSION  git ref/sha of gost-engine/engine (default: pinned below)
#   ABI                  arm64-v8a (default) | x86_64
#   ANDROID_API          default 21
#   PREFIX               install prefix (default ./gost-engine-android/$ABI)
#   BUILD_DIR            scratch dir (default ./.gost-build)
set -euo pipefail

# Pinned gost-engine commit (resolved via `git ls-remote .../engine HEAD`).
GOST_ENGINE_VERSION="${GOST_ENGINE_VERSION:-3dd0f0e4299489a537398cfa4d9daad260ac87a8}"
ABI="${ABI:-arm64-v8a}"
ANDROID_API="${ANDROID_API:-21}"
PREFIX="${PREFIX:-$PWD/gost-engine-android/$ABI}"
BUILD_DIR="${BUILD_DIR:-$PWD/.gost-build}"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must be set to the NDK path}"
: "${OPENSSL_PREFIX:?OPENSSL_PREFIX must point at the cross-built OpenSSL for this ABI}"

case "$ABI" in
  arm64-v8a) triple=aarch64-linux-android ;;
  x86_64)    triple=x86_64-linux-android ;;
  *) echo "build-gost-engine-android: unsupported ABI '$ABI'" >&2; exit 1 ;;
esac

toolchain="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
if [ ! -d "$toolchain" ]; then
  echo "build-gost-engine-android: NDK toolchain not found at $toolchain" >&2
  exit 1
fi
export PATH="$toolchain:$PATH"
CC="${triple}${ANDROID_API}-clang"
AR=llvm-ar

mkdir -p "$BUILD_DIR"
src="$BUILD_DIR/engine"
if [ ! -d "$src/.git" ]; then
  rm -rf "$src"
  git clone https://github.com/gost-engine/engine "$src"
fi
git -C "$src" fetch --depth 1 origin "$GOST_ENGINE_VERSION" 2>/dev/null || true
git -C "$src" checkout -q "$GOST_ENGINE_VERSION"
cd "$src"

# Compile the engine + crypto sources, excluding the standalone CLI tools
# (their own main()), the OpenSSL-3 provider sources, and the test programs.
# This is a superset of the engine + gost_core + gost_err source lists; archive
# members that are never referenced are simply not linked into the final binary.
mapfile -t srcs < <(ls *.c \
  | grep -vE '^(gostsum|gost12sum)\.c$' \
  | grep -vE '^gost_prov' \
  | grep -vE '^test_')

rm -f ./*.o
set -x
"$CC" -O2 -fPIC -DBUILDING_ENGINE_AS_LIBRARY \
  -I"$OPENSSL_PREFIX/include" -I. \
  -c "${srcs[@]}"
"$AR" rcs libgost.a ./*.o
set +x

mkdir -p "$PREFIX/lib/pkgconfig" "$PREFIX/include"
cp libgost.a "$PREFIX/lib/"
cp gost-engine.h "$PREFIX/include/" 2>/dev/null || true

# gostengine.pc: -lgost must be followed by libcrypto/libssl so the engine's
# unresolved crypto symbols are satisfied (static-link ordering). Requiring
# libssl + libcrypto via pkg-config Requires guarantees they appear after -lgost.
cat > "$PREFIX/lib/pkgconfig/gostengine.pc" <<EOF
prefix=$PREFIX
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: gostengine
Description: Statically-linked GOST engine for Android
Version: 0
Requires: libssl libcrypto
Libs: -L\${libdir} -lgost
Cflags: -I\${includedir}
EOF

echo "build-gost-engine-android: installed libgost.a ($ABI) to $PREFIX"
ls -l "$PREFIX/lib/libgost.a" "$PREFIX/lib/pkgconfig/gostengine.pc"
