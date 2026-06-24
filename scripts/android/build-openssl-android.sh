#!/usr/bin/env bash
# Cross-build static OpenSSL 3 for an Android ABI using the NDK, emitting
# libssl.a / libcrypto.a + pkg-config files under $PREFIX. Reproducible: runnable
# by CI and by any developer with an NDK. Inputs via environment (all optional
# except ANDROID_NDK_HOME):
#   ANDROID_NDK_HOME  path to the NDK (required)
#   OPENSSL_VERSION   default 3.3.2
#   ABI               arm64-v8a (default) | x86_64 | armeabi-v7a | x86
#   ANDROID_API       default 21
#   PREFIX            install prefix (default ./openssl-android/$ABI)
#   BUILD_DIR         scratch dir (default ./.openssl-build)
set -euo pipefail

OPENSSL_VERSION="${OPENSSL_VERSION:-3.3.2}"
ABI="${ABI:-arm64-v8a}"
ANDROID_API="${ANDROID_API:-21}"
PREFIX="${PREFIX:-$PWD/openssl-android/$ABI}"
BUILD_DIR="${BUILD_DIR:-$PWD/.openssl-build}"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must be set to the NDK path}"

case "$ABI" in
  arm64-v8a)   ossl_target=android-arm64 ;;
  x86_64)      ossl_target=android-x86_64 ;;
  armeabi-v7a) ossl_target=android-arm ;;
  x86)         ossl_target=android-x86 ;;
  *) echo "build-openssl-android: unknown ABI '$ABI'" >&2; exit 1 ;;
esac

# The OpenSSL android targets expect the NDK LLVM toolchain on PATH and read
# ANDROID_NDK_ROOT. (See OpenSSL NOTES-ANDROID.md.)
toolchain="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
if [ ! -d "$toolchain" ]; then
  echo "build-openssl-android: NDK toolchain not found at $toolchain" >&2
  exit 1
fi
export PATH="$toolchain:$PATH"
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
src="openssl-$OPENSSL_VERSION"
tarball="$src.tar.gz"
if [ ! -d "$src" ]; then
  url="https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/$tarball"
  echo "build-openssl-android: downloading $url"
  curl -fsSLo "$tarball" "$url"
  tar xzf "$tarball"
fi
cd "$src"

# Configure + build static, software-only (no shared libs, no tests/docs).
./Configure "$ossl_target" -D__ANDROID_API__="$ANDROID_API" \
  no-shared no-tests no-docs --prefix="$PREFIX" --openssldir="$PREFIX/ssl"
make -j"$(nproc)"
make install_sw

echo "build-openssl-android: installed OpenSSL $OPENSSL_VERSION ($ABI) to $PREFIX"
echo "pkgconfig:"
ls "$PREFIX"/lib*/pkgconfig/*.pc
