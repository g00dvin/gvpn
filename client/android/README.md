# gvpn Android client

Status: **build-infrastructure only.** This directory documents how the shared Go
core is cross-compiled and bound for Android. There is no app yet (a Kotlin
`VpnService` UI binding the `.aar` is a later sub-project), and **GOST TLS does
not yet work on a device**: the `.aar` *compiles* `core/gosttls` against a
cross-built OpenSSL, but the gost engine/provider runtime on Android (and a real
on-device GOST handshake) is a separate, later sub-project. The `.aar` builds
without the engine because `ENGINE_by_id("gost")` is a runtime call.

## What works today

The CI job **`Android core .aar (gomobile)`** cross-builds static OpenSSL 3 for
`android-arm64` and runs `gomobile bind` of `core/mobile`, producing and
uploading `gvpn-core.aar`. That `.aar` exports the client tunnel API to Kotlin:
`mobile.Connect(bundleJSON, tunFD, reporter) -> Tunnel`, `Tunnel.Disconnect()`,
and the `StatusReporter` callback interface.

## Building `gvpn-core.aar` locally

Requires the Android NDK (set `ANDROID_NDK_HOME`), Go ≥ 1.24 (the toolchain
auto-upgrades for gomobile), and JDK 17. Pinned: OpenSSL 3.3.2, NDK
26.3.11579264, Android API 21.

```bash
# 1. Cross-build static OpenSSL 3 for arm64.
ANDROID_NDK_HOME=/path/to/ndk \
  PREFIX="$PWD/openssl-android/arm64-v8a" ABI=arm64-v8a ANDROID_API=21 \
  bash scripts/android/build-openssl-android.sh

# 2. Bind core/mobile against it.
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
export PATH="$(go env GOPATH)/bin:$PATH"
cd core
go get golang.org/x/mobile/bind            # gomobile needs x/mobile in the module graph
PKG_CONFIG_PATH="$PWD/../openssl-android/arm64-v8a/lib/pkgconfig" \
  ANDROID_NDK_HOME=/path/to/ndk \
  gomobile init && \
  gomobile bind -target=android/arm64 -androidapi 21 -o ../gvpn-core.aar ./mobile
```

`PKG_CONFIG_PATH` points `gosttls`'s `#cgo pkg-config: libssl libcrypto` at the
cross-built static OpenSSL; `-androidapi 21` is required because NDK 26 supports
API 21–34 only.

## Other ABIs

`scripts/android/build-openssl-android.sh` is ABI-parameterized (`ABI=x86_64`,
`armeabi-v7a`, `x86`); add them to the CI matrix and the `gomobile bind -target`
list when a full multi-ABI `.aar` is needed (e.g. for the x86_64 emulator).
