# gvpn Android client

Status: **build infrastructure + GOST engine proven on-device.** This directory
documents how the shared Go core is cross-compiled and bound for Android. There
is no app yet (a Kotlin `VpnService` UI binding the `.aar` is a later
sub-project), but the GOST engine now works on a real Android ABI: the `.aar`
statically links the gost engine into `core/gosttls`, and CI proves on an x86_64
emulator that the engine loads (`ENGINE_by_id("gost")` resolves) and performs
GOST crypto (GOST-2012-256 keygen + self-sign + verify). A full server↔device
GOST-TLS *handshake* e2e remains a later sub-project.

## What works today

Two CI jobs:

- **`Android core .aar (gomobile)`** cross-builds static OpenSSL 3 for
  `android-arm64`, cross-builds the **gost engine** to a static `libgost.a`, and
  runs `gomobile bind` of `core/mobile` with the engine linked in — producing and
  uploading `gvpn-core.aar`. That `.aar` exports the client tunnel API to Kotlin:
  `mobile.Connect(bundleJSON, tunFD, reporter) -> Tunnel`, `Tunnel.Disconnect()`,
  and the `StatusReporter` callback interface.
- **`Android GOST on-device (engine + handshake)`** cross-builds OpenSSL + the
  gost engine for `x86_64` and runs two checks on an Android emulator
  (`GVPN_REQUIRE_GOST=1` makes a missing engine a hard failure):
  - the `core/gosttls` self-test — the engine loads and does GOST crypto
    (keygen + self-sign + verify) on-device;
  - the `core/goste2e` handshake e2e (`TestGOSTControlHandshake`) — a real
    GOST-TLS handshake plus the gvpn AUTH gate + SESSION_BIND control protocol;
  - the `core/goste2e` tunnel e2e (`TestGOSTTunnelHTTP`) — the **full pipeline**
    over a real GOST transport: an HTTP GET flows through the WireGuard tunnel
    (`server.Server` + gosttls listener ⟵ `gosttls.Dial` client), proving real IP
    traffic over GOST on the Android ABI. (Still short of reconnect/roaming over
    GOST and of device→host networking — both later sub-projects.)

## Building `gvpn-core.aar` locally

Requires the Android NDK (set `ANDROID_NDK_HOME`), Go ≥ 1.24 (the toolchain
auto-upgrades for gomobile), and JDK 17. Pinned: OpenSSL 3.3.2, NDK
26.3.11579264, Android API 21.

```bash
# 1. Cross-build static OpenSSL 3 for arm64.
ANDROID_NDK_HOME=/path/to/ndk \
  PREFIX="$PWD/openssl-android/arm64-v8a" ABI=arm64-v8a ANDROID_API=21 \
  bash scripts/android/build-openssl-android.sh

# 2. Cross-build the gost engine to a static libgost.a against that OpenSSL.
ANDROID_NDK_HOME=/path/to/ndk \
  OPENSSL_PREFIX="$PWD/openssl-android/arm64-v8a" \
  PREFIX="$PWD/gost-engine-android/arm64-v8a" ABI=arm64-v8a ANDROID_API=21 \
  bash scripts/android/build-gost-engine-android.sh

# 3. Bind core/mobile against both (OpenSSL + gost engine).
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
export PATH="$(go env GOPATH)/bin:$PATH"
cd core
go get golang.org/x/mobile/bind            # gomobile needs x/mobile in the module graph
PKG_CONFIG_PATH="$PWD/../openssl-android/arm64-v8a/lib/pkgconfig:$PWD/../gost-engine-android/arm64-v8a/lib/pkgconfig" \
  ANDROID_NDK_HOME=/path/to/ndk \
  gomobile init && \
  gomobile bind -target=android/arm64 -androidapi 21 -o ../gvpn-core.aar ./mobile
```

`PKG_CONFIG_PATH` points `gosttls`'s `#cgo pkg-config` directives at the
cross-built static OpenSSL (`libssl`/`libcrypto`) and the static gost engine
(`gostengine` → `libgost.a`); the Android build tag registers the engine via
`ENGINE_load_gost()`. `-androidapi 21` is required because NDK 26 supports
API 21–34 only.

## Other ABIs

Both `scripts/android/build-openssl-android.sh` (`ABI=x86_64`, `armeabi-v7a`,
`x86`) and `scripts/android/build-gost-engine-android.sh` (`ABI=x86_64`) are
ABI-parameterized; add them to the CI matrix and the `gomobile bind -target`
list when a full multi-ABI `.aar` is needed. The `x86_64` engine build is
already exercised by the emulator smoke job.
