# Android App Shell — Buildable Scaffold + `.aar` Binding (SP6a) — Design

**Status:** approved for planning (2026-06-26)
**Sub-project:** Client phase, SP6a — a minimal Android app that binds the
engine-linked `gvpn-core.aar` and assembles to an APK in CI.
**Predecessors:** SP1–SP5 (shared core proven end-to-end on the Android ABI:
build → engine loads → handshake → tunnel).

## Problem

The shared Go core is proven on the Android ABI, but nothing yet *binds* it from
an actual Android app. `client/android/` contains only a README. The one thing
that cannot be verified except through CI is whether `gvpn-core.aar` binds into a
Gradle Android build and assembles. This sub-project isolates that risk into a
small, CI-gated PR — the way SP2 de-risked the `.aar` build before SP3 added the
engine.

The full Android app (a "shell" with VpnService, secure storage, bundle import,
connect/disconnect UI) is **decomposed** into:
- **SP6a (this):** buildable scaffold + `.aar` binding, CI-gated.
- **SP6b (next):** VpnService + Keystore bundle storage + `.gvpn` import +
  connect/disconnect UI, verified manually on a device.

## Locked decisions

1. **Acceptance = CI-compiles + JVM-tested; real behavior is manual.** CI runs
   `./gradlew assembleDebug testDebugUnitTest`; an actual running app is a manual
   device check (and for SP6a there is no VPN behavior to run yet).
2. **Toolkit = Kotlin + Jetpack Compose.**
3. **Linkage probe = `mobile.Version()`.** A trivial bound function the Compose
   screen calls and displays — referencing it makes `assembleDebug` prove the
   Kotlin↔`.aar` binding compiles.

## Scope

In scope: a minimal Gradle app under `client/android/`; one bound `.aar` call;
CI that builds the engine-linked `.aar`, assembles a debug APK, and runs unit
tests. **Out of scope (SP6b):** `VpnService`, Keystore storage, `.gvpn` import,
`mobile.ParseBundleInfo` (TUN params), connect/disconnect, any real tunnel.

## Components

### `core/mobile/version.go` (new — tiny core addition)

```go
// Version returns the linked OpenSSL/GOST version string, a harmless bound call
// the Android shell uses to prove the .aar binding links. No engine init.
func Version() string { return gosttls.Version() }
```
gomobile-bindable (no args, returns string). A Go unit test asserts it is
non-empty.

### Gradle app under `client/android/` (Kotlin + Compose)

- `settings.gradle.kts`, root `build.gradle.kts`, `app/build.gradle.kts`
  (namespace + `applicationId "dev.gvpn"`, `minSdk 26`, `compileSdk 34`,
  `targetSdk 34`, Kotlin, Compose BOM), `gradle.properties`.
- Committed Gradle **wrapper**: `gradlew`, `gradle/wrapper/gradle-wrapper.jar`,
  `gradle/wrapper/gradle-wrapper.properties` (pinned Gradle version).
- `app/src/main/AndroidManifest.xml` — single `MainActivity`, no special
  permissions yet (VpnService permission lands in SP6b).
- `app/src/main/java/dev/gvpn/MainActivity.kt` — a Compose screen that displays
  `"gvpn core: " + Mobile.version()` (the bound `.aar` call; gomobile binds the
  `mobile` package as the `Mobile` class).
- `app/libs/` — `gvpn-core.aar` is placed here by CI, **git-ignored** (never
  commit the binary); Gradle consumes it via
  `implementation(files("libs/gvpn-core.aar"))`.
- `app/src/test/java/dev/gvpn/SmokeTest.kt` — one trivial JVM unit test to wire
  `testDebugUnitTest` into CI (a real JVM-test harness for SP6b's storage/parse
  logic).

### CI — rewrite the existing `android` job

The current `android` job is broken (it runs `gomobile bind ./core/...` to a
wrong path and `assembleRelease` against a non-existent project). Rewrite it,
reusing the SP2/SP3 scripts (with the same caches):

1. setup-go / setup-java 17 / setup-android; install NDK.
2. Cross-build OpenSSL (arm64) — `scripts/android/build-openssl-android.sh`.
3. Cross-build gost engine (arm64) — `scripts/android/build-gost-engine-android.sh`.
4. `gomobile bind -target=android/arm64 -androidapi 21 ./mobile` (engine-linked,
   same `PKG_CONFIG_PATH` as `android-aar`) → copy `gvpn-core.aar` to
   `client/android/app/libs/`.
5. `./gradlew --no-daemon assembleDebug testDebugUnitTest`.
6. Upload the debug APK artifact.

The job's detect-gate (currently keyed on `client/android/settings.gradle[.kts]`)
flips on once this scaffold lands. The separate `android-aar` job stays as-is.

## Data flow

None at runtime in CI: `assembleDebug` proves the Kotlin↔`.aar` binding compiles
and the APK links; `testDebugUnitTest` runs the JVM test. The `Mobile.version()`
reference is the proof the `.aar`'s API is reachable from Kotlin. Running the app
to see the version is a manual device check.

## Error handling / testing

- **Linux `core` job:** the new `mobile.Version()` is covered by a Go unit test
  (non-empty) and the existing vet/`-race` suite.
- **`android` CI job:** `assembleDebug` (build + bind) and `testDebugUnitTest`
  are the SP6a acceptance gate.
- No secrets are involved in SP6a (no bundle, no storage).

## Risks

- **AGP / Gradle / Android SDK / Compose version compatibility** and the flatDir
  `.aar` binding — I cannot run Gradle locally, so this is CI-iterated (expect a
  few pushes, like SP2). Mitigate by pinning AGP/Gradle/Kotlin/Compose-BOM
  versions explicitly and using `--no-daemon`.
- **gomobile `.aar` ↔ Gradle namespace/minSdk** mismatch — gomobile `.aar`s
  target a low API; `minSdk 26` is comfortably above it.

## Execution model

CI is the only build verifier (no local Gradle/Android SDK). Execute **inline**
(push → `gh run watch` → `gh run view --log-failed` → fix), as in SP2–SP5.
