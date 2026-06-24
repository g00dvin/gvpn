# gvpn — Android `.aar` cross-build (OpenSSL + gomobile) (Design)

**Status:** approved-in-principle 2026-06-24 (user chose: tackle the cross-compile first, CI-driven, milestones 1–2 before the engine runtime). Second sub-project of the client phase.
**Scope:** make `gomobile bind` of `core/mobile` produce an Android `.aar`, which requires cross-compiling the cgo `gosttls` package against an Android build of OpenSSL 3. This is a **build-infrastructure** sub-project: no application code, no Kotlin. The deliverable is a reproducible cross-build (a script + a CI job) that emits a `.aar`.

## 1. Context & why this is its own sub-project

`core/mobile` (merged, PR #15) is the gomobile-bindable client tunnel API. Binding it for Android runs `gomobile bind -target=android … ./core/mobile`, which cross-compiles every transitive package — including **`gosttls`**, a cgo package that links OpenSSL 3 via `#cgo pkg-config: libssl libcrypto`. The Android NDK ships **no** OpenSSL, so the bind fails: there is no `libssl`/`libcrypto` for the Android target. Producing OpenSSL for Android and wiring the cgo build to it is the real blocker behind every mobile client; it is solved once, here.

**Verification reality (important):** this repository's only Android-capable build environment is **GitHub Actions CI** (`android-actions/setup-android` provides the NDK; the dev/agent environment has no NDK and no emulator). Therefore this sub-project is **iterated against CI**: the cross-build is authored as a script + a CI job, pushed to the branch, and observed via `gh run`/`gh pr checks` until the job is green. There is no local build to verify against. Success criterion = **the CI `android-aar` job builds the `.aar`**.

## 2. Scope: milestones 1–2 only (engine runtime deferred)

The cross-compile decomposes by risk; this sub-project covers the first two:

1. **Cross-build OpenSSL 3 (static) for Android arm64.** Well-trodden: NDK toolchain + OpenSSL's `Configure android-arm64`. Output: `libssl.a`, `libcrypto.a`, headers, and pkg-config `.pc` files under a prefix. *(low risk)*
2. **`gomobile bind ./core/mobile` against that OpenSSL → `.aar`.** Wire the cgo build (via `PKG_CONFIG_PATH` to the cross-built `.pc`s) so `gosttls`'s `#cgo pkg-config: libssl libcrypto` resolves to the Android static libs. Output: `gvpn-core.aar`. *(medium risk — the pkg-config / gomobile-NDK wiring is the fiddly part to iterate)*

**Deferred to a later sub-project (high risk, needs a device/emulator):**

3. **The gost engine at runtime on Android.** The `.aar` from milestone 2 *compiles* `gosttls` (the cgo only needs OpenSSL headers+libs, not the engine — `ENGINE_by_id("gost")` is a **runtime** call), so the `.aar` builds without the engine. But on a real device `gosttls.Init()` would fail until a gost engine (or the OpenSSL-3 gost *provider*) is cross-built for Android and made loadable, and a real GOST handshake is verified on an emulator. That research/runtime work — and whether to use the engine or the provider — is its own sub-project. **This spec explicitly does not make GOST TLS work on a device; it makes the `.aar` build.**

This boundary is deliberate: milestones 1–2 are CI-verifiable real progress; milestone 3 is the unknown and is isolated.

## 3. Approach

- **OpenSSL:** a pinned OpenSSL 3.x release, built **static** (`no-shared`) so the bind links `.a`s and the milestone-2 artifact has no runtime `.so` dependency. Target `android-arm64` first (the primary Android ABI); other ABIs (`x86_64` for the emulator, `armeabi-v7a`) are a trivial loop extension once arm64 works, added only when needed.
- **Build script** `scripts/android/build-openssl-android.sh`: pure shell, parameterized by NDK path, ABI, API level, OpenSSL version, and install prefix. It puts the NDK LLVM toolchain on `PATH`, runs OpenSSL `./Configure android-arm64 -D__ANDROID_API__=<api> no-shared no-tests`, `make` + `make install_sw install_ssldirs`, and leaves `lib/pkgconfig/{libssl,libcrypto,openssl}.pc` under the prefix. Runnable by any dev with an NDK, and by CI.
- **gomobile bind:** `gomobile bind -target=android/arm64 -o gvpn-core.aar ./core/mobile`, with `PKG_CONFIG_PATH=<prefix>/lib/pkgconfig` (and, if needed, `PKG_CONFIG_LIBDIR`/`PKG_CONFIG_SYSROOT_DIR`) exported so the cgo pkg-config lookup resolves to the Android OpenSSL. gomobile drives the NDK clang itself; we only steer the library resolution via env, leaving `gosttls` source unchanged. The bind target is `./core/mobile` (the package with the bindable API), **not** `./core/...` (which would try to bind cmd/main packages and fail — the existing CI job's bind target is wrong and is corrected here).
- **CI:** add a job `android-aar` (ubuntu-latest), gated on the new build script existing (so it activates now and runs henceforth, matching the repo's detect-then-run convention). Steps: checkout → setup-go → setup-java → `setup-android` + install a pinned NDK → run the OpenSSL build script (cache the OpenSSL build by version+ABI+NDK to keep iterations fast) → `gomobile init` → `gomobile bind` → upload `gvpn-core.aar` as an artifact. The existing `android` (gradle app) job stays gated on `client/android/` and is left for the future Android-app sub-project, except its broken `./core/...` bind target is noted for that plan.

## 4. Risks & how they're handled

- **pkg-config not resolving to Android OpenSSL** (most likely failure): iterate the env wiring (`PKG_CONFIG_PATH`/`PKG_CONFIG_LIBDIR`/`PKG_CONFIG_SYSROOT_DIR`) against CI; fall back to setting `CGO_CFLAGS`/`CGO_LDFLAGS` explicitly if pkg-config can't be steered cleanly.
- **gomobile + NDK version mismatch / `gomobile init` issues:** pin the NDK and gomobile/x-mobile versions.
- **Slow iterations:** cache the OpenSSL cross-build (keyed by version+ABI+NDK) so only the bind re-runs on most pushes.
- **Milestone 3 is genuinely uncertain:** explicitly out of scope; the `.aar` building does not imply a working on-device GOST tunnel.

## 5. Deliverables & success criteria

- `scripts/android/build-openssl-android.sh` — reproducible OpenSSL-for-Android static cross-build.
- `.github/workflows/build.yml` — a new `android-aar` job that cross-builds OpenSSL and binds `core/mobile` to `gvpn-core.aar`.
- (Optional) a short `client/android/README.md` documenting how to build the `.aar` locally with an NDK, and stating that on-device GOST runtime is a later sub-project.

**Success = the `android-aar` CI job is green (the `.aar` is produced and uploaded).** Because this is CI-iterated, the implementation plan's "verify" steps are *push and read `gh run`*, not local test runs; the PR is merged only once that job is green.

## 6. Components & boundaries (summary)

| Unit | Responsibility | Notes |
|---|---|---|
| `scripts/android/build-openssl-android.sh` | OpenSSL 3 static cross-build for an Android ABI | parameterized; NDK-driven; emits `.a` + `.pc` |
| CI `android-aar` job | run the script + `gomobile bind ./core/mobile` → `.aar` | the only verifier; pinned NDK/gomobile; OpenSSL build cached |
| (deferred) gost engine/provider for Android + emulator handshake | make GOST TLS actually work on a device | separate sub-project (milestone 3) |

No Go source changes are required (the bind steers OpenSSL via env, not via `gosttls` edits). If the env approach proves impossible, the fallback is a minimal, additive build-tag-free CGO flag adjustment, decided during execution and kept out of the non-Android build path.
