# Android `.aar` Cross-build Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: this plan is **CI-iterated**, not local-TDD. The build environment (Android NDK) exists only in GitHub Actions; there is no local build to test against. Execute **inline** (the controller drives push → `gh run` → fix), not via per-task subagents — the work is an iterative debug loop against CI, not isolated TDD tasks. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make `gomobile bind ./mobile` produce an Android `.aar` for `core/mobile` by cross-building static OpenSSL 3 for android-arm64 and wiring the cgo `gosttls` build to it, verified by a green CI `android-aar` job.

**Architecture:** A parameterized shell script cross-builds OpenSSL 3 (static, `android-arm64`) with the NDK; a new CI job runs it, then runs `gomobile bind -target=android/arm64 ./mobile` with `PKG_CONFIG_PATH` pointed at the cross-built OpenSSL so `gosttls`'s `#cgo pkg-config: libssl libcrypto` resolves to the Android libs. No Go source changes. The gost engine runtime is out of scope (the `.aar` compiles `gosttls` without the engine, since `ENGINE_by_id` is a runtime call).

**Tech Stack:** GitHub Actions, Android NDK (pinned), OpenSSL 3.x (pinned, static), `golang.org/x/mobile` (`gomobile`/`gobind`), bash. Module `github.com/g00dvin/gvpn/core`.

**Design reference:** `docs/superpowers/specs/2026-06-24-android-aar-cross-build-design.md`.

---

## Conventions

- Branch `feat/android-aar` off `main` (already created; the design spec is committed there).
- Commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **Verification = CI.** After each change: `git push`, then watch the run with `gh run watch --exit-status` or poll `gh pr checks <PR>` / `gh run view <id> --log-failed`. Merge only when the `android-aar` job is green.
- Pinned versions (bump only if a build forces it): OpenSSL `3.3.2`; NDK `26.3.11579264`; Android API level `21`.
- Local checks that DO work without an NDK: `bash -n` (shell syntax), `shellcheck` if available, and a YAML sanity parse (`python3 -c 'import yaml,sys; yaml.safe_load(open(".github/workflows/build.yml"))'`). The OpenSSL/gomobile build itself only runs in CI.

## Decisions locked for this plan

- **arm64-v8a only** for now (`android-arm64`); the script is ABI-parameterized so other ABIs are a one-line CI matrix extension later.
- **Static OpenSSL** (`no-shared`): the `.aar` links `.a`s, no runtime `.so`.
- **Bind target `./mobile`** (run from `core/`), NOT `./core/...`.
- **Steer OpenSSL via `PKG_CONFIG_PATH`**, leaving `gosttls` source unchanged. Fallback (only if pkg-config can't be steered through gomobile's cgo): set `CGO_CFLAGS`/`CGO_LDFLAGS` explicitly in the CI step — decided during Task 3 against real CI output.
- **CI job gating:** `android-aar` activates when `scripts/android/build-openssl-android.sh` exists (added here), matching the repo's detect-then-run convention. The OpenSSL cross-build is cached (key = OpenSSL version + ABI + NDK) so most iterations only re-run the bind.

## File structure

```
scripts/android/build-openssl-android.sh   OpenSSL 3 static cross-build for an Android ABI   (CREATE)
.github/workflows/build.yml                + android-aar job                                 (MODIFY)
client/android/README.md                   how to build the .aar locally; runtime deferred   (CREATE, optional)
```

---

## Task 1: OpenSSL-for-Android cross-build script

**Files:** Create `scripts/android/build-openssl-android.sh`.

- [ ] **Step 1: Create `scripts/android/build-openssl-android.sh`:**

```bash
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
```

- [ ] **Step 2: Local syntax check (no NDK needed)**

Run: `bash -n scripts/android/build-openssl-android.sh && echo "syntax ok"` (and `shellcheck scripts/android/build-openssl-android.sh` if installed; fix any warnings).
Expected: `syntax ok`. (The script cannot be *run* locally — there is no NDK; it runs in CI in Task 3.)

- [ ] **Step 3: Make it executable + commit**

```bash
cd /home/goodvin/git/gvpn
chmod +x scripts/android/build-openssl-android.sh
git add scripts/android/build-openssl-android.sh
git commit -m "build(android): static OpenSSL 3 cross-build script for the NDK

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: CI `android-aar` job

**Files:** Modify `.github/workflows/build.yml`.

- [ ] **Step 1: Add the `android-aar` job**

Add this job to the `jobs:` map in `.github/workflows/build.yml` (e.g. after the existing `android` job). It activates because Task 1 added the script.

```yaml
  android-aar:
    name: Android core .aar (gomobile)
    runs-on: ubuntu-latest
    env:
      OPENSSL_VERSION: "3.3.2"
      NDK_VERSION: "26.3.11579264"
      ANDROID_API: "21"
    steps:
      - uses: actions/checkout@v4
      - name: Detect component
        id: detect
        run: |
          if [ -f scripts/android/build-openssl-android.sh ]; then
            echo "present=true" >> "$GITHUB_OUTPUT"
          else
            echo "present=false" >> "$GITHUB_OUTPUT"
            echo "::notice::scripts/android/ not present — skipping"
          fi
      - if: steps.detect.outputs.present == 'true'
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
      - if: steps.detect.outputs.present == 'true'
        uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: "17"
      - if: steps.detect.outputs.present == 'true'
        uses: android-actions/setup-android@v3
      - name: Install NDK
        if: steps.detect.outputs.present == 'true'
        run: sdkmanager --install "ndk;${NDK_VERSION}"
      - name: Cache cross-built OpenSSL
        if: steps.detect.outputs.present == 'true'
        id: ossl-cache
        uses: actions/cache@v4
        with:
          path: ${{ github.workspace }}/openssl-android
          key: openssl-${{ env.OPENSSL_VERSION }}-arm64-v8a-ndk${{ env.NDK_VERSION }}
      - name: Cross-build OpenSSL for Android
        if: steps.detect.outputs.present == 'true' && steps.ossl-cache.outputs.cache-hit != 'true'
        env:
          ANDROID_NDK_HOME: ${{ env.ANDROID_HOME }}/ndk/${{ env.NDK_VERSION }}
          ABI: arm64-v8a
          PREFIX: ${{ github.workspace }}/openssl-android/arm64-v8a
        run: bash scripts/android/build-openssl-android.sh
      - name: gomobile bind core/mobile -> .aar
        if: steps.detect.outputs.present == 'true'
        working-directory: core
        env:
          ANDROID_NDK_HOME: ${{ env.ANDROID_HOME }}/ndk/${{ env.NDK_VERSION }}
          PKG_CONFIG_PATH: ${{ github.workspace }}/openssl-android/arm64-v8a/lib/pkgconfig
        run: |
          go install golang.org/x/mobile/cmd/gomobile@latest
          go install golang.org/x/mobile/cmd/gobind@latest
          export PATH="$(go env GOPATH)/bin:$PATH"
          gomobile init
          gomobile bind -target=android/arm64 -o "$GITHUB_WORKSPACE/gvpn-core.aar" ./mobile
      - name: Upload .aar
        if: steps.detect.outputs.present == 'true'
        uses: actions/upload-artifact@v4
        with:
          name: gvpn-core-aar
          path: gvpn-core.aar
```

- [ ] **Step 2: Validate the workflow YAML locally**

Run: `python3 -c 'import yaml; yaml.safe_load(open(".github/workflows/build.yml")); print("yaml ok")'`
Expected: `yaml ok`. (If `gh` is configured, `gh workflow view build.yml` after push also lists the new job.)

- [ ] **Step 3: Commit**

```bash
cd /home/goodvin/git/gvpn
git add .github/workflows/build.yml
git commit -m "ci(android): android-aar job — cross-build OpenSSL + gomobile bind

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Iterate the CI job to green

**Files:** as needed — likely small fixes to `scripts/android/build-openssl-android.sh` and/or the `android-aar` job env wiring.

This is the open-ended core of the sub-project: push, read CI, fix, repeat until the `android-aar` job builds the `.aar`. There is no local reproduction.

- [ ] **Step 1: Push and open the PR**

```bash
cd /home/goodvin/git/gvpn
git push -u origin feat/android-aar
gh pr create --base main --head feat/android-aar \
  --title "Android core .aar cross-build (OpenSSL + gomobile)" \
  --body "Cross-builds static OpenSSL 3 for android-arm64 and binds core/mobile to gvpn-core.aar via a new CI android-aar job. Build infra only (no app); the gost engine runtime is a later sub-project. Verified by CI (no local Android toolchain)."
```

- [ ] **Step 2: Watch the run**

```bash
gh run watch --exit-status "$(gh run list --branch feat/android-aar --workflow build.yml --limit 1 --json databaseId -q '.[0].databaseId')"
```
Then, on failure: `gh run view <id> --log-failed | tail -120` to read the failing step.

- [ ] **Step 3: Diagnose + fix (likely failure modes and the fix to try)**

Apply the smallest fix for the observed error, commit, push, re-watch. Known-likely modes:
- **`sdkmanager: command not found`** → `setup-android@v3` puts `cmdline-tools/latest/bin` on PATH; if not, call it via `"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"`, and accept licenses with `yes | sdkmanager --licenses` before installing the NDK.
- **NDK path wrong** → the NDK installs under `$ANDROID_HOME/ndk/$NDK_VERSION`; verify with `ls "$ANDROID_HOME/ndk"` in a debug step and correct `ANDROID_NDK_HOME`.
- **OpenSSL `Configure` can't find the compiler** → ensure `ANDROID_NDK_ROOT` is exported and the LLVM toolchain dir exists (the script checks); confirm the host is `linux-x86_64`.
- **`pkg-config` doesn't resolve to the Android OpenSSL during bind** (the most likely real blocker) → the cgo build runs the host `pkg-config` with `PKG_CONFIG_PATH`; confirm the `.pc` files exist at `openssl-android/arm64-v8a/lib/pkgconfig` (OpenSSL may install to `lib64` — adjust `PKG_CONFIG_PATH` to the actual dir, or set both). If gomobile's per-ABI build doesn't inherit the env, switch to the **fallback**: drop `PKG_CONFIG_PATH` and instead export `CGO_CFLAGS="-I<prefix>/include"` and `CGO_LDFLAGS="-L<prefix>/lib -lssl -lcrypto"` for the bind step (the `gosttls` `#cgo pkg-config` line still runs, so it may be necessary to also provide a stub `.pc`; if so, keep the `.pc` approach and fix only the path).
- **`gomobile bind ./mobile` errors on the package** → ensure the working directory is `core/` (where `go.mod` is) and the path is `./mobile`; run `gomobile init` first; ensure `gobind` is installed and on PATH.
- **Link errors (undefined OpenSSL symbols)** → static link order; ensure `-lssl` precedes `-lcrypto`, and add `-ldl -lpthread` if the linker asks (`CGO_LDFLAGS`).

- [ ] **Step 4: Green**

Repeat Step 3 until `gh run watch --exit-status` returns success for the `android-aar` job and the `gvpn-core.aar` artifact is uploaded. Squash the iteration commits if they are noisy (`git rebase -i` is unavailable here; instead, this task's incremental commits are acceptable to keep — they document the cross-build debugging).

---

## Task 4: Document + finalize

**Files:** Create `client/android/README.md`.

- [ ] **Step 1: Create `client/android/README.md`:**

```markdown
# gvpn Android client

Status: **build-infrastructure only.** This directory currently documents how the
shared Go core is bound for Android. There is no app yet (a Kotlin VpnService UI
binding the `.aar` is a later sub-project), and **GOST TLS does not yet work on a
device** — the `.aar` compiles `core/gosttls` against a cross-built OpenSSL, but
the gost engine/provider runtime on Android is a separate sub-project.

## Building `gvpn-core.aar`

Requires the Android NDK (`ANDROID_NDK_HOME`), Go ≥ 1.24, and JDK 17. The CI
`android-aar` job does this automatically; locally:

\`\`\`bash
# 1. Cross-build static OpenSSL 3 for arm64.
ANDROID_NDK_HOME=/path/to/ndk \
  PREFIX="$PWD/openssl-android/arm64-v8a" ABI=arm64-v8a \
  bash scripts/android/build-openssl-android.sh

# 2. Bind core/mobile against it.
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
gomobile init
cd core && PKG_CONFIG_PATH="$PWD/../openssl-android/arm64-v8a/lib/pkgconfig" \
  ANDROID_NDK_HOME=/path/to/ndk \
  gomobile bind -target=android/arm64 -o ../gvpn-core.aar ./mobile
\`\`\`

The resulting `gvpn-core.aar` exports `mobile.Connect`/`mobile.Tunnel`/
`mobile.StatusReporter` to Kotlin.
```

- [ ] **Step 2: Commit + ensure CI still green**

```bash
cd /home/goodvin/git/gvpn
git add client/android/README.md
git commit -m "docs(android): how to build gvpn-core.aar; runtime deferred

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push
```
Confirm the `android-aar` job is still green after this push (the README doesn't affect it). The PR is mergeable once `android-aar` (and the other required checks) are green.

- [ ] **Step 3: Final review (light)**

This sub-project changes no Go source, so a security review is minimal. Confirm: the script pins versions and fails loudly on a missing NDK; the CI job caches the OpenSSL build; the bind targets `./mobile` only; no secrets in the workflow; `provision`/`server`/`mobile` Go code is untouched (the `.aar` build is purely additive infra). Then the PR is ready to merge.

---

## Self-Review

**Spec coverage (design §2–§5):** milestone 1 (static OpenSSL 3 cross-build for android-arm64) = Task 1 script; milestone 2 (`gomobile bind ./mobile` against it → `.aar`) = Task 2 CI job + Task 3 iteration; CI-as-verifier + iterate-to-green = Task 3; arm64-only, static, env-steered pkg-config, `./mobile` bind target = the locked decisions; deferred gost-engine runtime = stated in Task 4 README and not implemented. No Go source changes (design §6) — confirmed; the only fallback (CGO flags) is CI-step-local.

**Placeholder scan:** the pinned versions (OpenSSL 3.3.2, NDK 26.3.11579264, API 21) are concrete; Task 3 is intentionally open-ended (it is a debug loop) but every likely failure has a concrete fix to try, not a vague "handle errors." The fallback CGO-flags path is specified.

**Consistency:** the `PREFIX`/`PKG_CONFIG_PATH` path `openssl-android/arm64-v8a/lib/pkgconfig` is used consistently across the script default, the CI env, and the README (with Task 3 noting the `lib64` adjustment if OpenSSL installs there). `ANDROID_NDK_HOME=$ANDROID_HOME/ndk/$NDK_VERSION` is consistent across the CI steps. Bind target `./mobile` from `core/` is consistent. Verification is CI throughout (no local build claimed).
