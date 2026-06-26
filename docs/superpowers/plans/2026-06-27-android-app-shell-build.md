# Android App Shell — Buildable Scaffold + `.aar` Binding (SP6a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A minimal Kotlin + Jetpack Compose Android app under `client/android/` that binds the engine-linked `gvpn-core.aar` and assembles to a debug APK in CI.

**Architecture:** A new `mobile.Version()` bound function is the linkage probe; a single-activity Compose app displays it. CI rewrites the (broken) `android` job to build the engine-linked `.aar` (reusing the SP2/SP3 scripts), drop it in `app/libs/`, and run `gradle assembleDebug testDebugUnitTest`.

**Tech Stack:** Kotlin 1.9.24, Jetpack Compose (BOM 2024.06.00, compiler 1.5.14), AGP 8.5.2, Gradle 8.7, JDK 17, gomobile, Android NDK 26 / API 21, GitHub Actions.

**Execution model:** CI is the only build verifier (no local Gradle/Android SDK). Task 1 is locally verifiable (Go). Tasks 2–3 are CI-iterated (push → `gh run watch` → `gh run view --log-failed` → fix). Execute **inline**.

**Branch:** `feat/android-app-shell` (already created, spec already committed there).

---

## File Structure

- **Create** `core/mobile/version.go` + `core/mobile/version_test.go` — the bound linkage probe. (Task 1)
- **Create** the Gradle app under `client/android/`: `settings.gradle.kts`, `build.gradle.kts`, `gradle.properties`, `app/build.gradle.kts`, `app/src/main/AndroidManifest.xml`, `app/src/main/java/dev/gvpn/MainActivity.kt`, `app/src/test/java/dev/gvpn/SmokeTest.kt`. (Task 2)
- **Modify** `.gitignore` — ignore the dropped-in `.aar` and Gradle build dirs. (Task 2)
- **Modify** `.github/workflows/build.yml` — rewrite the `android` job. (Task 3)
- **Modify** `client/android/README.md` — note the app shell. (Task 4)

> **Note (deviation from spec):** the spec mentioned a committed Gradle wrapper.
> The wrapper requires a binary `gradle-wrapper.jar` that cannot be authored as
> text. Instead CI provisions Gradle via `gradle/actions/setup-gradle@v4`
> (`gradle-version: 8.7`) and invokes `gradle` directly — no committed wrapper.
> Local developers install Gradle 8.7 themselves (SP6a is CI-gated).

---

## Task 1: `mobile.Version()` linkage probe

**Files:**
- Create: `core/mobile/version.go`
- Create: `core/mobile/version_test.go`

Locally verifiable on Linux (cgo links OpenSSL).

- [ ] **Step 1: Write the failing test**

Create `core/mobile/version_test.go`:

```go
package mobile

import "testing"

func TestVersionNonEmpty(t *testing.T) {
	if Version() == "" {
		t.Fatal("Version() returned empty string")
	}
}
```

- [ ] **Step 2: Run it to verify it fails (undefined)**

Run: `cd core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./mobile/ -run TestVersionNonEmpty`
Expected: build failure — `undefined: Version`.

- [ ] **Step 3: Implement `Version()`**

Create `core/mobile/version.go`:

```go
package mobile

import "github.com/g00dvin/gvpn/core/gosttls"

// Version returns the linked OpenSSL/GOST version string. It is a harmless,
// no-argument bound call the Android shell uses to prove the .aar binding links
// at build time; it does not initialize the gost engine.
func Version() string {
	return gosttls.Version()
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./mobile/ -run TestVersionNonEmpty -v`
Expected: `--- PASS: TestVersionNonEmpty`.

- [ ] **Step 5: Commit**

```bash
git add core/mobile/version.go core/mobile/version_test.go
git commit -m "mobile: add Version() bound linkage probe for the Android shell"
```

---

## Task 2: Gradle app scaffold

**Files:**
- Create: `client/android/settings.gradle.kts`
- Create: `client/android/build.gradle.kts`
- Create: `client/android/gradle.properties`
- Create: `client/android/app/build.gradle.kts`
- Create: `client/android/app/src/main/AndroidManifest.xml`
- Create: `client/android/app/src/main/java/dev/gvpn/MainActivity.kt`
- Create: `client/android/app/src/test/java/dev/gvpn/SmokeTest.kt`
- Modify: `.gitignore`

No local Gradle; these are authored and verified by CI (Task 3).

- [ ] **Step 1: `settings.gradle.kts`**

```kotlin
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "gvpn"
include(":app")
```

(`implementation(files(...))` is a file dependency, not a project repository, so
it is compatible with `FAIL_ON_PROJECT_REPOS`.)

- [ ] **Step 2: root `build.gradle.kts`**

```kotlin
plugins {
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
}
```

- [ ] **Step 3: `gradle.properties`**

```properties
org.gradle.jvmargs=-Xmx2048m
android.useAndroidX=true
kotlin.code.style=official
```

- [ ] **Step 4: `app/build.gradle.kts`**

```kotlin
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.gvpn"
    compileSdk = 34

    defaultConfig {
        applicationId = "dev.gvpn"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }
}

dependencies {
    implementation(files("libs/gvpn-core.aar"))
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.0")
    testImplementation("junit:junit:4.13.2")
}
```

- [ ] **Step 5: `app/src/main/AndroidManifest.xml`**

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:allowBackup="false"
        android:label="gvpn">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

- [ ] **Step 6: `app/src/main/java/dev/gvpn/MainActivity.kt`**

```kotlin
package dev.gvpn

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import mobile.Mobile

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface {
                    Text("gvpn core: " + Mobile.version())
                }
            }
        }
    }
}
```

> The bound symbol: gomobile binds Go package `mobile` as Java class
> `mobile.Mobile` with static methods; the Go `Version()` becomes `version()`.
> If the CI build reports an unresolved reference, confirm the exact
> package/class/method from the generated `.aar` (`unzip -l gvpn-core.aar`;
> inspect `classes.jar`) and adjust the import + call accordingly.

- [ ] **Step 7: `app/src/test/java/dev/gvpn/SmokeTest.kt`**

A pure-JVM unit test (it must NOT call `Mobile.version()`, whose native lib does
not load on the JVM test host) — it just wires `testDebugUnitTest`:

```kotlin
package dev.gvpn

import org.junit.Assert.assertTrue
import org.junit.Test

class SmokeTest {
    @Test
    fun harnessRuns() {
        assertTrue("unit-test harness wired", 1 + 1 == 2)
    }
}
```

- [ ] **Step 8: `.gitignore` — ignore the dropped-in `.aar` and build dirs**

Append to the repo-root `.gitignore`:

```gitignore
# Android app build artifacts
client/android/app/libs/*.aar
client/android/**/build/
client/android/.gradle/
client/android/local.properties
```

- [ ] **Step 9: Commit**

```bash
git add client/android/settings.gradle.kts client/android/build.gradle.kts \
  client/android/gradle.properties client/android/app/build.gradle.kts \
  client/android/app/src .gitignore
git commit -m "android: minimal Compose app shell binding gvpn-core.aar"
```

---

## Task 3: CI — rewrite the `android` job

**Files:**
- Modify: `.github/workflows/build.yml`

Replace the existing `android` job (which runs `gomobile bind ./core/...` to a
wrong path and `assembleRelease` against a non-existent project) with one that
builds the engine-linked `.aar`, drops it in `app/libs/`, and runs Gradle.

- [ ] **Step 1: Replace the `android` job**

In `.github/workflows/build.yml`, replace the whole `android:` job block with:

```yaml
  android:
    name: Android client (gomobile + gradle)
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
          if [ -f client/android/settings.gradle.kts ] || [ -f client/android/settings.gradle ]; then
            echo "present=true" >> "$GITHUB_OUTPUT"
          else
            echo "present=false" >> "$GITHUB_OUTPUT"
            echo "::notice::client/android/ app not present — skipping"
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
      - name: Cross-build gost engine for Android
        if: steps.detect.outputs.present == 'true'
        env:
          ANDROID_NDK_HOME: ${{ env.ANDROID_HOME }}/ndk/${{ env.NDK_VERSION }}
          ABI: arm64-v8a
          OPENSSL_PREFIX: ${{ github.workspace }}/openssl-android/arm64-v8a
          PREFIX: ${{ github.workspace }}/gost-engine-android/arm64-v8a
        run: bash scripts/android/build-gost-engine-android.sh
      - name: gomobile bind core/mobile -> app/libs/gvpn-core.aar
        if: steps.detect.outputs.present == 'true'
        working-directory: core
        env:
          ANDROID_NDK_HOME: ${{ env.ANDROID_HOME }}/ndk/${{ env.NDK_VERSION }}
          PKG_CONFIG_PATH: ${{ github.workspace }}/openssl-android/arm64-v8a/lib/pkgconfig:${{ github.workspace }}/gost-engine-android/arm64-v8a/lib/pkgconfig
        run: |
          go install golang.org/x/mobile/cmd/gomobile@latest
          go install golang.org/x/mobile/cmd/gobind@latest
          export PATH="$(go env GOPATH)/bin:$PATH"
          go get golang.org/x/mobile/bind
          gomobile init
          mkdir -p "$GITHUB_WORKSPACE/client/android/app/libs"
          gomobile bind -target=android/arm64 -androidapi "${ANDROID_API}" \
            -o "$GITHUB_WORKSPACE/client/android/app/libs/gvpn-core.aar" ./mobile
      - name: Set up Gradle
        if: steps.detect.outputs.present == 'true'
        uses: gradle/actions/setup-gradle@v4
        with:
          gradle-version: "8.7"
      - name: Assemble debug APK + unit tests
        if: steps.detect.outputs.present == 'true'
        working-directory: client/android
        run: gradle --no-daemon assembleDebug testDebugUnitTest
      - name: Upload APK
        if: steps.detect.outputs.present == 'true'
        uses: actions/upload-artifact@v4
        with:
          name: gvpn-android-apk
          path: client/android/app/build/outputs/apk/debug/*.apk
```

- [ ] **Step 2: Validate YAML, push, open PR, iterate to green**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/build.yml'))" && echo "YAML OK"
git add .github/workflows/build.yml
git commit -m "ci: build the Android app (engine .aar + gradle assembleDebug)"
git push -u origin feat/android-app-shell
gh pr create --title "Android app shell: buildable Compose scaffold + .aar binding (SP6a)" --body "<summary>"
gh run list --branch feat/android-app-shell --limit 1
gh run watch <run-id> --exit-status
gh run view <run-id> --log-failed
```
Iterate until the `android` job (and all required checks) are green. Likely
friction and where to fix it: the `Mobile.version()` import (Task 2 Step 6 —
confirm the generated symbol); AGP/Gradle/Compose-compiler/SDK version
compatibility (Task 2 Step 4 + the `gradle-version`); SDK license/build-tools
auto-provisioning by `setup-android`.

---

## Task 4: Docs + finalize

**Files:**
- Modify: `client/android/README.md`

- [ ] **Step 1: Note the app shell**

In `client/android/README.md`, add a short section: the `client/android/` Gradle
app (Kotlin + Compose) binds `gvpn-core.aar` and assembles a debug APK in the
`android` CI job; it currently displays the bound `mobile.Version()` string and
has no VpnService/connect yet (SP6b). Mention local build needs Gradle 8.7 + the
`.aar` in `app/libs/` (built via the `android-aar` steps).

- [ ] **Step 2: Confirm CI still green and commit**

```bash
git add client/android/README.md
git commit -m "docs(android): note the buildable Compose app shell (SP6a)"
git push
```
Confirm the README push keeps the `android` job (and other required checks)
green. The PR is mergeable once all checks are green.

---

## Self-Review

**Spec coverage:**
- `mobile.Version()` linkage probe (spec Components) → Task 1.
- Gradle Compose app binding the `.aar`, single activity showing the bound call (spec Components) → Task 2.
- CI rewrite of the `android` job: engine `.aar` → `app/libs/` → `assembleDebug testDebugUnitTest` → upload APK (spec CI) → Task 3.
- JVM unit-test harness (spec acceptance) → Task 2 Step 7 + Task 3 `testDebugUnitTest`.
- Docs → Task 4.
- Out of scope (VpnService, storage, import, connect) → not present.

**Placeholder scan:** the PR `--body "<summary>"` (Task 3) is a CLI argument filled at run time. The `Mobile.version()` symbol caveat (Task 2 Step 6) is a concrete CI-confirm step with the exact command to resolve it, not a vague TODO. No "add error handling"/uncoded steps.

**Type consistency:** `mobile.Version()` (Go, Task 1) ↔ `Mobile.version()` (Kotlin, Task 2) — the gomobile name-mangling caveat is documented. Pinned versions are consistent across Task 2 (`app/build.gradle.kts`: AGP 8.5.2, Kotlin 1.9.24, compose compiler 1.5.14, BOM 2024.06.00) and Task 3 (`gradle-version: 8.7`, NDK 26.3.11579264, API 21). `namespace`/`applicationId` `dev.gvpn` matches the Kotlin package `dev.gvpn` and the `.aar` path `client/android/app/libs/gvpn-core.aar` is identical in Task 2 (`build.gradle.kts`), Task 3 (gomobile `-o`), and `.gitignore`.
