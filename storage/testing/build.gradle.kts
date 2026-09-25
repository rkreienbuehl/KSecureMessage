import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl

// Shared test fixtures: ClientStorage and StorageKeyProvider contract tests
// for every adapter.
// Not meant to be published.

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
}

kotlin {
    jvm()

    android {
        namespace = "dev.kreienbuehl.ksecuremessage.storage.testing"
        compileSdk = libs.versions.android.compileSdk.get().toInt()
        minSdk = libs.versions.android.minSdk.get().toInt()
    }

    js(IR) { browser(); nodejs() }

    @OptIn(ExperimentalWasmDsl::class)
    wasmJs { browser(); nodejs() }

    iosX64()
    iosArm64()
    iosSimulatorArm64()

    macosX64()
    macosArm64()

    linuxX64()

    mingwX64()

    sourceSets {
        commonMain.dependencies {
            api(project(":storage:core"))
            api(project(":storage:encryption"))
            api(kotlin("test"))
            api(libs.kotlinx.coroutines.test)
        }
        // Test framework binding the other modules' jvmTest also infers.
        jvmMain.dependencies {
            api(kotlin("test-junit"))
        }
        androidMain.dependencies {
            api(kotlin("test-junit"))
        }
    }
}
