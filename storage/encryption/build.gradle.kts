import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl

// Record-level encryption of sensitive client storage records
// (docs/storage-encryption.md). The AEAD comes from cryptography-kotlin; only
// AesGcm.kt imports it.

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
}

kotlin {
    jvm()

    android {
        namespace = "dev.kreienbuehl.ksecuremessage.storage.encryption"
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
            implementation(libs.cryptography.core)
            implementation(libs.cryptography.random)
            implementation(libs.cryptography.provider.optimal)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}
