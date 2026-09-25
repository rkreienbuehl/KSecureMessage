import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl

// Storage key rotation state machine and backend contract
// (docs/storage-key-rotation.md). No storage, SQL or platform code: a
// persistent storage adapter implements StorageKeyRotationBackend.

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
}

kotlin {
    jvm()

    android {
        namespace = "dev.kreienbuehl.ksecuremessage.storage.rotation"
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
            api(project(":storage:encryption"))
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}
