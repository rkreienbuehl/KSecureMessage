import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.kotlin.serialization)
}

description = "KSecureMessage protocol engine: X3DH and Double Ratchet via Kodium, wire, payload, authentication and recovery formats."

kotlin {
    jvm()

    android {
        namespace = "dev.kreienbuehl.ksecuremessage.protocol"
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
            api(project(":core:model"))
            implementation(libs.kodium)
            implementation(libs.kotlincrypto.sha2)
            implementation(libs.kotlinx.coroutines.core)
            implementation(libs.kotlinx.serialization.core)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}
