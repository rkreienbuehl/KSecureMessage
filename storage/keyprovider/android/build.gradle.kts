// Storage key provider on the Android Keystore (docs/storage-key-providers.md).
// Android target only. Keystore behavior is tested on a device or emulator
// (androidDeviceTest); the wrapped key file codec also on the host.

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
}

kotlin {
    android {
        namespace = "dev.kreienbuehl.ksecuremessage.storage.keyprovider.android"
        compileSdk = libs.versions.android.compileSdk.get().toInt()
        minSdk = libs.versions.android.minSdk.get().toInt()

        withHostTestBuilder {}
        withDeviceTestBuilder {}.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }

    sourceSets {
        androidMain.dependencies {
            api(project(":storage:encryption"))
            implementation(libs.kotlinx.coroutines.core)
        }
        getByName("androidHostTest").dependencies {
            implementation(kotlin("test"))
            implementation(kotlin("test-junit"))
        }
        getByName("androidDeviceTest").dependencies {
            implementation(project(":storage:testing"))
            implementation(libs.androidx.test.runner)
        }
    }
}
