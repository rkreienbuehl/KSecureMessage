import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.sqldelight)
}

kotlin {
    jvm()

    android {
        namespace = "dev.kreienbuehl.ksecuremessage.storage.client.sqldelight"
        compileSdk = libs.versions.android.compileSdk.get().toInt()
        minSdk = libs.versions.android.minSdk.get().toInt()

        // The SQLite tests on a device or emulator, with the Android Keystore provider.
        withDeviceTestBuilder {}.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }

    js(IR) { browser(); nodejs() }

    @OptIn(ExperimentalWasmDsl::class)
    wasmJs { browser(); nodejs() }

    val appleTargets = listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64(),
        macosX64(),
        macosArm64(),
    )
    val nativeTargets = appleTargets + listOf(linuxX64(), mingwX64())

    // Simulated entitlements for the signed keychain host (apple-keychain-host/).
    iosSimulatorArm64().binaries.getTest("DEBUG").linkerOpts(
        "-sectcreate", "__TEXT", "__entitlements", rootProject.file("apple-keychain-host/ios-simulator.entitlements").absolutePath,
    )

    sourceSets {
        commonMain.dependencies {
            api(project(":storage:core"))
            api(project(":storage:encryption"))
            api(project(":storage:rotation:core"))
            api(libs.sqldelight.runtime)
            implementation(libs.sqldelight.async.extensions)
            implementation(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
            implementation(project(":storage:testing"))
            implementation(project(":client:core"))
            implementation(project(":storage:client:inmemory"))
        }

        // Tests need a real SQLite driver. JS/Wasm only have the web worker
        // driver, which needs a browser worker, so they get no tests.
        val sqliteTest by creating { dependsOn(commonTest.get()) }
        jvmTest {
            dependsOn(sqliteTest)
            dependencies { implementation(libs.sqldelight.sqlite.driver) }
        }
        val nativeTest by creating {
            dependsOn(sqliteTest)
            dependencies { implementation(libs.sqldelight.native.driver) }
        }
        // Storage opened with the Keychain provider (docs/storage-key-providers.md).
        val appleTest by creating {
            dependsOn(nativeTest)
            dependencies { implementation(project(":storage:keyprovider:apple")) }
        }
        val macosTest by creating { dependsOn(appleTest) }
        nativeTargets.forEach { target ->
            val testSet = when {
                target.name.startsWith("macos") -> macosTest
                target in appleTargets -> appleTest
                else -> nativeTest
            }
            getByName("${target.name}Test").dependsOn(testSet)
        }
        getByName("androidDeviceTest") {
            dependsOn(sqliteTest)
            dependencies {
                implementation(libs.sqldelight.android.driver)
                implementation(libs.androidx.test.runner)
                implementation(project(":storage:keyprovider:android"))
            }
        }
    }
}

sqldelight {
    databases {
        create("KSecureMessageDatabase") {
            packageName.set("dev.kreienbuehl.ksecuremessage.storage.client.sqldelight.db")
            generateAsync.set(true)
        }
    }
}

// Native test binaries link against the target's libsqlite3, which a
// cross-compiling host does not have. Link and run them only on their own OS.
val hostOs = System.getProperty("os.name").lowercase()
val nativeTestHosts = mapOf("LinuxX64" to hostOs.contains("linux"), "MingwX64" to hostOs.contains("windows"))
nativeTestHosts.forEach { (target, supported) ->
    tasks.matching { it.name == "linkDebugTest$target" || it.name == "${target.replaceFirstChar(Char::lowercase)}Test" }
        .configureEach { onlyIf { supported } }
}

// The simulated entitlements are linked in: relink when they change.
tasks.named("linkDebugTestIosSimulatorArm64") { inputs.file(rootProject.file("apple-keychain-host/ios-simulator.entitlements")) }

// DataProtection tests run only in the signed keychain host (docs/storage-key-providers.md).
extra["keychainHostModes"] = listOf("tests", "relaunch")
apply(from = rootProject.file("apple-keychain-host/keychain-host.gradle.kts"))
