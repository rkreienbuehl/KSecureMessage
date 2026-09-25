// Storage key provider on the Apple Keychain (docs/storage-key-providers.md).
// Apple targets only: the Security framework does not exist elsewhere.

plugins {
    alias(libs.plugins.kotlin.multiplatform)
}

kotlin {
    val iosTargets = listOf(iosX64(), iosArm64(), iosSimulatorArm64())
    val macosTargets = listOf(macosX64(), macosArm64())

    // Simulated entitlements for the signed keychain host (apple-keychain-host/).
    iosSimulatorArm64().binaries.getTest("DEBUG").linkerOpts(
        "-sectcreate", "__TEXT", "__entitlements", rootProject.file("apple-keychain-host/ios-simulator.entitlements").absolutePath,
    )

    sourceSets {
        // No default hierarchy (gradle.properties): declare the shared source sets.
        val appleMain by creating {
            dependsOn(commonMain.get())
            dependencies {
                api(project(":storage:encryption"))
                implementation(libs.kotlinx.coroutines.core)
            }
        }
        val appleTest by creating {
            dependsOn(commonTest.get())
            dependencies {
                implementation(kotlin("test"))
                implementation(project(":storage:testing"))
            }
        }
        val macosMain by creating { dependsOn(appleMain) }
        val macosTest by creating { dependsOn(appleTest) }
        iosTargets.forEach { target ->
            getByName("${target.name}Main").dependsOn(appleMain)
            getByName("${target.name}Test").dependsOn(appleTest)
        }
        macosTargets.forEach { target ->
            getByName("${target.name}Main").dependsOn(macosMain)
            getByName("${target.name}Test").dependsOn(macosTest)
        }
    }
}

// The simulated entitlements are linked in: relink when they change.
tasks.named("linkDebugTestIosSimulatorArm64") { inputs.file(rootProject.file("apple-keychain-host/ios-simulator.entitlements")) }

// DataProtection tests run only in the signed keychain host (docs/storage-key-providers.md).
extra["keychainHostModes"] = listOf("tests")
extra["keychainHostLeftoverCheck"] = true
apply(from = rootProject.file("apple-keychain-host/keychain-host.gradle.kts"))
