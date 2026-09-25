plugins {
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
    alias(libs.plugins.sqldelight) apply false
}

group = "dev.kreienbuehl.ksecuremessage"
version = "0.1.0-SNAPSHOT"

allprojects {
    // Unique coordinates per module: several modules share the name "core"
    group = rootProject.group.toString() + path.substringBeforeLast(':').replace(':', '.')
    version = rootProject.version
}

// The JVM target of the multiplatform modules must load on the server
// modules' Java 17 toolchain (Kodium is Java 17 bytecode as well). Without
// this they get the bytecode level of the JDK running Gradle.
subprojects {
    plugins.withId("org.jetbrains.kotlin.multiplatform") {
        extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension> {
            targets.withType<org.jetbrains.kotlin.gradle.targets.jvm.KotlinJvmTarget>().configureEach {
                compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
            }
        }
    }
}

// DataProtection Keychain tests in the signed keychain host
// (apple-keychain-host/, docs/storage-key-providers.md): provider contract,
// SQLDelight storage and relaunch, then the leftover check. Not part of build.
val keychainHostModules = listOf(":storage:keyprovider:apple", ":storage:client:sqldelight")
listOf("macosArm64", "macosX64", "iosSimulatorArm64").forEach { target ->
    val tests = keychainHostModules.map { "$it:${target}KeychainHostTest" }
    tasks.register("${target}KeychainHostTest") {
        group = "verification"
        description = "Runs the DataProtection Keychain tests of $target in a signed, entitled host."
        dependsOn(tests, ":storage:keyprovider:apple:${target}KeychainHostLeftoverCheck")
    }
}
tasks.register("appleKeychainHostTest") {
    group = "verification"
    description = "Runs the DataProtection Keychain tests in the signed macOS host and the entitled iOS simulator host."
    dependsOn("macosArm64KeychainHostTest", "iosSimulatorArm64KeychainHostTest")
}
