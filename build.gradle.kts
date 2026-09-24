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
