plugins {
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
}

group = "dev.kreienbuehl.ksecuremessage"
version = "0.1.0-SNAPSHOT"

allprojects {
    // Unique coordinates per module: several modules share the name "core"
    group = rootProject.group.toString() + path.substringBeforeLast(':').replace(':', '.')
    version = rootProject.version
}
