// Release engineering checks for the root build (docs/releasing.md). Gradle
// API, the JDK and SnakeYAML (workflow checks) only: no Kotlin, Android or
// publishing plugin classes here, so these tasks never clash with the plugin
// versions of the main build.

plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(libs.snakeyaml)
}
