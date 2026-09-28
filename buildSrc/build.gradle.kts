// Release engineering checks for the root build (docs/releasing.md). Gradle
// API and JDK only: no Kotlin, Android or publishing plugin classes here, so
// these tasks never clash with the plugin versions of the main build.

plugins {
    `kotlin-dsl`
}

repositories {
    mavenCentral()
}
