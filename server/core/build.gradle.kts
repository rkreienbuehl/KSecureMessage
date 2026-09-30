plugins {
    alias(libs.plugins.kotlin.jvm)
}

description = "KSecureMessage server: blind relay, prekey distribution, device authentication and recovery."

kotlin {
    jvmToolchain(17)
}

dependencies {
    api(project(":core:model"))
    api(project(":storage:core"))
    implementation(libs.kotlinx.coroutines.core)

    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(project(":storage:server:inmemory"))
    // N2 registration races run against every server storage adapter (S1.1).
    testImplementation(project(":storage:server:sqldelight"))
    testImplementation(libs.sqldelight.sqlite.driver)
}
