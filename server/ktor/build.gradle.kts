plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    api(project(":server:core"))
    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.content.negotiation)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.kotlinx.serialization.json)

    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.ktor.client.content.negotiation)
    // HTTP contract and end-to-end tests run the real client adapter against the routes.
    testImplementation(project(":client:ktor"))
    testImplementation(project(":storage:client:inmemory"))
    testImplementation(project(":storage:server:inmemory"))
    // Persistent server storage injected into the same routes (docs/server-storage.md).
    testImplementation(project(":storage:server:sqldelight"))
    testImplementation(libs.sqldelight.sqlite.driver)
}
