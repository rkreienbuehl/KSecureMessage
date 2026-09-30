plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

description = "KSecureMessage server HTTP routes on Ktor (HTTP API v1)."

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

// PreS1CleanupTest runs the operator SQL of docs/operating-the-server.md verbatim
// (S1.2, finding N5): the page is a test input, so a doc change reruns the test.
tasks.test {
    val operatingServerDoc = rootProject.layout.projectDirectory.file("docs/operating-the-server.md")
    inputs.file(operatingServerDoc).withPathSensitivity(PathSensitivity.RELATIVE).withPropertyName("operatingServerDoc")
    systemProperty("ksm.docs.operatingServer", operatingServerDoc.asFile.absolutePath)
}
