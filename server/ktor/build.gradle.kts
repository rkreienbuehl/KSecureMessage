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
    // N7 (S1.3): the host boundary is also tested on a real CIO engine.
    testImplementation(libs.ktor.server.cio)
    testImplementation(libs.ktor.client.content.negotiation)
    // HTTP contract and end-to-end tests run the real client adapter against the routes.
    testImplementation(project(":client:ktor"))
    testImplementation(project(":storage:client:inmemory"))
    testImplementation(project(":storage:server:inmemory"))
    // Persistent server storage injected into the same routes (docs/server-storage.md).
    testImplementation(project(":storage:server:sqldelight"))
    testImplementation(libs.sqldelight.sqlite.driver)
}

// PreS1CleanupTest runs the operator cleanup script (docs/operator/, S1.2 N5,
// S1.3 N6) with the real sqlite3 shell and the audit SQL of
// docs/operating-the-server.md: both are test inputs, so a change reruns the test.
tasks.test {
    val operatingServerDoc = rootProject.layout.projectDirectory.file("docs/operating-the-server.md")
    val preS1Cleanup = rootProject.layout.projectDirectory.file("docs/operator/ksecuremessage-pre-s1-cleanup.sql")
    inputs.file(operatingServerDoc).withPathSensitivity(PathSensitivity.RELATIVE).withPropertyName("operatingServerDoc")
    inputs.file(preS1Cleanup).withPathSensitivity(PathSensitivity.RELATIVE).withPropertyName("preS1Cleanup")
    systemProperty("ksm.docs.operatingServer", operatingServerDoc.asFile.absolutePath)
    systemProperty("ksm.operator.preS1Cleanup", preS1Cleanup.asFile.absolutePath)
}
