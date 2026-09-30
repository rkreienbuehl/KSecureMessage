// End-to-end example on the JVM: a reference server on SQLite and two clients
// over HTTP, using only published artifacts and public API.

plugins {
    alias(libs.plugins.kotlin.jvm)
    application
}

kotlin {
    jvmToolchain(17)
}

val ksmVersion: String = providers.gradleProperty("ksmVersion").orNull
    ?: error("Pass the KSecureMessage version: -PksmVersion=<version>")

dependencies {
    implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-client-ktor:$ksmVersion")
    implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-storage-client-inmemory:$ksmVersion")
    implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-server-ktor:$ksmVersion")
    implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-storage-server-sqldelight:$ksmVersion")
    implementation(libs.sqldelight.sqlite.driver)
    implementation(libs.ktor.server.cio)
    implementation(libs.ktor.server.content.negotiation)
    // The application's own HTTP client, carrying its authentication (S1.1).
    implementation(libs.ktor.client.core)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.client.engine.defaults)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.kotlinx.coroutines.core)
}

application {
    mainClass.set("dev.kreienbuehl.ksecuremessage.sample.MainKt")
}
