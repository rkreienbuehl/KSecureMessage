// Persistent server storage on SQLite through SQLDelight (docs/server-storage.md).
// JVM only, like server:core and server:ktor. The host application creates,
// configures and closes the SqlDriver; this module never creates one.

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.sqldelight)
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    api(project(":storage:core"))
    api(libs.sqldelight.runtime)
    implementation(libs.kotlinx.coroutines.core)

    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(project(":storage:testing"))
    testImplementation(libs.sqldelight.sqlite.driver)
}

sqldelight {
    databases {
        create("ServerDatabase") {
            packageName.set("dev.kreienbuehl.ksecuremessage.storage.server.sqldelight.db")
        }
    }
}
