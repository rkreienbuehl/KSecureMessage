import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.sqldelight)
}

kotlin {
    jvm()

    android {
        namespace = "dev.kreienbuehl.ksecuremessage.storage.sqldelight"
        compileSdk = libs.versions.android.compileSdk.get().toInt()
        minSdk = libs.versions.android.minSdk.get().toInt()
    }

    js(IR) { browser(); nodejs() }

    @OptIn(ExperimentalWasmDsl::class)
    wasmJs { browser(); nodejs() }

    val nativeTargets = listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64(),
        macosX64(),
        macosArm64(),
        linuxX64(),
        mingwX64(),
    )

    sourceSets {
        commonMain.dependencies {
            api(project(":storage:core"))
            api(project(":storage:encryption"))
            api(libs.sqldelight.runtime)
            implementation(libs.sqldelight.async.extensions)
            implementation(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
            implementation(project(":storage:testing"))
            implementation(project(":client:core"))
            implementation(project(":storage:inmemory"))
        }

        // Tests need a real SQLite driver. JS/Wasm only have the web worker
        // driver, which needs a browser worker, so they get no tests.
        val sqliteTest by creating { dependsOn(commonTest.get()) }
        jvmTest {
            dependsOn(sqliteTest)
            dependencies { implementation(libs.sqldelight.sqlite.driver) }
        }
        val nativeTest by creating {
            dependsOn(sqliteTest)
            dependencies { implementation(libs.sqldelight.native.driver) }
        }
        nativeTargets.forEach { target ->
            getByName("${target.name}Test").dependsOn(nativeTest)
        }
    }
}

sqldelight {
    databases {
        create("KSecureMessageDatabase") {
            packageName.set("dev.kreienbuehl.ksecuremessage.storage.sqldelight.db")
            generateAsync.set(true)
        }
    }
}

// Native test binaries link against the target's libsqlite3, which a
// cross-compiling host does not have. Link and run them only on their own OS.
val hostOs = System.getProperty("os.name").lowercase()
val nativeTestHosts = mapOf("LinuxX64" to hostOs.contains("linux"), "MingwX64" to hostOs.contains("windows"))
nativeTestHosts.forEach { (target, supported) ->
    tasks.matching { it.name == "linkDebugTest$target" || it.name == "${target.replaceFirstChar(Char::lowercase)}Test" }
        .configureEach { onlyIf { supported } }
}
