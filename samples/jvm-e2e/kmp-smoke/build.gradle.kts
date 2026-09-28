// Compile-only check that the published Gradle module metadata resolves the
// right variant for each Kotlin target.

plugins {
    alias(libs.plugins.kotlin.multiplatform)
}

val ksmVersion: String = providers.gradleProperty("ksmVersion").orNull
    ?: error("Pass the KSecureMessage version: -PksmVersion=<version>")

kotlin {
    jvm()
    js(IR) { nodejs() }
    @OptIn(org.jetbrains.kotlin.gradle.ExperimentalWasmDsl::class)
    wasmJs { nodejs() }
    linuxX64()
    mingwX64()
    val appleTargets = if (System.getProperty("os.name").lowercase().contains("mac")) {
        listOf(macosArm64(), iosSimulatorArm64(), iosArm64())
    } else {
        emptyList()
    }

    sourceSets {
        commonMain.dependencies {
            implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-client-core:$ksmVersion")
            implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-storage-client-inmemory:$ksmVersion")
            implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-storage-client-sqldelight:$ksmVersion")
        }
        if (appleTargets.isNotEmpty()) {
            val appleMain by creating {
                dependsOn(commonMain.get())
                dependencies { implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-storage-keyprovider-apple:$ksmVersion") }
            }
            appleTargets.forEach { getByName("${it.name}Main").dependsOn(appleMain) }
        }
    }
}

// Compiles every configured target's main code; no tests, no Node.js download.
tasks.register("smokeCompile") {
    group = "verification"
    description = "Compiles the smoke code for every target against the published artifacts."
    dependsOn(kotlin.targets.filter { it.name != "metadata" }.map { "compileKotlin${it.name.replaceFirstChar(Char::uppercase)}" })
}
