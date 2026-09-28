@file:OptIn(org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation::class)

import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm
import com.vanniktech.maven.publish.KotlinMultiplatform
import com.vanniktech.maven.publish.MavenPublishBaseExtension
import com.vanniktech.maven.publish.SourcesJar

plugins {
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
    alias(libs.plugins.sqldelight) apply false
    alias(libs.plugins.maven.publish) apply false
    alias(libs.plugins.dokka) apply false
    base
}

group = "dev.kreienbuehl.ksecuremessage"

// The one authoritative project version (docs/releasing.md). Published
// coordinates: group KsmRelease.GROUP, artifact ID ksecuremessage-<module path>.
version = "0.1.0-SNAPSHOT"

allprojects {
    // Unique internal project coordinates: several modules share the name
    // "core". Publications get their own group and artifact IDs (below).
    group = rootProject.group.toString() + path.substringBeforeLast(':').replace(':', '.')
    version = rootProject.version
}

// The JVM target of the multiplatform modules must load on the server
// modules' Java 17 toolchain (Kodium is Java 17 bytecode as well). Without
// this they get the bytecode level of the JDK running Gradle.
subprojects {
    plugins.withId("org.jetbrains.kotlin.multiplatform") {
        extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension> {
            targets.withType<org.jetbrains.kotlin.gradle.targets.jvm.KotlinJvmTarget>().configureEach {
                compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
            }
        }
    }
}

// Published modules (buildSrc/src/main/kotlin/KsmRelease.kt): Maven
// publication with sources and Dokka documentation jars, signing only when a
// key is supplied, and the public API baseline (checkKotlinAbi/updateKotlinAbi).
val releaseRepository = layout.buildDirectory.dir("release-repo")
subprojects {
    // The opt-in marker for cross-module plumbing (InternalKSecureMessageApi):
    // every module of this build may use it, consumers must opt in explicitly.
    plugins.withId("org.jetbrains.kotlin.multiplatform") {
        extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension> {
            compilerOptions.optIn.add("dev.kreienbuehl.ksecuremessage.InternalKSecureMessageApi")
        }
    }
    plugins.withId("org.jetbrains.kotlin.jvm") {
        extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension> {
            compilerOptions.optIn.add("dev.kreienbuehl.ksecuremessage.InternalKSecureMessageApi")
        }
    }

    if (path !in KsmRelease.publishedModules) return@subprojects

    apply(plugin = "com.vanniktech.maven.publish.base")
    apply(plugin = "org.jetbrains.dokka")

    extensions.configure<MavenPublishBaseExtension> {
        coordinates(KsmRelease.GROUP, KsmRelease.artifactId(path), version.toString())
        pom {
            name.set(KsmRelease.artifactId(path))
            description.set(provider { requireNotNull(project.description) { "$path needs a description" } })
            url.set(KsmRelease.PROJECT_URL)
            inceptionYear.set("2026")
            licenses {
                license {
                    name.set("Apache-2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    distribution.set("repo")
                }
            }
            developers {
                developer {
                    id.set("rkreienbuehl")
                    name.set("Roger Kreienbühl")
                    url.set("https://github.com/rkreienbuehl")
                }
            }
            scm {
                url.set(KsmRelease.PROJECT_URL)
                connection.set("scm:git:${KsmRelease.PROJECT_URL}.git")
                developerConnection.set("scm:git:ssh://git@github.com/rkreienbuehl/KSecureMessage.git")
            }
        }
        // Configured, never run by the build or CI (docs/releasing.md).
        publishToMavenCentral(automaticRelease = false)
        // Keys come only from outside the repository (ORG_GRADLE_PROJECT_signingInMemoryKey ...).
        if (providers.gradleProperty("signingInMemoryKey").isPresent) signAllPublications()
    }
    extensions.configure<PublishingExtension> {
        repositories {
            maven {
                name = "releaseCheck"
                url = uri(releaseRepository)
            }
        }
    }

    val documentation = JavadocJar.Dokka("dokkaGeneratePublicationHtml")
    // SQLDelight generates public database/query classes and has no option to
    // make them internal. They are not KSecureMessage API: the adapters expose
    // only open(driver, ...) and Schema. Excluded from the ABI baseline and
    // documented in docs/security-review.md.
    val generatedSqlDelightPackage = "dev.kreienbuehl.ksecuremessage.**.sqldelight.db.**"
    plugins.withId("org.jetbrains.kotlin.multiplatform") {
        extensions.configure<MavenPublishBaseExtension> {
            configure(KotlinMultiplatform(javadocJar = documentation, sourcesJar = SourcesJar.Sources()))
        }
        extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension> {
            abiValidation {
                filters { exclude { byNames.add(generatedSqlDelightPackage) } }
            }
        }
    }
    plugins.withId("org.jetbrains.kotlin.jvm") {
        extensions.configure<MavenPublishBaseExtension> {
            configure(KotlinJvm(javadocJar = documentation, sourcesJar = SourcesJar.Sources()))
        }
        extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension> {
            abiValidation {
                filters { exclude { byNames.add(generatedSqlDelightPackage) } }
            }
        }
    }
}

// JS/Wasm tests run on Node.js (docs/supported-platforms.md). The Node
// distribution comes from the repository declared in settings.gradle.kts, so
// the Kotlin plugin must not add its own project repository.
allprojects {
    plugins.withType<org.jetbrains.kotlin.gradle.targets.js.nodejs.NodeJsPlugin> {
        extensions.getByType<org.jetbrains.kotlin.gradle.targets.js.nodejs.NodeJsEnvSpec>().downloadBaseUrl.set(null as String?)
    }
    plugins.withType<org.jetbrains.kotlin.gradle.targets.wasm.nodejs.WasmNodeJsPlugin> {
        extensions.getByType<org.jetbrains.kotlin.gradle.targets.wasm.nodejs.WasmNodeJsEnvSpec>().downloadBaseUrl.set(null as String?)
    }
}

// Compile-only runtimes for v0.x (docs/supported-platforms.md), disabled
// explicitly, never skipped silently:
// - JS and Wasm in a browser: the browser test tasks need Chrome and are not
//   part of the release gate.
// - Wasm on Node.js: Kodium's randomness dependency (kotlincrypto crypto-rand
//   0.6.0) calls CommonJS require, which the ESM modules of Kotlin/Wasm do not
//   have, so every key generation fails at runtime. Runtime unsupported.
subprojects {
    val compileOnlyTestTasks = setOf("jsBrowserTest", "wasmJsBrowserTest", "wasmJsNodeTest")
    tasks.matching { it.name in compileOnlyTestTasks }.configureEach {
        enabled = false
    }
    // Kodium's pure Kotlin curve arithmetic is slow on Kotlin/JS; Mocha's 2 s
    // default times out on key generation and session setup.
    tasks.withType<org.jetbrains.kotlin.gradle.targets.js.testing.KotlinJsTest>().configureEach {
        useMocha { timeout = "900s" }
    }
}

// DataProtection Keychain tests in the signed keychain host
// (apple-keychain-host/, docs/storage-key-providers.md): provider contract,
// SQLDelight storage and relaunch, then the leftover check. Not part of build.
val keychainHostModules = listOf(":storage:keyprovider:apple", ":storage:client:sqldelight")
listOf("macosArm64", "macosX64", "iosSimulatorArm64").forEach { target ->
    val tests = keychainHostModules.map { "$it:${target}KeychainHostTest" }
    tasks.register("${target}KeychainHostTest") {
        group = "verification"
        description = "Runs the DataProtection Keychain tests of $target in a signed, entitled host."
        dependsOn(tests, ":storage:keyprovider:apple:${target}KeychainHostLeftoverCheck")
    }
}
tasks.register("appleKeychainHostTest") {
    group = "verification"
    description = "Runs the DataProtection Keychain tests in the signed macOS host and the entitled iOS simulator host."
    dependsOn("macosArm64KeychainHostTest", "iosSimulatorArm64KeychainHostTest")
}

// Release engineering checks (docs/releasing.md; implementation in buildSrc).

val checkReleaseConventions by tasks.registering(CheckReleaseConventions::class) {
    group = "verification"
    description = "Checks version, README, release checklist, CI workflows, API dump dependency leaks and secrets."
    projectVersion.set(version.toString())
    readme.set(layout.projectDirectory.file("README.md"))
    wrapperProperties.set(layout.projectDirectory.file("gradle/wrapper/gradle-wrapper.properties"))
    releasingDoc.set(layout.projectDirectory.file("docs/releasing.md"))
    ciWorkflow.set(layout.projectDirectory.file(".github/workflows/ci.yml"))
    workflows.from(fileTree(".github/workflows") { include("*.yml", "*.yaml") })
    rootDirectory.set(layout.projectDirectory)
    apiDumps.from(KsmRelease.publishedModules.map { module ->
        fileTree(module.removePrefix(":").replace(':', '/') + "/api") { include("**/*.api") }
    })
    candidateFiles.set(
        providers.exec { commandLine("git", "ls-files", "--cached", "--others", "--exclude-standard") }
            .standardOutput.asText.map { it.lines().filter(String::isNotBlank) },
    )
}
tasks.named("check") { dependsOn(checkReleaseConventions) }

tasks.register<VerifyTestExecution>("verifyTestExecution") {
    group = "verification"
    description = "Fails unless every test task of the supported test matrix for this host ran with tests (run after build)."
    expectations.set(KsmRelease.testExpectations.map { it.encode() })
    rootDirectory.set(layout.projectDirectory)
}

val cleanReleaseRepository by tasks.registering(Delete::class) {
    delete(releaseRepository)
}
val publishToReleaseRepository by tasks.registering {
    group = "publishing"
    description = "Publishes every published module to build/release-repo."
    dependsOn(KsmRelease.publishedModules.map { "$it:publishAllPublicationsToReleaseCheckRepository" })
}
subprojects {
    tasks.withType<PublishToMavenRepository>().configureEach {
        mustRunAfter(":cleanReleaseRepository")
    }
}
val inspectReleaseArtifacts by tasks.registering(InspectReleaseArtifacts::class) {
    group = "verification"
    description = "Inspects build/release-repo: exact artifact set, POMs, sources/docs jars, no test or secret files."
    dependsOn(cleanReleaseRepository, publishToReleaseRepository)
    repository.set(releaseRepository)
    this.version.set(project.version.toString())
    expectedArtifacts.set(KsmRelease.publishedModules.map(KsmRelease::artifactId))
    forbiddenArtifacts.set(KsmRelease.neverPublishedModules.map(KsmRelease::artifactId))
    report.set(layout.buildDirectory.file("reports/release-artifacts.txt"))
}
val checkConsumerIsolation by tasks.registering(CheckConsumerIsolation::class) {
    group = "verification"
    description = "Checks that the consumer fixture resolves KSecureMessage only from the release repository."
    buildFiles.from(fileTree("samples/jvm-e2e") { include("**/*.gradle.kts"); exclude("**/build/**", "**/.gradle/**") })
}
val consumerSmokeTest by tasks.registering(Exec::class) {
    group = "verification"
    description = "Builds and runs the consumer fixture (samples/jvm-e2e) against build/release-repo."
    dependsOn(inspectReleaseArtifacts, checkConsumerIsolation)
    val smokeTasks = buildList {
        add(":app:build")
        add(":app:run")
        add(":kmp-smoke:smokeCompile")
    }
    workingDir = layout.projectDirectory.dir("samples/jvm-e2e").asFile
    commandLine(
        layout.projectDirectory.file("gradlew").asFile.absolutePath,
        "--no-daemon",
        "-PksmRepo=${releaseRepository.get().asFile.absolutePath}",
        "-PksmVersion=$version",
        *smokeTasks.toTypedArray(),
    )
}
tasks.register("verifyPublication") {
    group = "verification"
    description = "Publishes to build/release-repo, inspects the artifacts and builds and runs the consumer fixture."
    dependsOn(inspectReleaseArtifacts, consumerSmokeTest)
}
