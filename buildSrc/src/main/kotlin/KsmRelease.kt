/**
 * Publication scope and supported test matrix of KSecureMessage
 * (docs/releasing.md, docs/supported-platforms.md). The root build script and
 * the release checks read these lists; change them together with the docs.
 */
object KsmRelease {
    /** Maven group of every published artifact. Internal project groups differ (see root build script). */
    const val GROUP: String = "dev.kreienbuehl.ksecuremessage"

    const val ARTIFACT_PREFIX: String = "ksecuremessage"

    const val PROJECT_URL: String = "https://github.com/rkreienbuehl/KSecureMessage"

    /** The private vulnerability reporting path SECURITY.md must name (GitHub private vulnerability reporting). */
    const val VULNERABILITY_REPORTING_URL: String = "$PROJECT_URL/security/advisories/new"

    /** Maven Central snapshot repository (Central Portal) that `publishToMavenCentral` uploads SNAPSHOT versions to. */
    const val CENTRAL_SNAPSHOT_REPOSITORY: String = "https://central.sonatype.com/repository/maven-snapshots/"

    /**
     * Central Portal endpoint serving validated but unpublished deployments of
     * the namespace as a Maven repository (needs the user token as a bearer).
     */
    const val CENTRAL_DEPLOYMENT_REPOSITORY: String = "https://central.sonatype.com/api/v1/publisher/deployments/download/"

    /**
     * How publications are signed, from keys supplied outside the repository
     * (docs/releasing.md, "Signing"): [IN_MEMORY] from `signingInMemoryKey`
     * (CI secrets), [GPG_AGENT] from `signing.gnupg.keyName` (the maintainer's
     * gpg agent). `null`: unsigned (local release checks only).
     */
    enum class SigningMode { IN_MEMORY, GPG_AGENT }

    fun signingMode(providers: org.gradle.api.provider.ProviderFactory): SigningMode? = when {
        providers.gradleProperty("signingInMemoryKey").isPresent -> SigningMode.IN_MEMORY
        providers.gradleProperty("signing.gnupg.keyName").isPresent -> SigningMode.GPG_AGENT
        else -> null
    }

    /** Gradle modules published to Maven. Everything else is never published. */
    val publishedModules: List<String> = listOf(
        ":core:model",
        ":core:protocol",
        ":storage:core",
        ":storage:encryption",
        ":storage:rotation:core",
        ":storage:client:inmemory",
        ":storage:client:sqldelight",
        ":storage:server:inmemory",
        ":storage:server:sqldelight",
        ":storage:keyprovider:android",
        ":storage:keyprovider:apple",
        ":client:core",
        ":client:ktor",
        ":server:core",
        ":server:ktor",
    )

    /** Modules that must never appear in a publication (test fixtures). */
    val neverPublishedModules: List<String> = listOf(":storage:testing")

    /** Modules whose public API may name SQLDelight runtime types (the `open(driver)` boundary). */
    val sqlDelightApiModules: List<String> = listOf(":storage:client:sqldelight", ":storage:server:sqldelight")

    /** Modules whose public API may name Ktor types. */
    val ktorApiModules: List<String> = listOf(":client:ktor", ":server:ktor")

    fun artifactId(path: String): String = ARTIFACT_PREFIX + "-" + path.removePrefix(":").replace(':', '-')

    /** Artifact ID suffixes the Kotlin Multiplatform plugin appends per target. */
    val targetSuffixes: List<String> = listOf(
        "jvm", "android", "js", "wasm-js",
        "iosx64", "iosarm64", "iossimulatorarm64", "macosx64", "macosarm64",
        "linuxx64", "mingwx64",
    )

    enum class Host { ANY, MACOS, LINUX }

    /**
     * A test task that must have run with at least one test after `./gradlew build` on [host].
     * This is the "tests executed" column of docs/supported-platforms.md.
     */
    data class TestExpectation(val module: String, val task: String, val host: Host) {
        fun encode(): String = "$module|$task|$host"
    }

    private val commonTestedKmpModules = listOf(
        ":core:protocol",
        ":client:core",
        ":storage:encryption",
        ":storage:rotation:core",
        ":storage:client:inmemory",
        ":storage:server:inmemory",
    )

    val testExpectations: List<TestExpectation> = buildList {
        (commonTestedKmpModules + ":storage:client:sqldelight").forEach { module ->
            add(TestExpectation(module, "jvmTest", Host.ANY))
            add(TestExpectation(module, "macosArm64Test", Host.MACOS))
            add(TestExpectation(module, "iosSimulatorArm64Test", Host.MACOS))
            add(TestExpectation(module, "linuxX64Test", Host.LINUX))
        }
        commonTestedKmpModules.forEach { module ->
            add(TestExpectation(module, "jsNodeTest", Host.ANY))
        }
        add(TestExpectation(":storage:keyprovider:apple", "macosArm64Test", Host.MACOS))
        add(TestExpectation(":storage:keyprovider:apple", "iosSimulatorArm64Test", Host.MACOS))
        add(TestExpectation(":storage:keyprovider:android", "testAndroidHostTest", Host.ANY))
        listOf(":server:core", ":server:ktor", ":storage:server:sqldelight").forEach { module ->
            add(TestExpectation(module, "test", Host.ANY))
        }
    }
}
