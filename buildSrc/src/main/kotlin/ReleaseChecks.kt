import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.api.tasks.UntrackedTask
import java.io.ByteArrayInputStream
import java.io.File
import java.util.zip.ZipInputStream
import javax.xml.parsers.DocumentBuilderFactory

// Release engineering checks (docs/releasing.md). Each failure names the rule
// it broke; nothing here fixes or regenerates anything.

private fun failIfAny(problems: List<String>, title: String) {
    if (problems.isNotEmpty()) {
        throw GradleException("$title:\n" + problems.joinToString("\n") { "  - $it" })
    }
}

/** Secret material that must never be committed or packaged. */
internal object SecretPatterns {
    // Built from parts so this file does not match itself.
    private const val DASHES = "-----"
    val privateKeyBlock = Regex(DASHES + "BEGIN ((RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY( BLOCK)?" + DASHES)
    val appleTeamIdValue = Regex("ksm\\.apple\\.teamId\\s*=\\s*[A-Z0-9]{10}\\b")
    val signingKeyValue = Regex("signingInMemoryKey\\s*=\\s*\\S{20,}")

    val forbiddenExtensions = setOf(
        "p12", "pfx", "jks", "keystore", "mobileprovision", "provisionprofile",
        "cer", "der", "pem", "key", "gpg", "db", "sqlite", "sqlite3", "kexe",
    )

    fun extension(name: String): String = name.substringAfterLast('/').substringAfterLast('.', "").lowercase()

    fun scanText(label: String, text: String): List<String> = buildList {
        if (privateKeyBlock.containsMatchIn(text)) add("$label contains a private key block")
        if (appleTeamIdValue.containsMatchIn(text)) add("$label contains a ksm.apple.teamId value")
        if (signingKeyValue.containsMatchIn(text)) add("$label contains a signingInMemoryKey value")
    }
}

/**
 * Static release conventions: project version, README wrapper version, the
 * release checklist, CI workflows, the public API dumps (dependency leaks) and
 * a secret scan of every file git does not ignore.
 */
@UntrackedTask(because = "Scans the working tree; cheap and must always run")
abstract class CheckReleaseConventions : DefaultTask() {
    @get:Input abstract val projectVersion: Property<String>
    @get:InputFile @get:PathSensitive(PathSensitivity.RELATIVE) abstract val readme: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.RELATIVE) abstract val wrapperProperties: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.RELATIVE) abstract val releasingDoc: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.RELATIVE) abstract val ciWorkflow: RegularFileProperty
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val workflows: ConfigurableFileCollection

    /** The API dumps of the published modules (the .api files in each module's api directory). */
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val apiDumps: ConfigurableFileCollection

    /** Files git does not ignore (tracked and untracked), relative to [rootDirectory]. */
    @get:Input abstract val candidateFiles: ListProperty<String>
    @get:Internal abstract val rootDirectory: DirectoryProperty

    @TaskAction
    fun check() {
        val problems = mutableListOf<String>()
        checkVersion(problems)
        checkReadme(problems)
        checkReleasingDoc(problems)
        checkWorkflows(problems)
        checkApiDumps(problems)
        checkSecrets(problems)
        failIfAny(problems, "Release convention check failed")
    }

    private fun checkVersion(problems: MutableList<String>) {
        val version = projectVersion.get()
        if (version == "unspecified" || !Regex("""\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?""").matches(version)) {
            problems += "project version '$version' is not a SemVer version (set it once in the root build.gradle.kts)"
        }
    }

    private fun checkReadme(problems: MutableList<String>) {
        val wrapper = Regex("""gradle-([0-9][^-]*)-(bin|all)\.zip""")
            .find(wrapperProperties.get().asFile.readText())?.groupValues?.get(1)
            ?: return run { problems += "cannot read the Gradle version from gradle-wrapper.properties" }
        val readme = readme.get().asFile.readText()
        val mentioned = Regex("""(?i)gradle(?: wrapper)?(?: version)?[ :]+v?(\d+\.\d+(?:\.\d+)?)""")
            .findAll(readme).map { it.groupValues[1] }.toList() +
            Regex("""--gradle-version\s+(\S+)""").findAll(readme).map { it.groupValues[1] }.toList()
        if (wrapper !in mentioned) problems += "README.md does not name the Gradle wrapper version $wrapper"
        mentioned.filter { it != wrapper }.distinct().forEach {
            problems += "README.md names Gradle $it, but the wrapper is $wrapper"
        }
        if (readme.contains("does not bundle the Gradle wrapper")) problems += "README.md claims the wrapper is not bundled"
    }

    private fun checkReleasingDoc(problems: MutableList<String>) {
        val text = releasingDoc.get().asFile.readText()
        val required = mapOf(
            "./gradlew build" to "the default build",
            "checkKotlinAbi" to "the API compatibility check",
            "verifyPublication" to "publication and consumer verification",
            "connectedAndroidDeviceTest" to "Android instrumentation",
            "KeychainHostTest" to "the Apple keychain host",
            "StorageKeyProviderContractTest" to "platform key provider verification",
            "docs/security-review.md" to "the security checklist",
        )
        required.forEach { (token, what) ->
            if (!text.contains(token)) problems += "docs/releasing.md does not cover $what ($token)"
        }
    }

    private fun checkWorkflows(problems: MutableList<String>) {
        val ci = ciWorkflow.get().asFile.readText()
        if (!Regex("""\./gradlew\s+build(\s|$)""").containsMatchIn(ci)) problems += "ci.yml does not run ./gradlew build"
        if (!ci.contains("verifyPublication")) problems += "ci.yml does not run verifyPublication"
        workflows.files.forEach { file ->
            val text = file.readText()
            listOf("updateKotlinAbi", "updateLegacyAbi", "apiDump").forEach { task ->
                if (text.contains(task)) problems += "${file.name} runs $task; CI must check API dumps, never update them"
            }
        }
    }

    private fun checkApiDumps(problems: MutableList<String>) {
        val forbidden = mapOf(
            "Kodium" to listOf("io.kodium", "io/kodium"),
            "cryptography-kotlin" to listOf("dev.whyoleg", "dev/whyoleg"),
            "KotlinCrypto" to listOf("org.kotlincrypto", "org/kotlincrypto"),
        )
        val root = rootDirectory.get().asFile
        if (apiDumps.isEmpty) problems += "no API dumps found (run ./gradlew updateKotlinAbi once and review)"
        apiDumps.files.forEach { file ->
            val module = ":" + file.relativeTo(root).invariantSeparatorsPath.substringBefore("/api/").replace('/', ':')
            val text = file.readText()
            forbidden.forEach { (library, tokens) ->
                if (tokens.any(text::contains)) problems += "$library type in the public API of $module (${file.name})"
            }
            if (module !in KsmRelease.sqlDelightApiModules && ("app.cash.sqldelight" in text || "app/cash/sqldelight" in text)) {
                problems += "SQLDelight type in the public API of $module (${file.name})"
            }
            if (module !in KsmRelease.ktorApiModules && ("io.ktor" in text || "io/ktor" in text)) {
                problems += "Ktor type in the public API of $module (${file.name})"
            }
        }
    }

    private fun checkSecrets(problems: MutableList<String>) {
        val root = rootDirectory.get().asFile
        candidateFiles.get().forEach { path ->
            val file = root.resolve(path)
            if (!file.isFile) return@forEach
            if (SecretPatterns.extension(path) in SecretPatterns.forbiddenExtensions) {
                problems += "$path: key, certificate, profile, database or test binary file in the repository"
            }
            if (file.length() > 2_000_000 || SecretPatterns.extension(path) in setOf("jar", "png", "jpg", "zip")) return@forEach
            problems += SecretPatterns.scanText(path, file.readText(Charsets.ISO_8859_1))
        }
    }
}

/**
 * Checks that every test task of the supported test matrix ([KsmRelease.testExpectations])
 * for the current host produced JUnit results with at least one test and no
 * failure. Run after `./gradlew build`: a disabled or skipped test task fails here.
 */
@UntrackedTask(because = "Reads the results of other tasks")
abstract class VerifyTestExecution : DefaultTask() {
    @get:Input abstract val expectations: ListProperty<String>
    @get:Internal abstract val rootDirectory: DirectoryProperty

    @TaskAction
    fun verify() {
        val os = System.getProperty("os.name").lowercase()
        val host = when {
            os.contains("mac") -> KsmRelease.Host.MACOS
            os.contains("linux") -> KsmRelease.Host.LINUX
            else -> null
        }
        val problems = mutableListOf<String>()
        val summary = mutableListOf<String>()
        expectations.get().forEach { encoded ->
            val (module, task, required) = encoded.split('|')
            if (required != "ANY" && required != host?.name) return@forEach
            val dir = rootDirectory.get().asFile.resolve(module.removePrefix(":").replace(':', '/') + "/build/test-results/$task")
            val results = dir.listFiles { f -> f.name.endsWith(".xml") }.orEmpty()
            var tests = 0
            var failed = 0
            results.forEach { xml ->
                val suite = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xml).documentElement
                tests += suite.getAttribute("tests").toIntOrNull() ?: 0
                failed += (suite.getAttribute("failures").toIntOrNull() ?: 0) + (suite.getAttribute("errors").toIntOrNull() ?: 0)
            }
            summary += "$module:$task tests=$tests failed=$failed"
            when {
                tests == 0 -> problems += "$module:$task produced no test results (disabled, skipped or not run)"
                failed > 0 -> problems += "$module:$task has $failed failed tests"
            }
        }
        logger.lifecycle(summary.joinToString("\n"))
        failIfAny(problems, "Supported test matrix not executed")
    }
}

/**
 * Inspects the local release repository after publication: exactly the
 * expected artifacts, complete POMs, Gradle module metadata, sources and
 * documentation jars, no test classes, no secret or database files, sane sizes.
 */
@UntrackedTask(because = "Inspects a repository another task rewrites")
abstract class InspectReleaseArtifacts : DefaultTask() {
    @get:InputDirectory abstract val repository: DirectoryProperty
    @get:Input abstract val version: Property<String>
    @get:Input abstract val expectedArtifacts: ListProperty<String>
    @get:Input abstract val forbiddenArtifacts: ListProperty<String>

    @get:OutputFile abstract val report: RegularFileProperty

    @TaskAction
    fun inspect() {
        val problems = mutableListOf<String>()
        val lines = mutableListOf<String>()
        val groupDir = repository.get().asFile.resolve(KsmRelease.GROUP.replace('.', '/'))
        val present = groupDir.listFiles { f -> f.isDirectory }.orEmpty().map { it.name }.toSet()
        val expected = expectedArtifacts.get().toSet()

        expected.filter { it !in present }.forEach { problems += "missing artifact $it" }
        forbiddenArtifacts.get().filter { base -> present.any { it == base || it.startsWith("$base-") } }
            .forEach { problems += "forbidden artifact $it was published" }
        present.filter { name -> expected.none { base -> name == base || KsmRelease.targetSuffixes.any { name == "$base-$it" } } }
            .forEach { problems += "unexpected artifact $it" }

        val fileNames = mutableMapOf<String, String>()
        present.sorted().forEach { artifact ->
            val dir = groupDir.resolve("$artifact/${version.get()}")
            val files = dir.listFiles().orEmpty().filter { it.isFile }
            val snapshotAware = { suffix: String -> files.filter { it.name.endsWith(suffix) } }
            val pom = snapshotAware(".pom").singleOrNull()
            if (pom == null) {
                problems += "$artifact: no POM"
            } else {
                checkPom(artifact, pom, problems)
            }
            if (snapshotAware(".module").isEmpty()) problems += "$artifact: no Gradle module metadata"
            val binaries = files.filter { f -> listOf(".jar", ".aar", ".klib").any(f.name::endsWith) && !f.name.endsWith("-sources.jar") && !f.name.endsWith("-javadoc.jar") }
            if (binaries.isNotEmpty() || artifact in expected) {
                val sources = snapshotAware("-sources.jar")
                if (sources.isEmpty()) {
                    problems += "$artifact: no sources jar"
                } else if (!isMultiplatformRoot(artifact, present) && sources.none { jar -> kotlinSourceCount(jar) > 0 }) {
                    // A multiplatform root artifact carries only common sources, which
                    // a single-target module (keyprovider:android) does not have.
                    problems += "$artifact: sources jar contains no Kotlin sources"
                }
            }
            if (snapshotAware("-javadoc.jar").isEmpty()) problems += "$artifact: no documentation (javadoc) jar"
            files.forEach { file ->
                if (listOf(".jar", ".aar", ".klib").any(file.name::endsWith)) {
                    fileNames.put(file.name, artifact)?.let { other -> problems += "file name ${file.name} in both $other and $artifact" }
                }
                if (file.length() > 25_000_000) problems += "$artifact: ${file.name} is ${file.length()} bytes"
                if (listOf(".jar", ".aar", ".klib").any(file.name::endsWith)) inspectArchive("$artifact/${file.name}", file.readBytes(), problems)
                lines += "${file.length().toString().padStart(10)}  $artifact/${file.name}"
            }
        }
        report.get().asFile.writeText(lines.joinToString("\n", postfix = "\n"))
        logger.lifecycle("Inspected ${present.size} artifacts (${lines.size} files), report: ${report.get().asFile}")
        failIfAny(problems, "Release artifact inspection failed")
    }

    private fun isMultiplatformRoot(artifact: String, present: Set<String>): Boolean =
        KsmRelease.targetSuffixes.any { "$artifact-$it" in present }

    private fun kotlinSourceCount(jar: File): Int = ZipInputStream(jar.inputStream()).use { zip ->
        generateSequence { zip.nextEntry }.count { it.name.endsWith(".kt") }
    }

    private fun checkPom(artifact: String, pom: File, problems: MutableList<String>) {
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(pom)
        fun text(path: String): String? {
            var nodes = listOf(doc.documentElement as org.w3c.dom.Node)
            path.split('/').forEach { name ->
                nodes = nodes.flatMap { node ->
                    (0 until node.childNodes.length).map(node.childNodes::item).filter { it.nodeName == name }
                }
            }
            return nodes.firstOrNull()?.textContent?.trim()?.takeIf { it.isNotEmpty() }
        }
        mapOf(
            "groupId" to KsmRelease.GROUP,
            "artifactId" to artifact,
            "version" to version.get(),
        ).forEach { (path, value) -> if (text(path) != value) problems += "$artifact: POM $path is ${text(path)}, expected $value" }
        listOf(
            "name", "description", "url", "licenses/license/name", "licenses/license/url",
            "developers/developer/id", "developers/developer/name", "scm/url", "scm/connection",
        ).forEach { path -> if (text(path) == null) problems += "$artifact: POM has no $path" }
    }

    private fun inspectArchive(label: String, bytes: ByteArray, problems: MutableList<String>) {
        ZipInputStream(ByteArrayInputStream(bytes)).use { zip ->
            generateSequence { zip.nextEntry }.forEach { entry ->
                val name = entry.name
                val base = name.substringAfterLast('/')
                if (Regex("""(^|/)(test|commonTest|jvmTest|sqliteTest|appleTest|macosTest|androidDeviceTest|androidHostTest)/""").containsMatchIn(name) ||
                    Regex("""Test(\$.*)?\.class$|Test\.kt$""").containsMatchIn(base)
                ) {
                    problems += "$label contains test code: $name"
                }
                if (SecretPatterns.extension(name) in SecretPatterns.forbiddenExtensions || base == "local.properties") {
                    problems += "$label contains a key, certificate, database or binary file: $name"
                }
                if (!entry.isDirectory) {
                    val content = zip.readBytes()
                    if (base.endsWith(".jar")) {
                        inspectArchive("$label!$name", content, problems)
                    } else if (content.size < 1_000_000) {
                        problems += SecretPatterns.scanText("$label!$name", String(content, Charsets.ISO_8859_1))
                    }
                }
            }
        }
    }
}

/**
 * The consumer fixture must resolve KSecureMessage only as published
 * artifacts: no project dependencies, no included builds, no substitution.
 */
@UntrackedTask(because = "Scans the fixture sources")
abstract class CheckConsumerIsolation : DefaultTask() {
    @get:InputFiles abstract val buildFiles: ConfigurableFileCollection

    @TaskAction
    fun check() {
        val problems = mutableListOf<String>()
        buildFiles.files.forEach { file ->
            val text = file.readText()
            listOf("project(\":", "includeBuild", "dependencySubstitution", "substitute(").forEach { token ->
                if (text.contains(token)) problems += "${file.path} uses $token; the consumer must use published artifacts only"
            }
        }
        if (buildFiles.files.none { it.name == "settings.gradle.kts" && it.readText().contains("exclusiveContent") }) {
            problems += "the consumer settings do not restrict KSecureMessage to the release repository (exclusiveContent)"
        }
        failIfAny(problems, "Consumer fixture is not isolated")
    }
}
