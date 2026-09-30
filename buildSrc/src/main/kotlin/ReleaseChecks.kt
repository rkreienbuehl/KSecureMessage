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
 * release checklist, CI and documentation workflows, the vulnerability
 * reporting path, platform claims in the documentation, the public API dumps
 * (dependency leaks) and a secret scan of every file git does not ignore.
 */
@UntrackedTask(because = "Scans the working tree; cheap and must always run")
abstract class CheckReleaseConventions : DefaultTask() {
    @get:Input abstract val projectVersion: Property<String>
    @get:InputFile @get:PathSensitive(PathSensitivity.RELATIVE) abstract val readme: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.RELATIVE) abstract val wrapperProperties: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.RELATIVE) abstract val releasingDoc: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.RELATIVE) abstract val ciWorkflow: RegularFileProperty
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val workflows: ConfigurableFileCollection
    @get:InputFile @get:PathSensitive(PathSensitivity.RELATIVE) abstract val docsWorkflow: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.RELATIVE) abstract val securityPolicy: RegularFileProperty

    /** README and the documentation pages, checked for platform claims. */
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val markdownFiles: ConfigurableFileCollection

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
        checkDocsWorkflow(problems)
        checkSecurityPolicy(problems)
        checkPlatformClaims(problems)
        checkSecurityClaims(problems)
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
            "hosted" to "the hosted CI runs",
            "linuxX64Test" to "the hosted Linux native tests",
            "verifyReleaseSignatures" to "artifact signature verification",
            "publishToMavenCentral" to "the Maven Central upload",
            "inspectRemoteArtifacts" to "remote artifact inspection",
            "remoteConsumerSmokeTest" to "the consumer resolving from the remote repository",
            "mkdocs build --strict" to "the strict documentation build",
            "Pages" to "the documentation deployment",
            "SECURITY.md" to "the vulnerability reporting path",
        )
        required.forEach { (token, what) ->
            if (!text.contains(token)) problems += "docs/releasing.md does not cover $what ($token)"
        }
    }

    private fun checkWorkflows(problems: MutableList<String>) {
        val ci = ciWorkflow.get().asFile.readText()
        if (!Regex("""\./gradlew\s+build(\s|$)""").containsMatchIn(ci)) problems += "ci.yml does not run ./gradlew build"
        if (!ci.contains("verifyPublication")) problems += "ci.yml does not run verifyPublication"
        listOf("-Pksm.testMatrix=non-js", "-Pksm.testMatrix=js").forEach { matrix ->
            if (!Regex("""verifyTestExecution\s+${Regex.escape(matrix)}""").containsMatchIn(ci)) {
                problems += "ci.yml does not run verifyTestExecution $matrix"
            }
        }
        if (!ci.contains("verifyCompileOnlyTargets")) problems += "ci.yml does not run verifyCompileOnlyTargets"
        workflows.files.forEach { file ->
            val text = file.readText()
            listOf("updateKotlinAbi", "updateLegacyAbi", "apiDump").forEach { task ->
                if (text.contains(task)) problems += "${file.name} runs $task; CI must check API dumps, never update them"
            }
            val workflow = WorkflowFile.parse(file) ?: return@forEach run { problems += "${file.name} is not a YAML mapping" }
            if (workflow.permissions("") != mapOf("contents" to "read")) {
                problems += "${file.name}: top-level permissions must be exactly contents: read"
            }
            workflow.jobs.forEach { (job, _) ->
                val permissions = workflow.permissions(job)
                if (permissions == WorkflowFile.WRITE_ALL) problems += "${file.name}: job $job has permissions write-all"
                permissions?.forEach { (scope, level) ->
                    if (level == "write" && !(file.name == "docs.yml" && job == "deploy" && scope in setOf("pages", "id-token"))) {
                        problems += "${file.name}: job $job has $scope: write"
                    }
                }
            }
        }
    }

    private fun checkDocsWorkflow(problems: MutableList<String>) {
        val file = docsWorkflow.get().asFile
        val text = file.readText()
        if (!Regex("""mkdocs\s+build\s+--strict""").containsMatchIn(text)) problems += "docs.yml does not run mkdocs build --strict"
        if (!text.contains("stageApiReference")) problems += "docs.yml does not stage the API reference"
        if (!text.contains("checkDocsSite")) problems += "docs.yml does not run checkDocsSite"
        val workflow = WorkflowFile.parse(file) ?: return
        val deploy = workflow.jobs["deploy"] ?: return run { problems += "docs.yml has no deploy job" }
        val condition = deploy["if"]?.toString().orEmpty()
        if (!(condition.contains("github.event_name == 'push'") && condition.contains("github.ref == 'refs/heads/main'"))) {
            problems += "docs.yml deploy job must run only for a push to main (if: github.event_name == 'push' && github.ref == 'refs/heads/main')"
        }
        if (!deploy.toString().contains("actions/deploy-pages")) problems += "docs.yml deploy job does not use actions/deploy-pages"
        if (workflow.permissions("deploy") != mapOf("pages" to "write", "id-token" to "write")) {
            problems += "docs.yml deploy job permissions must be exactly pages: write, id-token: write"
        }
        workflow.jobs.keys.filter { it != "deploy" }.forEach { job ->
            if (workflow.jobs[job].toString().contains("actions/deploy-pages")) problems += "docs.yml job $job deploys Pages"
        }
    }

    private fun checkSecurityPolicy(problems: MutableList<String>) {
        val text = securityPolicy.get().asFile.readText()
        if (!text.contains(KsmRelease.VULNERABILITY_REPORTING_URL)) {
            problems += "SECURITY.md does not name the private reporting path ${KsmRelease.VULNERABILITY_REPORTING_URL}"
        }
        Regex("""https://github\.com/[^\s)>]*/security/[^\s)>]*""").findAll(text).map { it.value }
            .filter { it != KsmRelease.VULNERABILITY_REPORTING_URL }
            .forEach { problems += "SECURITY.md names an unexpected security URL $it" }
        if (!text.contains("public issue")) problems += "SECURITY.md does not tell reporters to avoid public issues"
    }

    // Security statements that must not silently disappear from the
    // documentation (S1.2): each lives in a marked region
    // `<!-- ksm-security-claim:<id> -->` … `<!-- /ksm-security-claim:<id> -->`
    // of a named page and must keep its required tokens (compared with
    // whitespace normalized, so rewrapping is fine).
    // The operator SQL blocks (`<!-- ksm-sql:<id>:begin -->` … `:end -->`) that
    // PreS1CleanupTest runs verbatim are guarded the same way, so the prose
    // around them cannot stand in for a statement the script lost.
    private class SecurityClaim(
        val file: String,
        val id: String,
        val required: List<String>,
        val forbidden: List<String> = emptyList(),
        val sqlBlock: Boolean = false,
    ) {
        val begin = if (sqlBlock) "<!-- ksm-sql:$id:begin -->" else "<!-- ksm-security-claim:$id -->"
        val end = if (sqlBlock) "<!-- ksm-sql:$id:end -->" else "<!-- /ksm-security-claim:$id -->"
    }

    private val securityClaims = listOf(
        SecurityClaim(
            "security-review-remediation.md", "f7-partial",
            listOf("F7", "PARTIALLY FIXED — RESIDUAL RISK DOCUMENTED"),
            forbidden = listOf("CLOSED"),
        ),
        SecurityClaim(
            "storage-key-providers.md", "android-haskeys",
            listOf("AndroidStorageKeyProvider.hasKeys()", "wrapped key file", "Keystore alias", "F7"),
        ),
        SecurityClaim(
            "operating-the-server.md", "pre-s1-audit",
            listOf(
                "never host-authorized", "audit", "Addresses alone are not enough",
                "auth_public_key", "recovery_id", "rotation_id", "last_device_recovery_id",
                "revocation_id", "reset_completion_id", "expected_public_key", "requested_by_device",
            ),
        ),
        SecurityClaim(
            "operating-the-server.md", "pre-s1-recovery-key-cleanup",
            listOf(
                "Removing only the device registration is insufficient", "compromised", "server stopped",
                "one database transaction", "SET state = 2", "DELETE FROM last_device_recovery_key_reset",
                "DELETE FROM last_device_recovery_challenge", "createLastDeviceRecoveryKey()", "registerLastDeviceRecoveryKey",
            ),
            forbidden = listOf("rotate or re-register", "rotateLastDeviceRecoveryKey"),
        ),
        SecurityClaim(
            "operating-the-server.md", "pre-s1-audit",
            listOf(
                "hex(auth_public_key) AS auth_public_key", "auth_epoch", "auth_key_installed_at", "hex(recovery_id) AS recovery_id",
                "hex(rotation_id) AS rotation_id", "hex(last_device_recovery_id) AS last_device_recovery_id", "FROM device_registration",
                "hex(public_key) AS public_key", "hex(revocation_id) AS revocation_id", "hex(reset_completion_id) AS reset_completion_id",
                "FROM last_device_recovery_key_state", "requested_by_device", "hex(expected_public_key) AS expected_public_key",
                "FROM last_device_recovery_key_reset", "FROM last_device_recovery_challenge",
            ),
            sqlBlock = true,
        ),
        SecurityClaim(
            "operating-the-server.md", "pre-s1-cleanup",
            listOf(
                "BEGIN IMMEDIATE;", "DELETE FROM device_registration", "DELETE FROM authentication_nonce", "DELETE FROM device_prekey_state",
                "DELETE FROM available_one_time_prekey", "DELETE FROM consumed_one_time_prekey", "DELETE FROM mailbox_message",
                "UPDATE last_device_recovery_key_state SET state = 2",
                "epoch = CASE WHEN epoch < 9223372036854775807 THEN epoch + 1 ELSE NULL END", "public_key = NULL", "installed_at = NULL",
                "rotation_id = NULL", "revocation_id = NULL", "reset_completion_id = NULL",
                "DELETE FROM last_device_recovery_key_reset", "DELETE FROM last_device_recovery_challenge", "COMMIT;",
            ),
            sqlBlock = true,
        ),
    )

    private fun checkSecurityClaims(problems: MutableList<String>) {
        val pages = markdownFiles.files.associateBy { it.name }
        securityClaims.forEach { claim ->
            val page = pages[claim.file] ?: return@forEach run { problems += "${claim.file} is missing (security claim ${claim.id})" }
            val text = page.readText()
            val begin = claim.begin
            val end = claim.end
            if (text.split(begin).size != 2 || text.split(end).size != 2 || text.indexOf(begin) > text.indexOf(end)) {
                return@forEach run { problems += "${claim.file} must contain the security claim region ${claim.id} exactly once" }
            }
            val region = text.substringAfter(begin).substringBefore(end).replace(Regex("""\s+"""), " ")
            claim.required.filterNot(region::contains).forEach {
                problems += "${claim.file}: security claim ${claim.id} no longer states '$it'"
            }
            claim.forbidden.filter(region::contains).forEach {
                problems += "${claim.file}: security claim ${claim.id} must not say '$it'"
            }
        }
        // F7 stays partial in the remediation summary table until a reviewer closes it.
        pages["security-review-remediation.md"]?.readLines()?.filter { it.startsWith("| F7 |") }?.let { rows ->
            if (rows.size != 1 || !rows.single().contains("PARTIALLY FIXED — RESIDUAL RISK DOCUMENTED")) {
                problems += "security-review-remediation.md: the F7 summary row must say PARTIALLY FIXED — RESIDUAL RISK DOCUMENTED"
            }
        }
        // The old guidance kept a suspect recovery key authoritative (N5).
        pages["operating-the-server.md"]?.readText()?.replace(Regex("""\s+"""), " ")?.let { text ->
            if (text.contains("rotate or re-register")) problems += "operating-the-server.md tells operators to rotate a suspect recovery key (S1.2, N5)"
        }
    }

    // Wasm runtimes are blocked upstream (docs/supported-platforms.md): no
    // row of a platform status table (a table with a "Status" column) may
    // claim more than compile-only for Wasm.
    private fun checkPlatformClaims(problems: MutableList<String>) {
        markdownFiles.files.forEach { file ->
            var header: String? = null
            file.readLines().forEachIndexed { index, raw ->
                val line = raw.trim()
                if (!line.startsWith("|")) return@forEachIndexed run { header = null }
                if (header == null) return@forEachIndexed run { header = line }
                val firstCell = line.removePrefix("|").substringBefore('|').trim()
                val statusTable = header.contains("Status")
                if (statusTable && firstCell.contains("Wasm", ignoreCase = true) &&
                    (!line.contains("compile-only") || Regex("""(?<!un)tested|tests executed""").containsMatchIn(line))
                ) {
                    problems += "${file.name}:${index + 1} claims more than compile-only for Wasm"
                }
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

    /**
     * Which part of the matrix to check: `all`, `js` (the jsNodeTest tasks) or
     * `non-js` (everything else). CI runs the JS tests in their own job and
     * checks both parts; together they are the whole matrix.
     */
    @get:Input abstract val matrix: Property<String>
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
        val selected: (String) -> Boolean = when (val part = matrix.get()) {
            "all" -> { _ -> true }
            "js" -> { task -> task == "jsNodeTest" }
            "non-js" -> { task -> task != "jsNodeTest" }
            else -> throw GradleException("unknown test matrix '$part' (all, js, non-js)")
        }
        expectations.get().forEach { encoded ->
            val (module, task, required) = encoded.split('|')
            if (required != "ANY" && required != host?.name) return@forEach
            if (!selected(task)) return@forEach
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

    /** Every artifact file needs a `.asc` signature (signing configured, or a remote repository). */
    @get:Input abstract val requireSignatures: Property<Boolean>

    /** Checksum files every artifact file needs, each matching its content (`md5`, `sha1`, `sha256`, `sha512`). */
    @get:Input abstract val checksumAlgorithms: ListProperty<String>

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
            files.filter { isArtifactFile(it.name) }.forEach { file ->
                if (requireSignatures.get() && files.none { it.name == file.name + ".asc" }) problems += "$artifact: ${file.name} has no signature (.asc)"
                checksumAlgorithms.get().forEach { algorithm ->
                    val checksum = files.firstOrNull { it.name == "${file.name}.$algorithm" }
                    when {
                        checksum == null -> problems += "$artifact: ${file.name} has no .$algorithm checksum"
                        checksum.readText().trim().substringBefore(' ').lowercase() != digest(file, algorithm) ->
                            problems += "$artifact: ${file.name}.$algorithm does not match"
                    }
                }
            }
            snapshotAware(".module").forEach { module ->
                // Variants of a multiplatform root point to their target artifacts.
                Regex(""""available-at"\s*:\s*\{[^}]*"module"\s*:\s*"([^"]+)"""").findAll(module.readText())
                    .map { it.groupValues[1] }.distinct()
                    .filter { it !in present }
                    .forEach { problems += "$artifact: Gradle module metadata points to $it, which is missing" }
                // Every file a variant lists must be published next to it (a
                // SNAPSHOT is stored under its timestamped name).
                val published = version.get()
                val versionPattern = if (published.endsWith("-SNAPSHOT")) {
                    Regex.escape(published.removeSuffix("-SNAPSHOT")) + """-(SNAPSHOT|\d{8}\.\d{6}-\d+)"""
                } else {
                    Regex.escape(published)
                }
                // Consumers store the JVM runtime jar under its "name" and JVM
                // distributions copy runtime jars side by side: it must be the
                // published, unique file name, never the internal project name.
                val jvmArtifact = artifact.endsWith("-jvm") ||
                    (KsmRelease.targetSuffixes.none { artifact.endsWith("-$it") } && !isMultiplatformRoot(artifact, present))
                val runtimeJar = Regex(Regex.escape(artifact) + "-" + Regex.escape(version.get()) + "\\.jar")
                Regex(""""name"\s*:\s*"([^"]+)"\s*,\s*"url"\s*:\s*"([^"/]+)"""").findAll(module.readText())
                    .filter { jvmArtifact && runtimeJar.matches(it.groupValues[2]) && it.groupValues[1] != it.groupValues[2] }
                    .forEach { problems += "$artifact: Gradle module metadata file name ${it.groupValues[1]} differs from its published name ${it.groupValues[2]}" }
                moduleFileUrls(module.readText()).forEach { url ->
                    val pattern = Regex(url.split(published).joinToString(versionPattern) { Regex.escape(it) })
                    if (files.none { pattern.matches(it.name) }) problems += "$artifact: Gradle module metadata lists $url, which is missing"
                }
            }
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

    companion object {
        /** Published file names a Gradle module metadata file lists (`url`s in the same directory). */
        fun moduleFileUrls(module: String): List<String> =
            Regex(""""url"\s*:\s*"([^"/]+)"""").findAll(module).map { it.groupValues[1] }.distinct().toList()
    }

    private fun isArtifactFile(name: String): Boolean =
        !name.startsWith("maven-metadata") && listOf(".asc", ".md5", ".sha1", ".sha256", ".sha512").none(name::endsWith)

    private fun digest(file: File, algorithm: String): String {
        val name = mapOf("md5" to "MD5", "sha1" to "SHA-1", "sha256" to "SHA-256", "sha512" to "SHA-512").getValue(algorithm)
        return java.security.MessageDigest.getInstance(name).digest(file.readBytes()).joinToString("") { "%02x".format(it) }
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
            listOf("project(\":", "includeBuild", "dependencySubstitution", "substitute(", "mavenLocal").forEach { token ->
                if (text.contains(token)) problems += "${file.path} uses $token; the consumer must use published artifacts only"
            }
        }
        if (buildFiles.files.none { it.name == "settings.gradle.kts" && it.readText().contains("exclusiveContent") }) {
            problems += "the consumer settings do not restrict KSecureMessage to the release repository (exclusiveContent)"
        }
        failIfAny(problems, "Consumer fixture is not isolated")
    }
}
