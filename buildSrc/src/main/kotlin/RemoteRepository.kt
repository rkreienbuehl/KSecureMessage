import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import org.gradle.api.tasks.UntrackedTask
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Downloads one published version of every KSecureMessage artifact from a
 * remote Maven repository into a local directory with the same layout, so
 * [InspectReleaseArtifacts] can inspect exactly what was uploaded
 * (docs/releasing.md, "Remote publication").
 *
 * - SNAPSHOT: the Central snapshot repository (public reads). The version's
 *   `maven-metadata.xml` names the files of the latest timestamp.
 * - Release version: a validated, unpublished Central Portal deployment via
 *   the Portal's deployment download endpoint, which needs [bearerToken]. The
 *   files are the POM, the Gradle module metadata, the files it lists, and
 *   the sources and documentation jars.
 *
 * For each artifact and each multiplatform target variant that exists
 * remotely it fetches every file with its signature and the checksums of
 * [checksumAlgorithms] (the ones the inspection checks). Missing files are
 * simply not mirrored: the inspection then reports them.
 *
 * A release version is mirrored resumably: the Central Portal deployment
 * endpoint answers each request in seconds, so a full mirror takes hours.
 * Files are written atomically (temporary file, then rename), and a run keeps
 * the files an earlier run mirrored from the same repository URL and version
 * (recorded in a marker file next to the mirror directory, `<mirror>`
 * plus [MARKER_SUFFIX]) and fetches only the missing ones. Anything else
 * (another URL or version, no marker, a SNAPSHOT) starts from an empty
 * directory. After a deployment of the same version was dropped and uploaded
 * again, delete the mirror directory by hand. Files that the remote does not
 * have are requested again by every run.
 */
@UntrackedTask(because = "Reads a remote repository that changes independently of the build")
abstract class MirrorRemoteRepository : DefaultTask() {
    @get:Input abstract val repositoryUrl: Property<String>
    @get:Input abstract val version: Property<String>
    @get:Input abstract val artifacts: ListProperty<String>
    @get:Input abstract val checksumAlgorithms: ListProperty<String>
    @get:OutputDirectory abstract val mirror: DirectoryProperty

    /** Authorization for the Central Portal deployment endpoint (never logged). */
    @get:Internal abstract val bearerToken: Property<String>

    // Created at execution time: the configuration cache cannot store an HttpClient.
    @Transient private var httpClient: HttpClient? = null
    private val client: HttpClient
        get() = httpClient ?: HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build()
            .also { httpClient = it }

    @TaskAction
    fun download() {
        val version = version.get()
        val snapshot = version.endsWith("-SNAPSHOT")
        if (!snapshot && !bearerToken.isPresent) throw GradleException("a release version is read from a Central Portal deployment, which needs credentials")
        val base = repositoryUrl.get().trimEnd('/')
        val root = mirror.get().asFile
        val marker = "repository=$base\nversion=$version\n"
        // Next to the mirror, not in it: every file in the mirror must be a signed artifact file.
        val markerFile = File(root.parentFile, root.name + MARKER_SUFFIX)
        val resume = !snapshot && root.isDirectory && markerFile.let { it.isFile && it.readText() == marker }
        if (!resume) {
            markerFile.delete()
            root.deleteRecursively()
            root.mkdirs()
            markerFile.writeText(marker)
        } else {
            // Leftovers of an interrupted write are never mirrored files.
            root.walkTopDown().filter { it.isFile && it.name.endsWith(".part") }.forEach { it.delete() }
            logger.lifecycle("Resuming the mirror of $version from $base in $root")
        }
        val suffixes = listOf("", ".asc") + checksumAlgorithms.get().map { ".$it" }
        val groupPath = KsmRelease.GROUP.replace('.', '/')
        val candidates = artifacts.get().flatMap { artifact -> listOf(artifact) + KsmRelease.targetSuffixes.map { "$artifact-$it" } }
        // Thousands of small files: fetch them in parallel, one file per request.
        val pool = java.util.concurrent.Executors.newFixedThreadPool(16)
        val fileCount = try {
            val files = candidates.map { artifact ->
                pool.submit<List<Pair<String, String>>> {
                    val versionPath = "$groupPath/$artifact/$version"
                    val names = if (snapshot) {
                        val metadata = get("$base/$versionPath/maven-metadata.xml") ?: return@submit emptyList()
                        root.resolve(versionPath).apply { mkdirs() }.resolve("maven-metadata.xml").writeBytes(metadata)
                        snapshotFiles(artifact, metadata)
                    } else {
                        val module = mirrored(root, versionPath, "$artifact-$version.module") ?: get("$base/$versionPath/$artifact-$version.module")
                        val pom = mirrored(root, versionPath, "$artifact-$version.pom") ?: get("$base/$versionPath/$artifact-$version.pom")
                        if (module == null && pom == null) return@submit emptyList()
                        releaseFiles(artifact, version, module)
                    }
                    names.flatMap { name -> suffixes.map { versionPath to name + it } }
                }
            }.flatMap { it.get() }
            files.map { (versionPath, name) ->
                pool.submit<Int> {
                    if (root.resolve(versionPath).resolve(name).isFile) return@submit 1
                    val bytes = get("$base/$versionPath/$name") ?: return@submit 0
                    write(root.resolve(versionPath).apply { mkdirs() }.resolve(name), bytes)
                    1
                }
            }.sumOf { it.get() }
        } finally {
            pool.shutdownNow()
        }
        if (fileCount == 0) throw GradleException("no KSecureMessage $version artifacts found in $base")
        logger.lifecycle("Mirrored $fileCount files of $version from $base to $root")
    }

    /** The bytes of a file an earlier run of this version mirrored, or null. */
    private fun mirrored(root: File, versionPath: String, name: String): ByteArray? =
        root.resolve(versionPath).resolve(name).takeIf(File::isFile)?.readBytes()

    /** Writes [bytes] to a temporary file and renames it, so an interrupted run never leaves a partial file. */
    private fun write(target: File, bytes: ByteArray) {
        val temporary = File(target.parentFile, ".${target.name}.part")
        temporary.writeBytes(bytes)
        java.nio.file.Files.move(temporary.toPath(), target.toPath(), java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
    }

    /** File names of the latest snapshot in a version-level maven-metadata.xml (signatures and checksums excluded). */
    private fun snapshotFiles(artifact: String, metadata: ByteArray): List<String> {
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(metadata.inputStream())
        val entries = doc.getElementsByTagName("snapshotVersion")
        val files = (0 until entries.length).map { index ->
            val entry = entries.item(index) as org.w3c.dom.Element
            fun child(name: String) = entry.getElementsByTagName(name).item(0)?.textContent?.trim().orEmpty()
            val classifier = child("classifier").let { if (it.isEmpty()) "" else "-$it" }
            "$artifact-${child("value")}$classifier.${child("extension")}"
        }
        return files.filter { name -> listOf(".asc", ".md5", ".sha1", ".sha256", ".sha512").none(name::endsWith) }.distinct()
    }

    /** File names of a release version: POM, module metadata, the files the module lists, sources and documentation jars. */
    private fun releaseFiles(artifact: String, version: String, module: ByteArray?): List<String> {
        // A file's "name" is the project's internal name; "url" is the published file name.
        val listed = module?.let { bytes -> InspectReleaseArtifacts.moduleFileUrls(String(bytes)) }.orEmpty()
        val known = listOf(".pom", ".module", "-sources.jar", "-javadoc.jar", "-kotlin-tooling-metadata.json").map { "$artifact-$version$it" }
        return (known + listed).distinct()
    }

    companion object {
        /** Suffix of the file next to the mirror directory that records the repository URL and version it holds. */
        const val MARKER_SUFFIX: String = ".ksm-mirror"
    }

    private fun get(url: String): ByteArray? {
        val request = HttpRequest.newBuilder(URI(url)).timeout(Duration.ofMinutes(2)).GET()
        if (bearerToken.isPresent) request.header("Authorization", "Bearer ${bearerToken.get()}")
        val response = client.send(request.build(), HttpResponse.BodyHandlers.ofByteArray())
        return when (response.statusCode()) {
            200 -> response.body()
            404 -> null
            else -> throw GradleException("GET $url returned ${response.statusCode()}")
        }
    }
}

/**
 * Checks the assembled documentation site (docs/releasing.md, "Documentation
 * site"): the MkDocs pages and the Dokka API reference are both present, and
 * the API reference covers every published module.
 */
@UntrackedTask(because = "Checks the output of the MkDocs build, which Gradle does not run")
abstract class CheckDocsSite : DefaultTask() {
    @get:InputDirectory abstract val site: DirectoryProperty
    @get:Input abstract val expectedModules: ListProperty<String>
    @get:Internal abstract val sourcePages: ListProperty<String>

    @TaskAction
    fun check() {
        val site = site.get().asFile
        val problems = mutableListOf<String>()
        listOf("index.html", "search/search_index.json", "api/index.html").forEach { path ->
            if (!site.resolve(path).isFile) problems += "site has no $path"
        }
        sourcePages.get().forEach { page ->
            val html = if (page == "index.md") "index.html" else page.removeSuffix(".md") + "/index.html"
            if (!site.resolve(html).isFile) problems += "site has no page for docs/$page ($html)"
        }
        val apiIndex = site.resolve("api/index.html").takeIf(File::isFile)?.readText().orEmpty()
        expectedModules.get().forEach { module ->
            if (!apiIndex.contains(module)) problems += "API reference does not list $module"
        }
        if (problems.isNotEmpty()) throw GradleException("Documentation site check failed:\n" + problems.joinToString("\n") { "  - $it" })
        logger.lifecycle("Documentation site OK: ${sourcePages.get().size} pages, API reference for ${expectedModules.get().size} modules")
    }
}
