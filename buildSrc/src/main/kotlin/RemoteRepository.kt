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
 * Downloads one published snapshot of every KSecureMessage artifact from a
 * remote Maven repository (the Central snapshot repository) into a local
 * directory with the same layout, so [InspectReleaseArtifacts] can inspect
 * exactly what was uploaded (docs/releasing.md, "Remote publication").
 *
 * Only public, unauthenticated reads. For each artifact (and each
 * multiplatform target variant that exists remotely) it reads the version's
 * `maven-metadata.xml`, takes the latest timestamp and fetches every file of
 * it with its signature and checksums. Missing optional files are simply not
 * mirrored: the inspection then reports them.
 */
@UntrackedTask(because = "Reads a remote repository that changes independently of the build")
abstract class MirrorRemoteRepository : DefaultTask() {
    @get:Input abstract val repositoryUrl: Property<String>
    @get:Input abstract val version: Property<String>
    @get:Input abstract val artifacts: ListProperty<String>
    @get:OutputDirectory abstract val mirror: DirectoryProperty

    private val client: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(30))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build()

    @TaskAction
    fun download() {
        val version = version.get()
        if (!version.endsWith("-SNAPSHOT")) throw GradleException("mirrorRemoteRepository reads snapshots only; $version is not a SNAPSHOT")
        val base = repositoryUrl.get().trimEnd('/')
        val root = mirror.get().asFile.apply { deleteRecursively(); mkdirs() }
        val groupPath = KsmRelease.GROUP.replace('.', '/')
        var fileCount = 0
        val candidates = artifacts.get().flatMap { artifact -> listOf(artifact) + KsmRelease.targetSuffixes.map { "$artifact-$it" } }
        candidates.forEach { artifact ->
            val versionPath = "$groupPath/$artifact/$version"
            val metadata = get("$base/$versionPath/maven-metadata.xml") ?: return@forEach
            val dir = root.resolve(versionPath).apply { mkdirs() }
            dir.resolve("maven-metadata.xml").writeBytes(metadata)
            snapshotFiles(artifact, metadata).forEach { name ->
                listOf("", ".asc", ".md5", ".sha1", ".sha256", ".sha512").forEach { suffix ->
                    get("$base/$versionPath/$name$suffix")?.let { bytes ->
                        dir.resolve(name + suffix).writeBytes(bytes)
                        fileCount++
                    }
                }
            }
        }
        if (fileCount == 0) throw GradleException("no KSecureMessage $version artifacts found in $base")
        logger.lifecycle("Mirrored $fileCount files of $version from $base to $root")
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

    private fun get(url: String): ByteArray? {
        val response = client.send(HttpRequest.newBuilder(URI(url)).timeout(Duration.ofMinutes(2)).GET().build(), HttpResponse.BodyHandlers.ofByteArray())
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
