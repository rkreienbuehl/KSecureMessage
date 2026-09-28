import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor
import java.io.File

/** A parsed GitHub Actions workflow, for the permission and deployment checks of [CheckReleaseConventions]. */
internal class WorkflowFile private constructor(private val root: Map<*, *>) {
    val jobs: Map<String, Map<*, *>> =
        (root["jobs"] as? Map<*, *>).orEmpty().entries.associate { (name, job) -> name.toString() to (job as? Map<*, *>).orEmpty() }

    /**
     * The permissions of [job] (`""`: the workflow's top level) as scope → level,
     * [WRITE_ALL] / [READ_ALL] for the shorthands, `null` when not declared.
     */
    fun permissions(job: String): Map<String, String>? {
        val declared = if (job.isEmpty()) root["permissions"] else jobs[job]?.get("permissions")
        return when (declared) {
            null -> null
            "write-all" -> WRITE_ALL
            "read-all" -> READ_ALL
            is Map<*, *> -> declared.entries.associate { (scope, level) -> scope.toString() to level.toString() }
            else -> mapOf("?" to declared.toString())
        }
    }

    companion object {
        val WRITE_ALL: Map<String, String> = mapOf("*" to "write")
        val READ_ALL: Map<String, String> = mapOf("*" to "read")

        fun parse(file: File): WorkflowFile? =
            (Yaml(SafeConstructor(LoaderOptions())).load<Any?>(file.readText()) as? Map<*, *>)?.let(::WorkflowFile)
    }
}
