// Signed keychain host tasks (docs/storage-key-providers.md, "Signed keychain host").
// Applied by modules with DataProtection Keychain tests; they set
// extra["keychainHostModes"] (run.sh MODES: tests, relaunch) and, for the
// module holding DataProtectionLeftoverCheck, extra["keychainHostLeftoverCheck"] = true
// before applying this script.
//
// - Plain Apple test tasks exclude *DataProtection*: without entitlements they
//   could only fail or check nothing.
// - <target>KeychainHostTest wraps the target's test.kexe in a signed,
//   entitled .app and runs the DataProtection tests in it. Not part of build/check.
//
// Signing comes from Gradle properties (-P, ~/.gradle/gradle.properties), the
// environment or the git-ignored root local.properties (in that order), never
// from the repository. Two sources with different values for one setting fail
// the task (docs/releasing.md, "Apple signing"):
// ksm.apple.teamId (KSM_APPLE_TEAM_ID), ksm.apple.macosProfile
// (KSM_APPLE_MACOS_PROFILE), optional ksm.apple.signingIdentity,
// ksm.apple.bundleId, ksm.apple.simulator, ksm.apple.keychainHost.required.

val hostScript = rootProject.layout.projectDirectory.file("apple-keychain-host/run.sh").asFile.absolutePath

// providers.gradleProperty does not read local.properties; read it as a
// tracked file so the configuration cache notices changes.
val localProperties: Provider<java.util.Properties> = providers
    .fileContents(rootProject.layout.projectDirectory.file("local.properties")).asText
    .map { text -> java.util.Properties().apply { load(text.reader()) } }
    .orElse(java.util.Properties())

fun setting(property: String, variable: String): Provider<String> =
    providers.gradleProperty(property)
        .orElse(providers.environmentVariable(variable))
        .orElse(localProperties.map { it.getProperty(property) ?: "" })

// A description of every setting that two sources set to different values;
// values are never included in the message.
fun conflict(property: String, variable: String): Provider<List<String>> {
    val gradle = providers.gradleProperty(property).orElse("")
    val environment = providers.environmentVariable(variable).orElse("")
    val local = localProperties.map { it.getProperty(property) ?: "" }
    return gradle.zip(environment) { a, b -> listOf(a, b) }.zip(local) { ab, c -> ab + c }.map { values ->
        val set = listOf("Gradle property $property", "environment variable $variable", "local.properties $property")
            .zip(values.map(String::trim)).filter { it.second.isNotEmpty() }
        if (set.map { it.second }.distinct().size > 1) listOf("$property is set differently in: " + set.joinToString { it.first }) else emptyList()
    }
}

val settingConflicts: Provider<List<String>> = listOf(
    "ksm.apple.teamId" to "KSM_APPLE_TEAM_ID",
    "ksm.apple.macosProfile" to "KSM_APPLE_MACOS_PROFILE",
    "ksm.apple.signingIdentity" to "KSM_APPLE_SIGNING_IDENTITY",
    "ksm.apple.bundleId" to "KSM_APPLE_BUNDLE_ID",
).map { (property, variable) -> conflict(property, variable) }
    .reduce { a, b -> a.zip(b) { x, y -> x + y } }

val teamId = setting("ksm.apple.teamId", "KSM_APPLE_TEAM_ID")
val macosProfile = setting("ksm.apple.macosProfile", "KSM_APPLE_MACOS_PROFILE")
val signingIdentity = setting("ksm.apple.signingIdentity", "KSM_APPLE_SIGNING_IDENTITY")
val bundleId = setting("ksm.apple.bundleId", "KSM_APPLE_BUNDLE_ID")
val simulator = setting("ksm.apple.simulator", "KSM_APPLE_SIMULATOR")
val required = setting("ksm.apple.keychainHost.required", "KSM_APPLE_KEYCHAIN_HOST_REQUIRED")

@Suppress("UNCHECKED_CAST")
val modes = (extra["keychainHostModes"] as List<String>).joinToString(" ")

tasks.withType<AbstractTestTask>().configureEach {
    if (name.startsWith("macos") || name.startsWith("ios")) filter.excludeTestsMatching("*DataProtection*")
}

// One host at a time across modules: the simulator hosts share one bundle
// identifier, and installing one replaces the other.
abstract class KeychainHostLock : BuildService<BuildServiceParameters.None>

val hostLock = gradle.sharedServices.registerIfAbsent("appleKeychainHost", KeychainHostLock::class) { maxParallelUsages.set(1) }

val hostTargets = mapOf("macosArm64" to "macos", "macosX64" to "macos", "iosSimulatorArm64" to "ios-simulator")

hostTargets.forEach { (target, platform) ->
    val capitalized = target.replaceFirstChar(Char::uppercase)
    val kexe = layout.buildDirectory.file("bin/$target/debugTest/test.kexe").map { it.asFile.absolutePath }
    val label = "${project.path} $target"

    fun registerHost(name: String, hostModes: String, description: String) = tasks.register<Exec>(name) {
        group = "verification"
        this.description = description
        dependsOn("linkDebugTest$capitalized")
        usesService(hostLock)
        val onMac = System.getProperty("os.name").lowercase().contains("mac")
        onlyIf { onMac }
        val work = layout.buildDirectory.dir("keychain-host/$target/$name").map { it.asFile.absolutePath }
        // Locals only: the configuration cache cannot store references to this script.
        val script = hostScript
        val teamId = teamId
        val macosProfile = macosProfile
        val signingIdentity = signingIdentity
        val bundleId = bundleId
        val simulator = simulator
        val required = required
        val conflicts = settingConflicts
        doFirst {
            val found = conflicts.get()
            if (found.isNotEmpty()) {
                throw GradleException("KEYCHAIN HOST $label: FAILED — inconsistent signing settings (keep one source, see docs/releasing.md \"Apple signing\"):\n  " + found.joinToString("\n  "))
            }
        }
        executable = "bash"
        argumentProviders.add(CommandLineArgumentProvider {
            listOf(
                script,
                "PLATFORM=$platform",
                "KEXE=${kexe.get()}",
                "WORK=${work.get()}",
                "LABEL=$label",
                "MODES=$hostModes",
                "TEAM_ID=${teamId.get()}",
                "MACOS_PROFILE=${macosProfile.get()}",
                "SIGNING_IDENTITY=${signingIdentity.get()}",
                "BUNDLE_ID=${bundleId.get().ifEmpty { "dev.kreienbuehl.ksecuremessage.keychainhost" }}",
                "SIMULATOR=${simulator.get().ifEmpty { "booted" }}",
                "REQUIRED=${required.get()}",
            )
        })
    }

    registerHost("${target}KeychainHostTest", modes, "Runs the DataProtection Keychain tests of $target in a signed, entitled host.")
    if (extra.has("keychainHostLeftoverCheck")) {
        registerHost("${target}KeychainHostLeftoverCheck", "leftover", "Checks that no test Keychain items remain in the $target host's groups.").configure {
            // After every host run of this target, in any module.
            mustRunAfter(listOf(":storage:keyprovider:apple", ":storage:client:sqldelight").map { "$it:${target}KeychainHostTest" })
        }
        registerHost("${target}KeychainHostPurge", "purge", "Deletes test Keychain items an interrupted $target host run left behind.")
    }
}
