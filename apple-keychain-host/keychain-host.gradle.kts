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
// Signing comes from Gradle properties or the environment, never from the
// repository: ksm.apple.teamId (KSM_APPLE_TEAM_ID), ksm.apple.macosProfile
// (KSM_APPLE_MACOS_PROFILE), optional ksm.apple.signingIdentity,
// ksm.apple.bundleId, ksm.apple.simulator, ksm.apple.keychainHost.required.

val hostScript = rootProject.layout.projectDirectory.file("apple-keychain-host/run.sh").asFile.absolutePath

fun setting(property: String, variable: String): Provider<String> =
    providers.gradleProperty(property).orElse(providers.environmentVariable(variable)).orElse("")

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
            mustRunAfter(listOf(":storage:keyprovider:apple", ":storage:sqldelight").map { "$it:${target}KeychainHostTest" })
        }
        registerHost("${target}KeychainHostPurge", "purge", "Deletes test Keychain items an interrupted $target host run left behind.")
    }
}
