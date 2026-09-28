// Consumer fixture and end-to-end example (docs/releasing.md, docs/application-lifecycle.md).
// A standalone build: it uses KSecureMessage only as published artifacts from
// the repository given by -PksmRepo (the root task verifyPublication passes
// build/release-repo), never as project dependencies.

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

val ksmRepo: String = providers.gradleProperty("ksmRepo").orNull
    ?: error("Pass the KSecureMessage release repository: -PksmRepo=<path>, e.g. ../../build/release-repo")

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        exclusiveContent {
            forRepository { maven { name = "ksmRelease"; url = uri(file(ksmRepo)) } }
            filter { includeGroup("dev.kreienbuehl.ksecuremessage") }
        }
        google()
        mavenCentral()
    }
    versionCatalogs {
        create("libs") { from(files("../../gradle/libs.versions.toml")) }
    }
}

rootProject.name = "ksecuremessage-jvm-e2e"

include(":app", ":kmp-smoke")
