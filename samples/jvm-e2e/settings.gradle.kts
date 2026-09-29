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
    ?: error("Pass the KSecureMessage release repository: -PksmRepo=<path>, e.g. ../../build/release-repo, or an https URL")
// A local directory (verifyPublication) or a remote https repository
// (remoteConsumerSmokeTest: the Central snapshot repository, or a Central
// Portal deployment, which needs the bearer token in ksmRepoBearer). Never
// Maven Local.
val ksmRepoUri: java.net.URI = if (ksmRepo.startsWith("https://")) uri(ksmRepo) else file(ksmRepo).toURI()
val ksmRepoBearer: String? = providers.gradleProperty("ksmRepoBearer").orNull

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        exclusiveContent {
            forRepository {
                maven {
                    name = "ksmRelease"
                    url = ksmRepoUri
                    if (ksmRepoBearer != null) {
                        credentials(HttpHeaderCredentials::class) {
                            name = "Authorization"
                            value = "Bearer $ksmRepoBearer"
                        }
                        authentication { create<HttpHeaderAuthentication>("header") }
                    }
                }
            }
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
