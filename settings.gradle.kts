pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Node.js distribution for the JS/Wasm Node test runtime. The Kotlin
        // Gradle plugin would otherwise add this repository to the project at
        // execution time, which FAIL_ON_PROJECT_REPOS rejects; the root build
        // script turns that off (downloadBaseUrl = null). docs/supported-platforms.md
        ivy("https://nodejs.org/dist") {
            name = "Node.js distributions"
            patternLayout { artifact("v[revision]/[artifact](-v[revision]-[classifier]).[ext]") }
            metadataSources { artifact() }
            content { includeModule("org.nodejs", "node") }
        }
    }
}

rootProject.name = "KSecureMessage"

include(
    ":core:model",
    ":core:protocol",
    ":client:core",
    ":client:ktor",
    ":server:core",
    ":server:ktor",
    ":storage:client:inmemory",
    ":storage:client:sqldelight",
    ":storage:core",
    ":storage:encryption",
    ":storage:keyprovider:android",
    ":storage:keyprovider:apple",
    ":storage:rotation:core",
    ":storage:server:inmemory",
    ":storage:server:sqldelight",
    ":storage:testing",
)
