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
