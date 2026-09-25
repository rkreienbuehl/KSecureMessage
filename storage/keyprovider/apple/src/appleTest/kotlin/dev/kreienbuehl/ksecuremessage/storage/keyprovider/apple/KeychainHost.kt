package dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import platform.posix.getenv

/**
 * The entitlements the signed keychain host was built with, passed by
 * apple-keychain-host/run.sh. Missing values fail the test: `DataProtection`
 * tests are never skipped.
 */
@OptIn(ExperimentalForeignApi::class)
object KeychainHost {
    /** First `keychain-access-groups` entry, the default group of new items (application identifier). */
    val defaultGroup: String get() = env("KSM_KEYCHAIN_DEFAULT_GROUP")

    /** Second entitled group, used explicitly. */
    val sharedGroup: String get() = env("KSM_KEYCHAIN_SHARED_GROUP")

    /** A group of the same team the host is not entitled to. */
    val unentitledGroup: String get() = defaultGroup.substringBefore('.') + ".dev.kreienbuehl.ksecuremessage.not-entitled"

    val purgeRequested: Boolean get() = getenv("KSM_KEYCHAIN_PURGE")?.toKString() == "yes"

    private fun env(name: String): String =
        getenv(name)?.toKString()?.takeIf { it.isNotEmpty() } ?: error("$name is not set: run DataProtection tests through appleKeychainHostTest")
}
