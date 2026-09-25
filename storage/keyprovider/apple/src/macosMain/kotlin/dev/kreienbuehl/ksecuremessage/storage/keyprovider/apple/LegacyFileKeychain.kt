package dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple

/**
 * macOS only: an [AppleStorageKeyProvider] on the file-based login keychain,
 * for applications that cannot have the entitlements the data protection
 * keychain requires (application identifier or keychain access group).
 *
 * Weaker than the default: the file-based keychain ignores the "after first
 * unlock, this device only" accessibility class; items are protected by the
 * keychain file and its access control list. Use it deliberately; the
 * default provider never falls back to it on its own.
 */
fun AppleStorageKeyProvider.Companion.legacyFileKeychain(
    namespace: String = AppleStorageKeyProvider.DEFAULT_NAMESPACE,
): AppleStorageKeyProvider = AppleStorageKeyProvider(namespace, accessGroup = null, dataProtection = false)
