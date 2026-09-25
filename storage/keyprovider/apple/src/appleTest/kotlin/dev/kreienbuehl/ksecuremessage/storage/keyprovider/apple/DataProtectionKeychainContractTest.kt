package dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple

/**
 * The contract on the data protection keychain with the application's
 * default access group, as applications use it. `DataProtection` tests need
 * keychain entitlements: they run only in the signed host
 * (`appleKeychainHostTest`, docs/storage-key-providers.md); the plain test
 * tasks exclude them.
 */
class DataProtectionKeychainContractTest : AppleContractBase(dataProtection = true)

/** The contract on the data protection keychain with an explicit, entitled access group. */
class DataProtectionAccessGroupContractTest : AppleContractBase(dataProtection = true, accessGroup = { KeychainHost.sharedGroup })
