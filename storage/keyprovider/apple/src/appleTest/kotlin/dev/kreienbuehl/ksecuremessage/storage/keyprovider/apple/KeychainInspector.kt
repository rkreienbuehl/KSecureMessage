package dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import platform.CoreFoundation.CFDictionaryAddValue
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFRetain
import platform.CoreFoundation.CFTypeRef
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFBooleanFalse
import platform.CoreFoundation.kCFBooleanTrue
import platform.CoreFoundation.kCFTypeDictionaryKeyCallBacks
import platform.CoreFoundation.kCFTypeDictionaryValueCallBacks
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSNumber
import platform.Foundation.NSString
import platform.Foundation.create
import platform.Security.SecItemCopyMatching
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
import platform.Security.kSecAttrAccessGroup
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
import platform.Security.kSecAttrAccount
import platform.Security.kSecAttrService
import platform.Security.kSecAttrSynchronizable
import platform.Security.kSecAttrSynchronizableAny
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitAll
import platform.Security.kSecReturnAttributes
import platform.Security.kSecUseDataProtectionKeychain

/** Attributes of one generic password item, as the Keychain reports them. Never the item data. */
data class KeychainItem(
    val service: String,
    val account: String,
    val accessGroup: String?,
    val accessible: String?,
    val synchronizable: Boolean,
)

/**
 * Reads item attributes independently of the provider's own queries: any
 * access group, and in the data protection keychain synchronizable or not.
 * Tests only.
 */
@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
object KeychainInspector {
    val afterFirstUnlockThisDeviceOnly: String = string(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)

    /**
     * Items of [service] (all services if `null`) in the data protection or
     * only the legacy keychain (`kSecUseDataProtectionKeychain` = false).
     */
    fun items(service: String?, dataProtection: Boolean, accessGroup: String? = null): List<KeychainItem> = memScoped {
        val owned = mutableListOf<CFTypeRef?>()
        val query = CFDictionaryCreateMutable(null, 0, kCFTypeDictionaryKeyCallBacks.ptr, kCFTypeDictionaryValueCallBacks.ptr)
        try {
            CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword)
            // On macOS a synchronizable attribute routes any query to the data
            // protection keychain, so legacy queries must not have one.
            if (dataProtection) CFDictionaryAddValue(query, kSecAttrSynchronizable, kSecAttrSynchronizableAny)
            CFDictionaryAddValue(query, kSecReturnAttributes, kCFBooleanTrue)
            CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitAll)
            if (service != null) CFDictionaryAddValue(query, kSecAttrService, cf(service).also { owned += it })
            if (accessGroup != null) CFDictionaryAddValue(query, kSecAttrAccessGroup, cf(accessGroup).also { owned += it })
            CFDictionaryAddValue(query, kSecUseDataProtectionKeychain, if (dataProtection) kCFBooleanTrue else kCFBooleanFalse)
            val result = alloc<CFTypeRefVar>()
            when (val status = SecItemCopyMatching(query, result.ptr)) {
                errSecItemNotFound -> emptyList()
                errSecSuccess -> (CFBridgingRelease(result.value) as List<*>).map { entry ->
                    val attributes = entry as Map<*, *>
                    KeychainItem(
                        service = attributes[string(kSecAttrService)] as String,
                        account = attributes[string(kSecAttrAccount)] as String,
                        accessGroup = attributes[string(kSecAttrAccessGroup)] as String?,
                        accessible = attributes[string(kSecAttrAccessible)] as String?,
                        synchronizable = (attributes[string(kSecAttrSynchronizable)] as NSNumber?)?.boolValue ?: false,
                    )
                }
                else -> throw KeychainException(status, "inspect")
            }
        } finally {
            CFRelease(query)
            owned.forEach { CFRelease(it) }
        }
    }

    private fun cf(value: String): CFTypeRef? = CFBridgingRetain(NSString.create(string = value))

    // Security constants are CFStrings owned by the framework: retain before bridging.
    private fun string(constant: CFTypeRef?): String = CFBridgingRelease(CFRetain(constant)) as String
}
