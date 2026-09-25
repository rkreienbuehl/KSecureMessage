package dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple

import kotlin.test.Test
import kotlin.test.assertFailsWith

class AppleStorageKeyProviderTest {
    @Test
    fun namespaceIsValidated() {
        for (invalid in listOf("", "a/b", "a b", "ä", "x".repeat(65))) {
            assertFailsWith<IllegalArgumentException> { AppleStorageKeyProvider(invalid) }
        }
        AppleStorageKeyProvider("prod-account_1.db")
        AppleStorageKeyProvider("x".repeat(64))
    }
}
