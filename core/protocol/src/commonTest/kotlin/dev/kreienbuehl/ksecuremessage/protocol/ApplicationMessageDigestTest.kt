package dev.kreienbuehl.ksecuremessage.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse

private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

/**
 * Frozen vectors: stored processed-message digests depend on this
 * construction. Computed independently (Python hashlib) from the layout in
 * docs/application-delivery.md.
 */
class ApplicationMessageDigestTest {
    @Test
    fun matchesVectorForAnEmptyBody() {
        assertContentEquals(
            hex("7d44197a4b18d43f3b5e30289ec8d6c2b67b868a4fbaf426fe47cd39ec4caa10"),
            ApplicationMessageDigest.of(ByteArray(0)),
        )
    }

    @Test
    fun matchesVectorForABody() {
        assertContentEquals(
            hex("ff761c428d54479fc3f9f6fddc7555dcbf1dd3b42d9a7620065a43b5f9f26e54"),
            ApplicationMessageDigest.of("hello".encodeToByteArray()),
        )
    }

    @Test
    fun isDomainSeparatedFromPlainSha256() {
        val plain = hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        assertFalse(plain.contentEquals(ApplicationMessageDigest.of("hello".encodeToByteArray())))
    }

    @Test
    fun hasTheDocumentedSizeAndLeavesTheBodyUnchanged() {
        val body = "hello".encodeToByteArray()
        assertEquals(ApplicationMessageDigest.SIZE, ApplicationMessageDigest.of(body).size)
        assertContentEquals("hello".encodeToByteArray(), body)
    }
}
