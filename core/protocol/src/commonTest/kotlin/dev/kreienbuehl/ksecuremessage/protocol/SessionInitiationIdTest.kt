package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

private fun key(first: Int) = ByteArray(ProtocolConstants.PUBLIC_KEY_SIZE) { (first + it).toByte() }

/**
 * Frozen vectors: persisted IDs and the simultaneous-initiation decision
 * depend on this construction. Computed independently (Python hashlib) from
 * the layout in docs/session-lifecycle.md.
 */
class SessionInitiationIdTest {
    private val initiator = key(0)
    private val responder = key(64)
    private val ephemeral = key(128)

    private fun id(oneTimePreKeyId: OneTimePreKeyId?, first: ByteArray = initiator, second: ByteArray = responder) =
        SessionInitiationId.derive(first, second, ephemeral, SignedPreKeyId(7), oneTimePreKeyId)

    @Test
    fun matchesVectorWithOneTimePreKey() {
        assertContentEquals(
            hex("745b4451b3e2779db9dd15f4c3ba749abb1543017356b89497ba24ef5ab55ef0"),
            id(OneTimePreKeyId(42)).bytes,
        )
    }

    @Test
    fun matchesVectorWithoutOneTimePreKey() {
        assertContentEquals(
            hex("e2e3a6c8d278e888b5a8d35e75ba090bb98977612b29d2a9d12ecfcf6c621d2a"),
            id(null).bytes,
        )
    }

    @Test
    fun rolesAreBound() {
        assertContentEquals(
            hex("2dc699b7e3b54a776f7339de031c6548e45a2a6ae98154d16d85ad231f978787"),
            id(null, first = responder, second = initiator).bytes,
        )
    }

    @Test
    fun messageIdMatchesDerivation() {
        val message = PreKeyMessage(initiator, ephemeral, SignedPreKeyId(7), OneTimePreKeyId(42), RatchetMessage(byteArrayOf(1)))
        assertEquals(id(OneTimePreKeyId(42)), SessionInitiationId.of(message, responder))
    }

    @Test
    fun domainIsUnchanged() {
        assertEquals("KSecureMessage-SessionInitiation-v1", ProtocolConstants.SESSION_INITIATION_DOMAIN)
    }

    @Test
    fun orderIsUnsignedLexicographic() {
        val low = SessionInitiationId(ByteArray(32).also { it[0] = 0x7F })
        val high = SessionInitiationId(ByteArray(32).also { it[0] = 0x80.toByte() })
        val last = SessionInitiationId(ByteArray(32).also { it[31] = 1 })
        assertTrue(low < high, "0x80 sorts after 0x7F")
        assertTrue(SessionInitiationId(ByteArray(32)) < last)
        assertEquals(0, low.compareTo(SessionInitiationId(low.bytes)))
        assertEquals(low, SessionInitiationId(low.bytes))
        assertNotEquals(low, high)
    }

    @Test
    fun bytesAreCopied() {
        val source = ByteArray(32)
        val id = SessionInitiationId(source)
        source[0] = 1
        id.bytes[0] = 2
        assertContentEquals(ByteArray(32), id.bytes)
        assertEquals("SessionInitiationId(<redacted>)", id.toString())
    }

    @Test
    fun invalidInputIsRejected() {
        assertFailsWith<IllegalArgumentException> { SessionInitiationId(ByteArray(31)) }
        assertFailsWith<ProtocolException.InvalidMessage> {
            SessionInitiationId.derive(ByteArray(63), responder, ephemeral, SignedPreKeyId(7), null)
        }
    }
}
