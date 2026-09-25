package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

private fun hex(value: String): ByteArray =
    ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

private fun id(hex: String) = LogicalMessageId.fromByteArray(hex(hex))

class SecurePayloadCodecTest {
    // Version-1 compatibility vectors. Written out by hand from
    // docs/message-reliability.md; never regenerate them with the codec.
    private val sequentialId = "000102030405060708090a0b0c0d0e0f"
    private val applicationVector = hex("0101" + sequentialId + "00000002" + "6869")
    private val acknowledgementVector = hex("0102" + sequentialId)
    private val emptyBodyVector = hex("0101" + "00000000000000000000000000000000" + "00000000")
    private val maxIdAcknowledgementVector = hex("0102" + "ffffffffffffffffffffffffffffffff")

    private inline fun <reified T : ProtocolException> assertRejected(bytes: ByteArray) {
        assertFailsWith<T> { SecurePayloadCodec.decode(bytes) }
    }

    @Test
    fun applicationMessageMatchesVector() {
        val payload = SecurePayload.ApplicationMessage(id(sequentialId), "hi".encodeToByteArray())
        assertContentEquals(applicationVector, SecurePayloadCodec.encode(payload))

        val decoded = assertIs<SecurePayload.ApplicationMessage>(SecurePayloadCodec.decode(applicationVector))
        assertEquals(id(sequentialId), decoded.id)
        assertContentEquals("hi".encodeToByteArray(), decoded.body)
    }

    @Test
    fun acknowledgementMatchesVector() {
        assertContentEquals(acknowledgementVector, SecurePayloadCodec.encode(SecurePayload.Acknowledgement(id(sequentialId))))

        val decoded = assertIs<SecurePayload.Acknowledgement>(SecurePayloadCodec.decode(acknowledgementVector))
        assertEquals(id(sequentialId), decoded.id)
    }

    @Test
    fun minimalAndMaximalIdsRoundTrip() {
        val min = id("00000000000000000000000000000000")
        assertContentEquals(emptyBodyVector, SecurePayloadCodec.encode(SecurePayload.ApplicationMessage(min, ByteArray(0))))
        val empty = assertIs<SecurePayload.ApplicationMessage>(SecurePayloadCodec.decode(emptyBodyVector))
        assertEquals(min, empty.id)
        assertEquals(0, empty.body.size)

        val max = id("ffffffffffffffffffffffffffffffff")
        assertContentEquals(maxIdAcknowledgementVector, SecurePayloadCodec.encode(SecurePayload.Acknowledgement(max)))
        assertEquals(max, SecurePayloadCodec.decode(maxIdAcknowledgementVector).id)
    }

    @Test
    fun randomIdsRoundTrip() {
        repeat(20) {
            val id = LogicalMessageId.random()
            val body = ByteArray(it * 7) { i -> (i * 13).toByte() }
            val decoded = assertIs<SecurePayload.ApplicationMessage>(
                SecurePayloadCodec.decode(SecurePayloadCodec.encode(SecurePayload.ApplicationMessage(id, body))),
            )
            assertEquals(id, decoded.id)
            assertContentEquals(body, decoded.body)
        }
    }

    @Test
    fun maximalBodyRoundTrips() {
        val body = ByteArray(SecurePayloadCodec.MAX_BODY_SIZE) { it.toByte() }
        val encoded = SecurePayloadCodec.encode(SecurePayload.ApplicationMessage(id(sequentialId), body))
        assertEquals(SecurePayloadCodec.MAX_ENCODED_SIZE, encoded.size)
        assertContentEquals(body, assertIs<SecurePayload.ApplicationMessage>(SecurePayloadCodec.decode(encoded)).body)
    }

    @Test
    fun oversizedBodyIsRejectedOnEncode() {
        assertFailsWith<ProtocolException.MessageTooLarge> {
            SecurePayloadCodec.encode(
                SecurePayload.ApplicationMessage(id(sequentialId), ByteArray(SecurePayloadCodec.MAX_BODY_SIZE + 1)),
            )
        }
    }

    @Test
    fun oversizedInputIsRejectedBeforeParsing() {
        assertRejected<ProtocolException.MessageTooLarge>(ByteArray(SecurePayloadCodec.MAX_ENCODED_SIZE + 1))
    }

    @Test
    fun oversizedLengthPrefixIsRejectedWithoutAllocation() {
        for (length in listOf("00030001", "7fffffff", "ffffffff", "80000000")) {
            assertRejected<ProtocolException.MalformedSecurePayload>(hex("0101" + sequentialId + length + "6869"))
        }
    }

    @Test
    fun everyTruncationIsRejected() {
        for (vector in listOf(applicationVector, acknowledgementVector, emptyBodyVector)) {
            for (size in 0 until vector.size) {
                assertRejected<ProtocolException.MalformedSecurePayload>(vector.copyOf(size))
            }
        }
    }

    @Test
    fun trailingBytesAreRejected() {
        assertRejected<ProtocolException.MalformedSecurePayload>(applicationVector + byteArrayOf(0))
        assertRejected<ProtocolException.MalformedSecurePayload>(acknowledgementVector + byteArrayOf(0))
    }

    @Test
    fun unsupportedVersionIsRejected() {
        for (version in listOf(0x00, 0x02, 0xff)) {
            val bytes = applicationVector.copyOf().also { it[0] = version.toByte() }
            val error = assertFailsWith<ProtocolException.UnsupportedSecurePayloadVersion> { SecurePayloadCodec.decode(bytes) }
            assertEquals(version, error.version)
        }
    }

    @Test
    fun unknownTypeIsRejected() {
        for (type in listOf(0x00, 0x03, 0xff)) {
            assertRejected<ProtocolException.MalformedSecurePayload>(acknowledgementVector.copyOf().also { it[1] = type.toByte() })
        }
    }

    @Test
    fun legacyRawPlaintextIsNotAFrame() {
        assertRejected<ProtocolException.UnsupportedSecurePayloadVersion>("hello".encodeToByteArray())
        assertRejected<ProtocolException.MalformedSecurePayload>(ByteArray(0))
    }

    /** The largest frame still fits the ciphertext wire format after ratchet encryption. */
    @Test
    fun maximalFrameFitsTheWireFormat() = runTest {
        val engine: ProtocolEngine = KodiumProtocolEngine()
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val frame = SecurePayloadCodec.encode(
            SecurePayload.ApplicationMessage(id(sequentialId), ByteArray(SecurePayloadCodec.MAX_BODY_SIZE)),
        )
        val session = engine.initiateSession(alice.identity, bob.bundle())
        val encrypted = engine.encrypt(session, frame)
        val wire = CiphertextMessageCodec.encode(encrypted.message)
        val decoded = assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(wire))
        val accepted = engine.accept(bob, alice.address, decoded)
        assertContentEquals(frame, accepted.plaintext)
    }
}
