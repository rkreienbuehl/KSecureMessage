package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

private fun key(first: Int) = PublicIdentityKey(ByteArray(PublicIdentityKey.SIZE) { (first + it).toByte() })

private fun address(user: String, device: String) = DeviceAddress(UserId(user), DeviceId(device))

/**
 * Frozen vectors of safety number version 1: users compare these values and
 * scan these payloads. Computed independently (Python hashlib) from the
 * layout in docs/identity-verification.md.
 */
class SafetyNumberTest {
    private val alice = address("alice", "phone")
    private val bob = address("bob", "phone")
    private val aliceKey = key(0)
    private val bobKey = key(64)

    private fun aliceBob() = SafetyNumber.derive(alice, aliceKey, bob, bobKey)

    @Test
    fun alicePhoneBobPhoneVector() {
        val number = aliceBob()
        assertContentEquals(hex("4e69d8aafd2b0bbd208c4780fcf8ed30cc8ae381d0f8ce66ad1aaf963d88e91c"), number.fingerprint.bytes)
        // The address encoding orders by length prefix first: bob (3 bytes) before alice (5 bytes).
        assertEquals(bob, number.first)
        assertEquals(alice, number.second)
    }

    @Test
    fun callerOrderDoesNotMatter() {
        val reversed = SafetyNumber.derive(bob, bobKey, alice, aliceKey)
        assertEquals(aliceBob(), reversed)
        assertContentEquals(hex("4e69d8aafd2b0bbd208c4780fcf8ed30cc8ae381d0f8ce66ad1aaf963d88e91c"), reversed.fingerprint.bytes)
        assertContentEquals(aliceBob().encode(), reversed.encode())
        assertEquals(aliceBob().displayString, reversed.displayString)
    }

    @Test
    fun keysStayBoundToTheirAddresses() {
        // Same addresses, keys swapped between them: a different pair of identities.
        assertNotEquals(aliceBob().fingerprint, SafetyNumber.derive(alice, bobKey, bob, aliceKey).fingerprint)
    }

    @Test
    fun otherDeviceIdGivesAnotherFingerprint() {
        val number = SafetyNumber.derive(alice, aliceKey, address("bob", "laptop"), bobKey)
        assertContentEquals(hex("2e81c75fa9d2104992d390e8dcab3bef2dfef0ded45c3fdb3c3d7d5f5229bcd8"), number.fingerprint.bytes)
    }

    @Test
    fun otherUserIdGivesAnotherFingerprint() {
        val number = SafetyNumber.derive(alice, aliceKey, address("carol", "phone"), bobKey)
        assertContentEquals(hex("853a4649daa2657430540536267ef986103e3b633d2db386b17c68687d2aa62b"), number.fingerprint.bytes)
    }

    @Test
    fun oneIdentityBitGivesAnotherFingerprint() {
        val flipped = bobKey.bytes.also { it[10] = (it[10].toInt() xor 1).toByte() }
        val number = SafetyNumber.derive(alice, aliceKey, bob, PublicIdentityKey(flipped))
        assertContentEquals(hex("ec796b2a98df81adf248f9a24c30c17afb91bc826a98b4f345c05a7d1e7cebda"), number.fingerprint.bytes)
    }

    @Test
    fun utf8AddressVector() {
        val first = address("jürg", "📱")
        val second = address("zoë", "ordinateur-été")
        val number = SafetyNumber.derive(first, aliceKey, second, bobKey)
        assertContentEquals(hex("5ce1aac4019180b625acb4ea463cc8ed6e2a365c4d909a95a808841b2a1f2292"), number.fingerprint.bytes)
        assertEquals("80442 05537 95979 02860 41028 08776 72514 69276 17705 93672 34881 31679", number.displayString)
        assertContentEquals(
            hex(
                "01000000047a6fc3ab000000106f7264696e61746575722dc3a974c3a9000000056ac3bc726700000004f09f93b1" +
                    "5ce1aac4019180b625acb4ea463cc8ed6e2a365c4d909a95a808841b2a1f2292",
            ),
            number.encode(),
        )
    }

    @Test
    fun machineReadablePayloadVector() {
        val expected = hex(
            "0100000003626f620000000570686f6e6500000005616c6963650000000570686f6e65" +
                "4e69d8aafd2b0bbd208c4780fcf8ed30cc8ae381d0f8ce66ad1aaf963d88e91c",
        )
        assertContentEquals(expected, aliceBob().encode())
        val decoded = SafetyNumberCodec.decode(expected)
        assertEquals(bob, decoded.first)
        assertEquals(alice, decoded.second)
        assertEquals(aliceBob().fingerprint, decoded.fingerprint)
        assertEquals(SafetyNumberComparison.MATCH, aliceBob().compare(decoded))
    }

    @Test
    fun humanReadableVector() {
        val number = aliceBob()
        assertEquals("21181 68061 76315 60300 92879 50157 99880 13601 55948 43789 09305 08968", number.displayString)
        assertEquals(SafetyNumber.GROUP_COUNT, number.groups.size)
        assertTrue(number.groups.all { it.length == SafetyNumber.GROUP_DIGITS && it.all(Char::isDigit) })
    }

    @Test
    fun displayUsesTheFullGroupRange() {
        // All-ones chunks are 1048575 = 10 * 100000 + 48575; zero stays zero-padded.
        val ones = SafetyNumber.groups(ByteArray(SafetyFingerprint.SIZE) { 0xFF.toByte() })
        assertEquals(List(12) { "48575" }, ones)
        assertEquals(List(12) { "00000" }, SafetyNumber.groups(ByteArray(SafetyFingerprint.SIZE)))
        // Only bytes 0..29 are displayed.
        val tail = ByteArray(SafetyFingerprint.SIZE).also { it[30] = 1; it[31] = 1 }
        assertEquals(List(12) { "00000" }, SafetyNumber.groups(tail))
    }

    @Test
    fun comparisonDetectsMismatchAndOtherDevices() {
        val number = aliceBob()
        val otherKey = SafetyNumber.derive(alice, aliceKey, bob, key(1))
        assertEquals(SafetyNumberComparison.MISMATCH, number.compare(SafetyNumberCodec.decode(otherKey.encode())))
        val otherDevice = SafetyNumber.derive(alice, aliceKey, address("bob", "laptop"), bobKey)
        assertEquals(SafetyNumberComparison.DIFFERENT_DEVICES, number.compare(SafetyNumberCodec.decode(otherDevice.encode())))
    }

    @Test
    fun decodingIsStrict() {
        val valid = aliceBob().encode()
        assertFailsWith<IllegalArgumentException> { SafetyNumberCodec.decode(valid + 0) }
        assertFailsWith<IllegalArgumentException> { SafetyNumberCodec.decode(valid.copyOf(valid.size - 1)) }
        assertFailsWith<IllegalArgumentException> { SafetyNumberCodec.decode(byteArrayOf()) }
        assertFailsWith<IllegalArgumentException> { SafetyNumberCodec.decode(valid.copyOf().also { it[0] = 2 }) }
        // 0xC3 0x28 is not valid UTF-8; the user ID "bob" becomes 3 bytes with a broken sequence.
        assertFailsWith<IllegalArgumentException> {
            SafetyNumberCodec.decode(valid.copyOf().also { it[5] = 0xC3.toByte(); it[6] = 0x28 })
        }
        // Addresses swapped: not canonical.
        val swapped = byteArrayOf(1) + SafetyNumber.encodeAddress(alice) + SafetyNumber.encodeAddress(bob) + aliceBob().fingerprint.bytes
        assertFailsWith<IllegalArgumentException> { SafetyNumberCodec.decode(swapped) }
        val same = byteArrayOf(1) + SafetyNumber.encodeAddress(bob) + SafetyNumber.encodeAddress(bob) + aliceBob().fingerprint.bytes
        assertFailsWith<IllegalArgumentException> { SafetyNumberCodec.decode(same) }
    }

    @Test
    fun inputsAreChecked() {
        assertFailsWith<IllegalArgumentException> { SafetyNumber.derive(alice, aliceKey, alice, bobKey) }
        assertFailsWith<IllegalArgumentException> { PublicIdentityKey(ByteArray(63)) }
        assertFailsWith<IllegalArgumentException> { PublicIdentityKey(ByteArray(65)) }
        assertFailsWith<IllegalArgumentException> { SafetyFingerprint(ByteArray(31)) }
        // A lone surrogate would encode like "?".
        assertFailsWith<IllegalArgumentException> { SafetyNumber.derive(address("a\uD800", "x"), aliceKey, bob, bobKey) }
    }

    @Test
    fun bytesAreCopied() {
        val source = ByteArray(PublicIdentityKey.SIZE)
        val identityKey = PublicIdentityKey(source)
        source[0] = 1
        assertContentEquals(ByteArray(PublicIdentityKey.SIZE), identityKey.bytes)
        identityKey.bytes[0] = 1
        assertContentEquals(ByteArray(PublicIdentityKey.SIZE), identityKey.bytes)

        val number = aliceBob()
        number.fingerprint.bytes[0] = 0
        number.encode()[0] = 0
        assertEquals(aliceBob(), number)
        assertContentEquals(aliceBob().encode(), number.encode())
    }

    @Test
    fun domainIsUnchanged() {
        assertEquals("KSecureMessage-SafetyNumber-v1", ProtocolConstants.SAFETY_NUMBER_DOMAIN)
    }

    @Test
    fun toStringHasNoKeyBytes() {
        assertEquals("PublicIdentityKey(64 bytes)", aliceKey.toString())
    }
}
