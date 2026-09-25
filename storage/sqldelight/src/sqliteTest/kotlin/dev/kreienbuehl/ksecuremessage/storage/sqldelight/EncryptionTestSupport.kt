package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.storage.encryption.ClientRecordCipher
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Clock
import kotlin.time.Instant

/** Relay with bundles set directly; envelopes wait per recipient. */
class TestRelay : SecureMessageTransport {
    val bundles = mutableMapOf<DeviceAddress, PreKeyBundle>()
    private val mailboxes = mutableMapOf<DeviceAddress, MutableList<EncryptedEnvelope>>()

    suspend fun publish(client: SecureMessageClient) {
        bundles[client.localAddress] = bundleOf(client)
    }

    suspend fun bundleOf(client: SecureMessageClient): PreKeyBundle =
        client.currentPreKeyBundle().copy(oneTimePreKey = client.publicOneTimePreKeys().first())

    override suspend fun publishPreKeys(publication: PreKeyPublication) = error("Tests set bundles directly")

    override suspend fun fetchPreKeyBundle(address: DeviceAddress) = bundles.getValue(address)

    override suspend fun send(envelope: EncryptedEnvelope) {
        mailboxes.getOrPut(envelope.recipient) { mutableListOf() }.add(envelope)
    }

    override suspend fun receive(address: DeviceAddress) = mailboxes.remove(address)?.toList().orEmpty()

    fun waiting(address: DeviceAddress): Int = mailboxes[address]?.size ?: 0
}

class TestClock(var now: Instant) : Clock {
    override fun now(): Instant = now
}

/** Record cipher whose seal calls fail on demand, for atomicity tests. */
class FailingRecords(private val delegate: ClientRecordCipher) : ClientRecordCipher by delegate {
    /** Names of the seal functions that fail: identity, signedPreKey, oneTimePreKey, session, pending. */
    var failing: Set<String> = emptySet()

    /** Fails the seal call with this number (1-based, all record kinds counted), if set. */
    var failAtSeal: Int? = null
    /** Cancels the coroutine at the seal call with this number (1-based), if set. */
    var cancelAtSeal: Int? = null

    var seals = 0
        private set

    private fun check(kind: String) {
        seals++
        if (seals == cancelAtSeal) throw CancellationException("Injected cancellation at $kind encryption")
        if (kind in failing || seals == failAtSeal) throw IllegalStateException("Injected $kind encryption failure")
    }

    override suspend fun sealIdentity(identity: LocalIdentity): ByteArray = check("identity").let { delegate.sealIdentity(identity) }
    override suspend fun sealSignedPreKey(preKey: SignedPreKeyPair): ByteArray =
        check("signedPreKey").let { delegate.sealSignedPreKey(preKey) }
    override suspend fun sealOneTimePreKey(preKey: OneTimePreKeyPair): ByteArray =
        check("oneTimePreKey").let { delegate.sealOneTimePreKey(preKey) }
    override suspend fun sealSession(session: SecureSession): ByteArray = check("session").let { delegate.sealSession(session) }
    override suspend fun sealPendingFrame(recipient: DeviceAddress, id: LogicalMessageId, frame: ByteArray): ByteArray =
        check("pending").let { delegate.sealPendingFrame(recipient, id, frame) }

    companion object {
        /** A factory for [SqlDelightClientStorage.open] that records the cipher it created. */
        fun factory(created: MutableList<FailingRecords>, failAtSeal: Int? = null): RecordCipherFactory =
            { key, retained -> FailingRecords(ClientRecordCipher(key, *retained.toTypedArray())).also { it.failAtSeal = failAtSeal; created += it } }
    }
}
