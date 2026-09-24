package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.PreKeyStore
import dev.kreienbuehl.ksecuremessage.storage.RemoteIdentityStore
import dev.kreienbuehl.ksecuremessage.storage.SessionInitiationStore
import dev.kreienbuehl.ksecuremessage.storage.SessionStore
import dev.kreienbuehl.ksecuremessage.storage.inmemory.InMemoryServerStorage

internal val ALICE = DeviceAddress(UserId("alice"), DeviceId("phone"))
internal val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))
internal val CAROL = DeviceAddress(UserId("carol"), DeviceId("tablet"))

/** Stands in for the relay server: bundles plus one mailbox per device. */
internal class FakeNetwork : SecureMessageTransport {
    val bundles = mutableMapOf<DeviceAddress, PreKeyBundle>()
    private val mailboxes = mutableMapOf<DeviceAddress, MutableList<EncryptedEnvelope>>()

    val publications = mutableListOf<PreKeyPublication>()

    /** Only records: these tests set [bundles] by hand, see [publish]. */
    override suspend fun publishPreKeys(publication: PreKeyPublication) {
        publications += publication
    }

    override suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle = bundles.getValue(address)

    override suspend fun send(envelope: EncryptedEnvelope) {
        mailboxes.getOrPut(envelope.recipient) { mutableListOf() }.add(envelope)
    }

    override suspend fun receive(address: DeviceAddress): List<EncryptedEnvelope> =
        mailboxes.remove(address)?.toList().orEmpty()

    /** Stands in for publication: the relay hands out the lowest one-time prekey, or none. */
    suspend fun publish(client: SecureMessageClient, withOneTimePreKey: Boolean = true) {
        bundles[client.localAddress] = client.currentPreKeyBundle().copy(
            oneTimePreKey = if (withOneTimePreKey) client.publicOneTimePreKeys().first() else null,
        )
    }
}

/**
 * Stands in for the relay server with the real server-side prekey semantics
 * of [InMemoryServerStorage]: publication is idempotent and every fetch
 * consumes one one-time prekey. [beforeNetworkCall] runs on every call.
 */
internal class ServerBackedNetwork(
    private val beforeNetworkCall: () -> Unit = {},
) : SecureMessageTransport {
    val server = InMemoryServerStorage()

    override suspend fun publishPreKeys(publication: PreKeyPublication) {
        beforeNetworkCall()
        server.preKeys.publish(publication)
    }

    override suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle {
        beforeNetworkCall()
        return server.preKeys.consumePreKeyBundle(address) ?: throw SecureMessageTransportException.DeviceNotFound(address)
    }

    override suspend fun send(envelope: EncryptedEnvelope) {
        beforeNetworkCall()
        server.mailboxes.enqueue(envelope)
    }

    override suspend fun receive(address: DeviceAddress): List<EncryptedEnvelope> {
        beforeNetworkCall()
        return server.mailboxes.drain(address)
    }
}

/** Delegates to [delegate] and tracks whether a transaction is running. */
internal class TransactionTrackingStorage(private val delegate: ClientStorage) : ClientStorage by delegate {
    var depth = 0
        private set

    override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T {
        depth++
        try {
            return delegate.transaction(block)
        } finally {
            depth--
        }
    }
}

internal fun EncryptedEnvelope.tampered() =
    copy(payload = payload.copyOf().also { it[it.lastIndex] = (it[it.lastIndex].toInt() xor 1).toByte() })

internal class StorageFailure : Exception("Injected storage failure")

/** Delegates to [delegate], but can make writes inside a transaction fail. */
internal class FailingClientStorage(private val delegate: ClientStorage) : ClientStorage {
    var failSessionStore = false
    var failOneTimePreKeyRemoval = false
    var failRemoteIdentityStore = false
    var failRetire = false

    override val identity get() = delegate.identity
    override val remoteIdentities get() = delegate.remoteIdentities
    override val sessions get() = delegate.sessions
    override val sessionInitiations get() = delegate.sessionInitiations
    override val preKeys get() = delegate.preKeys

    override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T =
        delegate.transaction { FailingView(this).block() }

    private inner class FailingView(private val tx: ClientStorage) : ClientStorage {
        override val identity get() = tx.identity

        override val remoteIdentities: RemoteIdentityStore = object : RemoteIdentityStore by tx.remoteIdentities {
            override suspend fun store(address: DeviceAddress, identityKey: ByteArray) {
                if (failRemoteIdentityStore) throw StorageFailure()
                tx.remoteIdentities.store(address, identityKey)
            }
        }

        override val sessions: SessionStore = object : SessionStore by tx.sessions {
            override suspend fun store(session: SecureSession) {
                if (failSessionStore) throw StorageFailure()
                tx.sessions.store(session)
            }
        }

        override val sessionInitiations: SessionInitiationStore = object : SessionInitiationStore by tx.sessionInitiations {
            override suspend fun retire(remote: DeviceAddress, id: SessionInitiationId) {
                if (failRetire) throw StorageFailure()
                tx.sessionInitiations.retire(remote, id)
            }
        }

        override val preKeys: PreKeyStore = object : PreKeyStore by tx.preKeys {
            override suspend fun removeOneTimePreKey(id: OneTimePreKeyId) {
                if (failOneTimePreKeyRemoval) throw StorageFailure()
                tx.preKeys.removeOneTimePreKey(id)
            }
        }

        override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T = block()
    }
}
