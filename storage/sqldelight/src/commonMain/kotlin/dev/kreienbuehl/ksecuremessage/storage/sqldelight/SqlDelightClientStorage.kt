package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import app.cash.sqldelight.async.coroutines.awaitAsList
import app.cash.sqldelight.async.coroutines.awaitAsOne
import app.cash.sqldelight.async.coroutines.awaitAsOneOrNull
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.IdentityStore
import dev.kreienbuehl.ksecuremessage.storage.PreKeyStore
import dev.kreienbuehl.ksecuremessage.storage.RemoteIdentityStore
import dev.kreienbuehl.ksecuremessage.storage.SessionInitiationStore
import dev.kreienbuehl.ksecuremessage.storage.SessionStore
import dev.kreienbuehl.ksecuremessage.storage.SignedPreKeyInfo
import dev.kreienbuehl.ksecuremessage.storage.sqldelight.db.ClientStateQueries
import dev.kreienbuehl.ksecuremessage.storage.sqldelight.db.KSecureMessageDatabase
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.CoroutineContext
import kotlin.time.Instant

/**
 * Persistent [ClientStorage] on SQLite through SQLDelight.
 *
 * The application creates the [SqlDriver] for its platform with [Schema]
 * (for example `JdbcSqliteDriver`, `AndroidSqliteDriver`,
 * `NativeSqliteDriver`), and closes it. Every [transaction] is a real SQLite
 * transaction: if the block throws, SQLite rolls back all of its writes. A
 * [Mutex] serializes transactions of this instance; use one instance per
 * database.
 *
 * The JVM and native drivers bind a transaction to the thread that started
 * it. Transaction blocks must not move to another thread, so they must not
 * suspend on I/O or switch dispatchers. `SecureMessageClient` follows this.
 *
 * Private keys and session state are stored as plain BLOBs. This adapter does
 * not encrypt them: protect the database file with platform means.
 *
 * Schema version 2 added the `remote_identity` table (milestone 5), version 3
 * the `retired_session_initiation` table (milestone 6), version 4 nullable
 * signed prekey lifecycle columns (milestone 7). A driver created with
 * [Schema] upgrades an older database on open; an application that manages
 * versions itself calls `Schema.migrate(driver, oldVersion, 4)`. The
 * migrations only add tables and nullable columns. Session state written
 * before milestone 6 stays readable; its format is versioned inside the BLOB.
 * Timestamps are stored as epoch milliseconds.
 */
class SqlDelightClientStorage(driver: SqlDriver) : ClientStorage {
    private val database = KSecureMessageDatabase(driver)
    private val mutex = Mutex()
    private val view = DatabaseView(database.clientStateQueries)

    override val identity: IdentityStore = object : IdentityStore {
        override suspend fun identity() = transaction { identity.identity() }
        override suspend fun store(identity: LocalIdentity) = transaction { this.identity.store(identity) }
    }

    override val remoteIdentities: RemoteIdentityStore = object : RemoteIdentityStore {
        override suspend fun identityKey(address: DeviceAddress) = transaction { remoteIdentities.identityKey(address) }
        override suspend fun store(address: DeviceAddress, identityKey: ByteArray) =
            transaction { remoteIdentities.store(address, identityKey) }
    }

    override val sessions: SessionStore = object : SessionStore {
        override suspend fun load(address: DeviceAddress) = transaction { sessions.load(address) }
        override suspend fun store(session: SecureSession) = transaction { sessions.store(session) }
        override suspend fun remove(address: DeviceAddress) = transaction { sessions.remove(address) }
    }

    override val sessionInitiations: SessionInitiationStore = object : SessionInitiationStore {
        override suspend fun isRetired(remote: DeviceAddress, id: SessionInitiationId) =
            transaction { sessionInitiations.isRetired(remote, id) }
        override suspend fun retire(remote: DeviceAddress, id: SessionInitiationId, signedPreKeyId: SignedPreKeyId?) =
            transaction { sessionInitiations.retire(remote, id, signedPreKeyId) }
        override suspend fun retiredSignedPreKeyIds() = transaction { sessionInitiations.retiredSignedPreKeyIds() }
        override suspend fun removeRetiredFor(signedPreKeyId: SignedPreKeyId) =
            transaction { sessionInitiations.removeRetiredFor(signedPreKeyId) }
    }

    override val preKeys: PreKeyStore = object : PreKeyStore {
        override suspend fun signedPreKey(id: SignedPreKeyId) = transaction { preKeys.signedPreKey(id) }
        override suspend fun currentSignedPreKey() = transaction { preKeys.currentSignedPreKey() }
        override suspend fun storeCurrentSignedPreKey(preKey: SignedPreKeyPair, createdAt: Instant) =
            transaction { preKeys.storeCurrentSignedPreKey(preKey, createdAt) }
        override suspend fun signedPreKeyInfo(id: SignedPreKeyId) = transaction { preKeys.signedPreKeyInfo(id) }
        override suspend fun signedPreKeyInfos() = transaction { preKeys.signedPreKeyInfos() }
        override suspend fun stampLegacySignedPreKeys(at: Instant) = transaction { preKeys.stampLegacySignedPreKeys(at) }
        override suspend fun removeSignedPreKey(id: SignedPreKeyId) = transaction { preKeys.removeSignedPreKey(id) }
        override suspend fun highestSignedPreKeyId() = transaction { preKeys.highestSignedPreKeyId() }
        override suspend fun oneTimePreKey(id: OneTimePreKeyId) = transaction { preKeys.oneTimePreKey(id) }
        override suspend fun publicOneTimePreKeys() = transaction { preKeys.publicOneTimePreKeys() }
        override suspend fun oneTimePreKeyCount() = transaction { preKeys.oneTimePreKeyCount() }
        override suspend fun storeOneTimePreKeys(preKeys: List<OneTimePreKeyPair>) =
            transaction { this.preKeys.storeOneTimePreKeys(preKeys) }
        override suspend fun removeOneTimePreKey(id: OneTimePreKeyId) = transaction { preKeys.removeOneTimePreKey(id) }
        override suspend fun highestOneTimePreKeyId() = transaction { preKeys.highestOneTimePreKeyId() }
    }

    override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T {
        val active = currentCoroutineContext()[ActiveTransaction]
        if (active != null && active.owner === this) return view.block()

        return mutex.withLock {
            withContext(ActiveTransaction(this)) {
                database.transactionWithResult { view.block() }
            }
        }
    }

    /** Marks the coroutine that runs a transaction, so nested calls join it. */
    private class ActiveTransaction(val owner: SqlDelightClientStorage) : CoroutineContext.Element {
        override val key: CoroutineContext.Key<*> get() = ActiveTransaction

        companion object : CoroutineContext.Key<ActiveTransaction>
    }

    companion object {
        /** Database schema, for creating the platform [SqlDriver]. */
        val Schema: SqlSchema<QueryResult.AsyncValue<Unit>> get() = KSecureMessageDatabase.Schema
    }
}

/** Store implementations. Only used inside a database transaction. */
private class DatabaseView(private val queries: ClientStateQueries) : ClientStorage {
    override val identity: IdentityStore = object : IdentityStore {
        override suspend fun identity(): LocalIdentity? =
            queries.selectIdentity { publicKey, privateKey -> LocalIdentity(publicKey, privateKey) }.awaitAsOneOrNull()

        override suspend fun store(identity: LocalIdentity) {
            check(identity() == null) { "A local identity is already stored" }
            queries.insertIdentity(identity.publicKey, identity.privateKey)
        }
    }

    override val remoteIdentities: RemoteIdentityStore = object : RemoteIdentityStore {
        override suspend fun identityKey(address: DeviceAddress): ByteArray? =
            queries.selectRemoteIdentity(address.userId.value, address.deviceId.value).awaitAsOneOrNull()

        override suspend fun store(address: DeviceAddress, identityKey: ByteArray) {
            val pinned = identityKey(address)
            if (pinned != null) {
                check(pinned.contentEquals(identityKey)) { "A different remote identity is already pinned" }
                return
            }
            queries.insertRemoteIdentity(address.userId.value, address.deviceId.value, identityKey.copyOf())
        }
    }

    override val sessions: SessionStore = object : SessionStore {
        override suspend fun load(address: DeviceAddress): SecureSession? =
            queries.selectSession(address.userId.value, address.deviceId.value).awaitAsOneOrNull()
                ?.let { SecureSession(address, it) }

        override suspend fun store(session: SecureSession) {
            queries.upsertSession(session.remote.userId.value, session.remote.deviceId.value, session.state)
        }

        override suspend fun remove(address: DeviceAddress) {
            queries.deleteSession(address.userId.value, address.deviceId.value)
        }
    }

    override val sessionInitiations: SessionInitiationStore = object : SessionInitiationStore {
        override suspend fun isRetired(remote: DeviceAddress, id: SessionInitiationId): Boolean =
            queries.countRetiredSessionInitiation(remote.userId.value, remote.deviceId.value, id.bytes).awaitAsOne() > 0

        override suspend fun retire(remote: DeviceAddress, id: SessionInitiationId, signedPreKeyId: SignedPreKeyId?) {
            queries.insertRetiredSessionInitiation(
                remote.userId.value,
                remote.deviceId.value,
                id.bytes,
                signedPreKeyId?.value?.toLong(),
            )
        }

        override suspend fun retiredSignedPreKeyIds(): Set<SignedPreKeyId> =
            queries.selectRetiredSignedPreKeyIds().awaitAsList().map { SignedPreKeyId(it.toInt()) }.toSet()

        override suspend fun removeRetiredFor(signedPreKeyId: SignedPreKeyId) {
            queries.deleteRetiredForSignedPreKey(signedPreKeyId.value.toLong())
        }
    }

    override val preKeys: PreKeyStore = object : PreKeyStore {
        override suspend fun signedPreKey(id: SignedPreKeyId): SignedPreKeyPair? =
            queries.selectSignedPreKey(id.value.toLong(), ::signedPreKeyPair).awaitAsOneOrNull()

        override suspend fun currentSignedPreKey(): SignedPreKeyPair? =
            state().current_signed_pre_key_id?.let { queries.selectSignedPreKey(it, ::signedPreKeyPair).awaitAsOne() }

        override suspend fun storeCurrentSignedPreKey(preKey: SignedPreKeyPair, createdAt: Instant) {
            require(preKey.id.value > (highestSignedPreKeyId()?.value ?: -1)) { "Signed prekey ID already used" }
            val id = preKey.id.value.toLong()
            val millis = createdAt.toEpochMilliseconds()
            queries.insertSignedPreKey(id, preKey.publicKey, preKey.signature, preKey.privateKey, millis)
            queries.markCurrentSignedPreKeyReplaced(millis)
            queries.makeSignedPreKeyCurrent(id)
        }

        override suspend fun signedPreKeyInfo(id: SignedPreKeyId): SignedPreKeyInfo? =
            signedPreKeyInfos().firstOrNull { it.id == id }

        override suspend fun signedPreKeyInfos(): List<SignedPreKeyInfo> =
            queries.selectSignedPreKeyInfos { id, isCurrent, createdAt, replacedAt ->
                SignedPreKeyInfo(
                    id = SignedPreKeyId(id.toInt()),
                    isCurrent = isCurrent,
                    createdAt = createdAt?.let(Instant::fromEpochMilliseconds),
                    replacedAt = replacedAt?.let(Instant::fromEpochMilliseconds),
                )
            }.awaitAsList()

        override suspend fun stampLegacySignedPreKeys(at: Instant) {
            val millis = at.toEpochMilliseconds()
            queries.stampLegacySignedPreKeyCreation(millis)
            queries.stampLegacySignedPreKeyReplacement(millis)
        }

        override suspend fun removeSignedPreKey(id: SignedPreKeyId) {
            require(id.value.toLong() != state().current_signed_pre_key_id) { "The current signed prekey cannot be removed" }
            queries.deleteSignedPreKey(id.value.toLong())
        }

        override suspend fun highestSignedPreKeyId(): SignedPreKeyId? =
            state().highest_signed_pre_key_id?.let { SignedPreKeyId(it.toInt()) }

        override suspend fun oneTimePreKey(id: OneTimePreKeyId): OneTimePreKeyPair? =
            queries.selectOneTimePreKey(id.value.toLong()) { rowId, publicKey, privateKey ->
                OneTimePreKeyPair(OneTimePreKeyId(rowId.toInt()), publicKey, privateKey)
            }.awaitAsOneOrNull()

        override suspend fun publicOneTimePreKeys(): List<PublicOneTimePreKey> =
            queries.selectPublicOneTimePreKeys { id, publicKey ->
                PublicOneTimePreKey(OneTimePreKeyId(id.toInt()), publicKey)
            }.awaitAsList()

        override suspend fun oneTimePreKeyCount(): Int = queries.countOneTimePreKeys().awaitAsOne().toInt()

        override suspend fun storeOneTimePreKeys(preKeys: List<OneTimePreKeyPair>) {
            if (preKeys.isEmpty()) return
            val ids = preKeys.map { it.id.value }
            require(ids.toSet().size == ids.size) { "Duplicate one-time prekey ID" }
            val highest = highestOneTimePreKeyId()?.value ?: -1
            require(ids.all { it > highest }) { "One-time prekey ID already used" }
            for (preKey in preKeys) {
                queries.insertOneTimePreKey(preKey.id.value.toLong(), preKey.publicKey, preKey.privateKey)
            }
            queries.setHighestOneTimePreKeyId(ids.max().toLong())
        }

        override suspend fun removeOneTimePreKey(id: OneTimePreKeyId) {
            queries.deleteOneTimePreKey(id.value.toLong())
        }

        override suspend fun highestOneTimePreKeyId(): OneTimePreKeyId? =
            state().highest_one_time_pre_key_id?.let { OneTimePreKeyId(it.toInt()) }

        private suspend fun state() = queries.selectPreKeyState().awaitAsOne()
    }

    override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T = block()
}

private fun signedPreKeyPair(id: Long, publicKey: ByteArray, signature: ByteArray, privateKey: ByteArray) =
    SignedPreKeyPair(SignedPreKeyId(id.toInt()), publicKey, signature, privateKey)
