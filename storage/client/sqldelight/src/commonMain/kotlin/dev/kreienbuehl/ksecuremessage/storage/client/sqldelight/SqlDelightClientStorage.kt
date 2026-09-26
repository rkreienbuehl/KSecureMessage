package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.async.coroutines.awaitAsList
import app.cash.sqldelight.async.coroutines.awaitAsOne
import app.cash.sqldelight.async.coroutines.awaitAsOneOrNull
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.DeviceAuthenticationKeyStore
import dev.kreienbuehl.ksecuremessage.storage.IdentityStore
import dev.kreienbuehl.ksecuremessage.storage.PendingOutboundMessage
import dev.kreienbuehl.ksecuremessage.storage.PendingOutboundStore
import dev.kreienbuehl.ksecuremessage.storage.PreKeyStore
import dev.kreienbuehl.ksecuremessage.storage.ProcessedInboundStore
import dev.kreienbuehl.ksecuremessage.storage.RemoteIdentityRecord
import dev.kreienbuehl.ksecuremessage.storage.RemoteIdentityStore
import dev.kreienbuehl.ksecuremessage.storage.SessionInitiationStore
import dev.kreienbuehl.ksecuremessage.storage.SessionStore
import dev.kreienbuehl.ksecuremessage.storage.SignedPreKeyInfo
import dev.kreienbuehl.ksecuremessage.storage.client.sqldelight.db.ClientStateQueries
import dev.kreienbuehl.ksecuremessage.storage.encryption.ClientRecordCipher
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationInProgressException
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationManager
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationPhase
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationStatus
import dev.kreienbuehl.ksecuremessage.storage.client.sqldelight.SqlDelightStorageKeyRotationBackend.Companion.storageKeyId
import dev.kreienbuehl.ksecuremessage.storage.client.sqldelight.db.KSecureMessageDatabase
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.cancellation.CancellationException
import kotlin.coroutines.CoroutineContext
import kotlin.time.Instant

/**
 * Persistent [ClientStorage] on SQLite through SQLDelight, with record-level
 * encryption of the sensitive records (docs/storage-encryption.md).
 *
 * Open it with [open]. The application creates the [SqlDriver] for its
 * platform with [Schema] (for example `JdbcSqliteDriver`,
 * `AndroidSqliteDriver`, `NativeSqliteDriver`), and closes it. Every
 * [transaction] is a real SQLite transaction: if the block throws, SQLite
 * rolls back all of its writes. A [Mutex] serializes transactions of this
 * instance; use one instance per database.
 *
 * The JVM and native drivers bind a transaction to the thread that started
 * it. Transaction blocks must not move to another thread, so they must not
 * suspend on I/O or switch dispatchers. `SecureMessageClient` follows this.
 * Sealing and opening records is CPU work inside the transaction.
 *
 * The local identity, the device authentication key, signed and one-time
 * prekeys (whole key pairs), session
 * state and pending message frames are stored as AES-256-GCM records bound
 * to their record type and row key. IDs, addresses, timestamps, high-water
 * marks, remote identity pins, retired initiations and processed message IDs
 * stay plaintext metadata. There is no unencrypted mode. A record that does
 * not authenticate throws [StorageEncryptionException]; it is never treated
 * as missing.
 *
 * Schema version 2 added the `remote_identity` table (milestone 5), version 3
 * the `retired_session_initiation` table (milestone 6), version 4 nullable
 * signed prekey lifecycle columns (milestone 7), version 5 the
 * `pending_outbound_message` and `processed_inbound_message` tables
 * (milestone 8), version 6 the `storage_encryption` marker (milestone 9),
 * version 7 the storage key rotation state (milestone 11), version 8 the
 * `device_authentication_key` and `device_authentication_state` tables
 * (milestone 12, docs/server-authentication.md), version 9 the
 * `device_authentication_recovery_key` table (milestone 14,
 * docs/device-recovery.md), version 10 the `remote_identity.verification`
 * column (milestone 15, docs/identity-verification.md), version 11 the
 * `device_authentication_rotation_key` table (milestone 16,
 * docs/device-authentication-rotation.md), version 12 the
 * `device_authentication_last_device_recovery_key` table (milestone 18,
 * docs/last-device-recovery.md). A driver created with
 * [Schema] upgrades an older database on open; an application that manages
 * versions itself calls `Schema.migrate(driver, oldVersion, Schema.version)`. An upgraded database still holds
 * its milestone 8 plaintext until [open] encrypts it. Session state written
 * before milestone 6 stays readable; its format is versioned inside the
 * record. Timestamps are stored as epoch milliseconds.
 */
class SqlDelightClientStorage private constructor(
    private val driver: SqlDriver,
    private val keyProvider: StorageKeyProvider,
    internal val cipherFactory: RecordCipherFactory,
    currentKey: StorageEncryptionKey,
    records: ClientRecordCipher,
) : ClientStorage {
    private val database = KSecureMessageDatabase(driver)
    private val queries = database.clientStateQueries
    private val mutex = Mutex()

    // The keys and cipher change only by storage key rotation, while [mutex]
    // is held, right after the transaction that recorded the change.
    internal var currentKey: StorageEncryptionKey = currentKey
        private set
    internal var records: ClientRecordCipher = records
        private set
    private var view = DatabaseView(queries, records)

    override val identity: IdentityStore = object : IdentityStore {
        override suspend fun identity() = transaction { identity.identity() }
        override suspend fun store(identity: LocalIdentity) = transaction { this.identity.store(identity) }
    }

    override val deviceAuthentication: DeviceAuthenticationKeyStore = object : DeviceAuthenticationKeyStore {
        override suspend fun keyPair() = transaction { deviceAuthentication.keyPair() }
        override suspend fun store(keyPair: DeviceAuthenticationKeyPair) = transaction { deviceAuthentication.store(keyPair) }
        override suspend fun awaitsUpgradeKey() = transaction { deviceAuthentication.awaitsUpgradeKey() }
        override suspend fun pendingRecoveryKeyPair() = transaction { deviceAuthentication.pendingRecoveryKeyPair() }
        override suspend fun storePendingRecoveryKeyPair(keyPair: DeviceAuthenticationKeyPair) =
            transaction { deviceAuthentication.storePendingRecoveryKeyPair(keyPair) }
        override suspend fun removePendingRecoveryKeyPair() = transaction { deviceAuthentication.removePendingRecoveryKeyPair() }
        override suspend fun promotePendingRecoveryKeyPair() = transaction { deviceAuthentication.promotePendingRecoveryKeyPair() }
        override suspend fun pendingRotationKeyPair() = transaction { deviceAuthentication.pendingRotationKeyPair() }
        override suspend fun storePendingRotationKeyPair(keyPair: DeviceAuthenticationKeyPair) =
            transaction { deviceAuthentication.storePendingRotationKeyPair(keyPair) }
        override suspend fun removePendingRotationKeyPair() = transaction { deviceAuthentication.removePendingRotationKeyPair() }
        override suspend fun promotePendingRotationKeyPair() = transaction { deviceAuthentication.promotePendingRotationKeyPair() }
        override suspend fun pendingLastDeviceRecoveryKeyPair() = transaction { deviceAuthentication.pendingLastDeviceRecoveryKeyPair() }
        override suspend fun storePendingLastDeviceRecoveryKeyPair(keyPair: DeviceAuthenticationKeyPair) =
            transaction { deviceAuthentication.storePendingLastDeviceRecoveryKeyPair(keyPair) }
        override suspend fun removePendingLastDeviceRecoveryKeyPair() =
            transaction { deviceAuthentication.removePendingLastDeviceRecoveryKeyPair() }
        override suspend fun promotePendingLastDeviceRecoveryKeyPair() =
            transaction { deviceAuthentication.promotePendingLastDeviceRecoveryKeyPair() }
    }

    override val remoteIdentities: RemoteIdentityStore = object : RemoteIdentityStore {
        override suspend fun identityKey(address: DeviceAddress) = transaction { remoteIdentities.identityKey(address) }
        override suspend fun record(address: DeviceAddress) = transaction { remoteIdentities.record(address) }
        override suspend fun store(address: DeviceAddress, identityKey: ByteArray) =
            transaction { remoteIdentities.store(address, identityKey) }
        override suspend fun setVerification(address: DeviceAddress, identityKey: ByteArray, verification: VerificationState) =
            transaction { remoteIdentities.setVerification(address, identityKey, verification) }
        override suspend fun replace(address: DeviceAddress, expectedIdentityKey: ByteArray, newIdentityKey: ByteArray) =
            transaction { remoteIdentities.replace(address, expectedIdentityKey, newIdentityKey) }
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

    override val pendingOutbound: PendingOutboundStore = object : PendingOutboundStore {
        override suspend fun store(recipient: DeviceAddress, id: LogicalMessageId, frame: ByteArray) =
            transaction { pendingOutbound.store(recipient, id, frame) }
        override suspend fun get(recipient: DeviceAddress, id: LogicalMessageId) = transaction { pendingOutbound.get(recipient, id) }
        override suspend fun list(recipient: DeviceAddress) = transaction { pendingOutbound.list(recipient) }
        override suspend fun remove(recipient: DeviceAddress, id: LogicalMessageId) =
            transaction { pendingOutbound.remove(recipient, id) }
    }

    override val processedInbound: ProcessedInboundStore = object : ProcessedInboundStore {
        override suspend fun isProcessed(sender: DeviceAddress, id: LogicalMessageId) =
            transaction { processedInbound.isProcessed(sender, id) }
        override suspend fun markProcessed(sender: DeviceAddress, id: LogicalMessageId) =
            transaction { processedInbound.markProcessed(sender, id) }
    }

    override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T {
        val active = currentCoroutineContext()[ActiveTransaction]
        if (active != null && active.owner === this) return view.block()

        return mutex.withLock { lockedTransaction { view.block() } }
    }

    /** A database transaction; the caller holds [mutex]. */
    internal suspend fun <T> lockedTransaction(block: suspend () -> T): T =
        withContext(ActiveTransaction(this)) {
            database.transactionWithResult {
                checkKeyState()
                block()
            }
        }

    /**
     * Fails if the database's storage key state no longer matches this
     * instance, for example because another instance rotated the key: this
     * one must not seal records with a key that is being retired.
     */
    private suspend fun checkKeyState() {
        val state = queries.selectStorageEncryption().awaitAsOne()
        val expected = setOfNotNull(state.key_id, state.retiring_key_id.takeIf { state.rotation_phase == SqlDelightStorageKeyRotationBackend.PHASE_MIGRATING })
        if (state.key_id != currentKey.id.value.toLong() || records.openableKeyIds.map { it.value.toLong() }.toSet() != expected) {
            throw StorageEncryptionException.KeyUnavailable("The storage key changed since this storage was opened; open it again")
        }
    }

    private val rotation = StorageKeyRotationManager(SqlDelightStorageKeyRotationBackend(this, driver, queries), keyProvider)

    /**
     * The storage key rotation state (docs/storage-key-rotation.md). Key IDs
     * only.
     */
    suspend fun storageKeyRotationStatus(): StorageKeyRotationStatus = rotation.status()

    /**
     * Starts a storage key rotation and returns the new current key ID.
     *
     * Allocates the next key ID (committed first, so it is never reused),
     * has the [StorageKeyProvider] create and persist that key, reads it back,
     * and then makes it current in one transaction: from then on every new
     * record is sealed with it, while records of the previous key stay
     * readable. The previous key is re-encrypted away and retired by
     * [resumeStorageKeyRotation].
     *
     * If a start was interrupted ([StorageKeyRotationPhase.PREPARING]), this
     * finishes it with the key ID already allocated. Throws
     * [StorageKeyRotationInProgressException] while a rotation is migrating
     * or retiring; [StorageEncryptionException.KeyIdsExhausted] if no key ID
     * is left; [StorageEncryptionException.KeyUnavailable] if the provider
     * cannot create or return the key (the database then still uses its
     * current key). The state machine is [StorageKeyRotationManager].
     */
    suspend fun rotateStorageKey(): StorageKeyId = rotation.rotate()

    /**
     * Advances a storage key rotation by one step and returns the new status:
     *
     * - [StorageKeyRotationPhase.PREPARING]: finishes the start like [rotateStorageKey].
     * - [StorageKeyRotationPhase.MIGRATING]: re-encrypts up to [maxRecords] records of the
     *   retiring key with the current key, in one transaction. When none are
     *   left, proves by a scan of every sealed record that no record uses the
     *   retiring key, then retires it.
     * - [StorageKeyRotationPhase.RETIRING]: removes the retiring key from the provider (again)
     *   and ends the rotation.
     * - [StorageKeyRotationPhase.STABLE]: nothing to do.
     *
     * Call it until the phase is [StorageKeyRotationPhase.STABLE]. Every
     * committed step survives a crash or cancellation; a failed step rolls
     * back only itself. A record that does not open stops the migration: the
     * rotation stays in progress and the retiring key is kept.
     */
    suspend fun resumeStorageKeyRotation(maxRecords: Int = DEFAULT_ROTATION_BATCH): StorageKeyRotationStatus =
        rotation.resume(maxRecords)

    /** Runs a rotation step under [mutex]. Provider calls in it run outside any transaction. */
    internal suspend fun <T> rotationStep(block: suspend () -> T): T {
        val active = currentCoroutineContext()[ActiveTransaction]
        check(active == null || active.owner !== this) { "Storage key rotation cannot run inside a storage transaction" }
        return mutex.withLock { block() }
    }

    /** Switches to [cipher] after a committed rotation step; [current] seals new records. */
    internal fun useKeys(current: StorageEncryptionKey, cipher: ClientRecordCipher) {
        currentKey = current
        records = cipher
        view = DatabaseView(queries, cipher)
    }

    /** Marks the coroutine that runs a transaction, so nested calls join it. */
    private class ActiveTransaction(val owner: SqlDelightClientStorage) : CoroutineContext.Element {
        override val key: CoroutineContext.Key<*> get() = ActiveTransaction

        companion object : CoroutineContext.Key<ActiveTransaction>
    }

    companion object {
        /** Database schema, for creating the platform [SqlDriver]. */
        val Schema: SqlSchema<QueryResult.AsyncValue<Unit>> get() = KSecureMessageDatabase.Schema

        /** Records per [resumeStorageKeyRotation] call if not given. */
        const val DEFAULT_ROTATION_BATCH: Int = StorageKeyRotationManager.DEFAULT_BATCH_SIZE

        private const val FORMAT_LEGACY_PLAINTEXT = 0L
        private const val FORMAT_RECORD_ENCRYPTION_V1 = 1L

        /**
         * Opens the database behind [driver] with the storage key from
         * [keyProvider]. Fails closed with [StorageEncryptionException]:
         *
         * - The database has a bound key: [StorageKeyProvider.key] must
         *   return it (else [StorageEncryptionException.KeyUnavailable]) and
         *   it must be the right key (else
         *   [StorageEncryptionException.AuthenticationFailed]). No key is
         *   created. While a storage key rotation is migrating, the retiring
         *   key is required and checked the same way
         *   (docs/storage-key-rotation.md). Opening never advances or rolls
         *   back a rotation.
         * - A new database: [StorageKeyProvider.loadOrCreateKey] supplies the
         *   key, which is bound to the database.
         * - A database upgraded from schema version 5 or older still holds
         *   plaintext: the key comes from [StorageKeyProvider.loadOrCreateKey]
         *   and every sensitive record is encrypted in one transaction before
         *   this returns. If anything fails, the database stays as it was and
         *   the next open tries again.
         *
         * The provider is called outside any database transaction.
         */
        suspend fun open(driver: SqlDriver, keyProvider: StorageKeyProvider): SqlDelightClientStorage =
            open(driver, keyProvider) { current, retained -> ClientRecordCipher(current, *retained.toTypedArray()) }

        /** [open] with a replaceable record cipher, for failure injection in tests. */
        internal suspend fun open(
            driver: SqlDriver,
            keyProvider: StorageKeyProvider,
            cipherFactory: RecordCipherFactory,
        ): SqlDelightClientStorage {
            val database = KSecureMessageDatabase(driver)
            val queries = database.clientStateQueries
            val state = queries.selectStorageEncryption().awaitAsOne()
            val keyId = state.key_id
            return when {
                state.format == FORMAT_RECORD_ENCRYPTION_V1 && keyId != null -> {
                    val current = boundKey(keyProvider, storageKeyId(keyId), state.key_check, "Missing key check record")
                    val rotation = SqlDelightStorageKeyRotationBackend.rotationState(state)
                    // While MIGRATING the retiring key is needed too; RETIRING no longer needs it (it may be gone).
                    val retained = (rotation.requiredKeyIds - rotation.currentKeyId).singleOrNull()?.let {
                        boundKey(keyProvider, it, state.retiring_key_check, "Missing retiring key check record")
                    }
                    SqlDelightClientStorage(driver, keyProvider, cipherFactory, current, cipherFactory(current, listOfNotNull(retained)))
                }
                state.format == FORMAT_RECORD_ENCRYPTION_V1 -> {
                    val key = provide("No storage key could be provided") { keyProvider.loadOrCreateKey() }
                    val records = cipherFactory(key, emptyList())
                    val keyCheck = records.sealKeyCheck()
                    database.transaction {
                        val current = queries.selectStorageEncryption().awaitAsOne()
                        if (current.format != FORMAT_RECORD_ENCRYPTION_V1 || current.key_id != null) {
                            throw IllegalStateException("Storage encryption state changed while opening")
                        }
                        // Records exist only once a key is bound. Records without one mean
                        // a modified database; binding a key now could hide that.
                        if (queries.countSealedRecords().awaitAsOne() != 0L) {
                            throw StorageEncryptionException.KeyUnavailable("Storage has encrypted records but no bound storage key")
                        }
                        queries.bindStorageKey(key.id.value.toLong(), keyCheck)
                    }
                    SqlDelightClientStorage(driver, keyProvider, cipherFactory, key, records)
                }
                state.format == FORMAT_LEGACY_PLAINTEXT -> {
                    val key = provide("No storage key could be provided") { keyProvider.loadOrCreateKey() }
                    val records = cipherFactory(key, emptyList())
                    val keyCheck = records.sealKeyCheck()
                    database.transaction {
                        val current = queries.selectStorageEncryption().awaitAsOne()
                        if (current.format != FORMAT_LEGACY_PLAINTEXT) {
                            throw IllegalStateException("Storage encryption state changed while opening")
                        }
                        LegacyPlaintextMigration(driver, records).run()
                        driver.execute(null, "UPDATE storage_encryption SET format = ?, key_id = ?, key_check = ?, highest_key_id = ?", 4) {
                            bindLong(0, FORMAT_RECORD_ENCRYPTION_V1)
                            bindLong(1, records.keyId.value.toLong())
                            bindBytes(2, keyCheck)
                            bindLong(3, records.keyId.value.toLong())
                        }.await()
                    }
                    SqlDelightClientStorage(driver, keyProvider, cipherFactory, key, records)
                }
                else -> throw StorageEncryptionException.UnsupportedFormat("Unsupported storage encryption format ${state.format}")
            }
        }

        /** Key [id] from the provider, proven by its key check [sealedCheck]. */
        private suspend fun boundKey(
            keyProvider: StorageKeyProvider,
            id: StorageKeyId,
            sealedCheck: ByteArray?,
            missingCheck: String,
        ): StorageEncryptionKey {
            val key = provide("Storage key ${id.value} is not available") { keyProvider.key(id) }
            if (key.id != id) throw StorageEncryptionException.KeyUnavailable("Provider returned another storage key than ${id.value}")
            // A single-key cipher: the check must be sealed with exactly this key.
            ClientRecordCipher(key).verifyKeyCheck(sealedCheck ?: throw StorageEncryptionException.MalformedRecord(missingCheck))
            return key
        }

        private suspend fun provide(message: String, load: suspend () -> StorageEncryptionKey?): StorageEncryptionKey {
            val key = try {
                load()
            } catch (e: CancellationException) {
                throw e
            } catch (e: StorageEncryptionException) {
                throw e
            } catch (e: Exception) {
                throw StorageEncryptionException.KeyUnavailable(message, e)
            }
            return key ?: throw StorageEncryptionException.KeyUnavailable(message)
        }
    }
}

/** Creates the record cipher for a current key and the keys retained for reading. */
internal typealias RecordCipherFactory = (current: StorageEncryptionKey, retained: List<StorageEncryptionKey>) -> ClientRecordCipher

/** Store implementations. Only used inside a database transaction. */
private class DatabaseView(private val queries: ClientStateQueries, private val records: ClientRecordCipher) : ClientStorage {
    override val pendingOutbound: PendingOutboundStore = object : PendingOutboundStore {
        override suspend fun store(recipient: DeviceAddress, id: LogicalMessageId, frame: ByteArray): Long {
            require(
                queries.selectPendingOutbound(recipient.userId.value, recipient.deviceId.value, id.toByteArray()).awaitAsOneOrNull() == null,
            ) { "Message is already pending" }
            val sealed = records.sealPendingFrame(recipient, id, frame)
            queries.insertPendingOutbound(recipient.userId.value, recipient.deviceId.value, id.toByteArray(), sealed)
            return queries.selectPendingOutbound(recipient.userId.value, recipient.deviceId.value, id.toByteArray()).awaitAsOne().sequence
        }

        override suspend fun get(recipient: DeviceAddress, id: LogicalMessageId): PendingOutboundMessage? {
            val row = queries.selectPendingOutbound(recipient.userId.value, recipient.deviceId.value, id.toByteArray())
                .awaitAsOneOrNull() ?: return null
            return PendingOutboundMessage(recipient, id, row.sequence, records.openPendingFrame(recipient, id, row.sealed_frame))
        }

        override suspend fun list(recipient: DeviceAddress): List<PendingOutboundMessage> =
            queries.selectPendingOutboundFor(recipient.userId.value, recipient.deviceId.value).awaitAsList().map { row ->
                val id = LogicalMessageId.fromByteArray(row.message_id)
                PendingOutboundMessage(recipient, id, row.sequence, records.openPendingFrame(recipient, id, row.sealed_frame))
            }

        override suspend fun remove(recipient: DeviceAddress, id: LogicalMessageId): Boolean {
            // Existence only: an entry is removed without being opened.
            if (queries.selectPendingOutbound(recipient.userId.value, recipient.deviceId.value, id.toByteArray()).awaitAsOneOrNull() == null) {
                return false
            }
            queries.deletePendingOutbound(recipient.userId.value, recipient.deviceId.value, id.toByteArray())
            return true
        }
    }

    override val processedInbound: ProcessedInboundStore = object : ProcessedInboundStore {
        override suspend fun isProcessed(sender: DeviceAddress, id: LogicalMessageId): Boolean =
            queries.countProcessedInbound(sender.userId.value, sender.deviceId.value, id.toByteArray()).awaitAsOne() > 0

        override suspend fun markProcessed(sender: DeviceAddress, id: LogicalMessageId) {
            queries.insertProcessedInbound(sender.userId.value, sender.deviceId.value, id.toByteArray())
        }
    }

    override val identity: IdentityStore = object : IdentityStore {
        override suspend fun identity(): LocalIdentity? =
            queries.selectIdentity().awaitAsOneOrNull()?.let { records.openIdentity(it) }

        override suspend fun store(identity: LocalIdentity) {
            // Existence only: an identity that fails to open must not look absent.
            check(queries.selectIdentity().awaitAsOneOrNull() == null) { "A local identity is already stored" }
            queries.insertIdentity(records.sealIdentity(identity))
        }
    }

    override val deviceAuthentication: DeviceAuthenticationKeyStore = object : DeviceAuthenticationKeyStore {
        override suspend fun keyPair(): DeviceAuthenticationKeyPair? =
            queries.selectDeviceAuthenticationKey().awaitAsOneOrNull()?.let { records.openDeviceAuthenticationKey(it) }

        override suspend fun store(keyPair: DeviceAuthenticationKeyPair) {
            // Existence only: a key that fails to open must not look absent.
            check(queries.selectDeviceAuthenticationKey().awaitAsOneOrNull() == null) {
                "A device authentication key is already stored"
            }
            queries.insertDeviceAuthenticationKey(records.sealDeviceAuthenticationKey(keyPair))
            queries.clearDeviceAuthenticationAwaitsUpgradeKey()
        }

        override suspend fun awaitsUpgradeKey(): Boolean =
            queries.selectDeviceAuthenticationAwaitsUpgradeKey().awaitAsOne() != 0L

        override suspend fun pendingRecoveryKeyPair(): DeviceAuthenticationKeyPair? =
            queries.selectDeviceAuthenticationRecoveryKey().awaitAsOneOrNull()?.let { records.openDeviceAuthenticationRecoveryKey(it) }

        override suspend fun storePendingRecoveryKeyPair(keyPair: DeviceAuthenticationKeyPair) {
            // Existence only: a pending key that fails to open must not look absent.
            check(queries.selectDeviceAuthenticationRecoveryKey().awaitAsOneOrNull() == null) {
                "A pending recovery key is already stored"
            }
            check(queries.selectDeviceAuthenticationRotationKey().awaitAsOneOrNull() == null) {
                "A device authentication rotation is pending"
            }
            check(queries.selectDeviceAuthenticationLastDeviceRecoveryKey().awaitAsOneOrNull() == null) {
                "A last-device recovery is pending"
            }
            queries.insertDeviceAuthenticationRecoveryKey(records.sealDeviceAuthenticationRecoveryKey(keyPair))
        }

        override suspend fun removePendingRecoveryKeyPair() {
            queries.deleteDeviceAuthenticationRecoveryKey()
        }

        // Opens the pending record (a damaged one throws and changes nothing) and
        // reseals it as the active key: the record types differ, so the sealed
        // bytes cannot be moved as they are.
        override suspend fun promotePendingRecoveryKeyPair() {
            val sealed = checkNotNull(queries.selectDeviceAuthenticationRecoveryKey().awaitAsOneOrNull()) { "No pending recovery key" }
            val keyPair = records.openDeviceAuthenticationRecoveryKey(sealed)
            try {
                val active = records.sealDeviceAuthenticationKey(keyPair)
                queries.deleteDeviceAuthenticationKey()
                queries.insertDeviceAuthenticationKey(active)
                queries.deleteDeviceAuthenticationRecoveryKey()
                queries.clearDeviceAuthenticationAwaitsUpgradeKey()
            } finally {
                keyPair.privateKey.fill(0)
            }
        }

        override suspend fun pendingRotationKeyPair(): DeviceAuthenticationKeyPair? =
            queries.selectDeviceAuthenticationRotationKey().awaitAsOneOrNull()?.let { records.openDeviceAuthenticationRotationKey(it) }

        override suspend fun storePendingRotationKeyPair(keyPair: DeviceAuthenticationKeyPair) {
            // Existence only: a pending key that fails to open must not look absent.
            check(queries.selectDeviceAuthenticationRotationKey().awaitAsOneOrNull() == null) {
                "A pending rotation key is already stored"
            }
            check(queries.selectDeviceAuthenticationRecoveryKey().awaitAsOneOrNull() == null) {
                "A device recovery is pending"
            }
            check(queries.selectDeviceAuthenticationLastDeviceRecoveryKey().awaitAsOneOrNull() == null) {
                "A last-device recovery is pending"
            }
            queries.insertDeviceAuthenticationRotationKey(records.sealDeviceAuthenticationRotationKey(keyPair))
        }

        override suspend fun removePendingRotationKeyPair() {
            queries.deleteDeviceAuthenticationRotationKey()
        }

        // Like the recovery promotion: open (a damaged record throws and changes
        // nothing), reseal as the active key, all in the caller's transaction.
        override suspend fun promotePendingRotationKeyPair() {
            val sealed = checkNotNull(queries.selectDeviceAuthenticationRotationKey().awaitAsOneOrNull()) { "No pending rotation key" }
            val keyPair = records.openDeviceAuthenticationRotationKey(sealed)
            try {
                val active = records.sealDeviceAuthenticationKey(keyPair)
                queries.deleteDeviceAuthenticationKey()
                queries.insertDeviceAuthenticationKey(active)
                queries.deleteDeviceAuthenticationRotationKey()
                queries.clearDeviceAuthenticationAwaitsUpgradeKey()
            } finally {
                keyPair.privateKey.fill(0)
            }
        }

        override suspend fun pendingLastDeviceRecoveryKeyPair(): DeviceAuthenticationKeyPair? =
            queries.selectDeviceAuthenticationLastDeviceRecoveryKey().awaitAsOneOrNull()
                ?.let { records.openDeviceAuthenticationLastDeviceRecoveryKey(it) }

        override suspend fun storePendingLastDeviceRecoveryKeyPair(keyPair: DeviceAuthenticationKeyPair) {
            // Existence only: a pending key that fails to open must not look absent.
            check(queries.selectDeviceAuthenticationLastDeviceRecoveryKey().awaitAsOneOrNull() == null) {
                "A pending last-device recovery key is already stored"
            }
            check(queries.selectDeviceAuthenticationRecoveryKey().awaitAsOneOrNull() == null) {
                "A device recovery is pending"
            }
            check(queries.selectDeviceAuthenticationRotationKey().awaitAsOneOrNull() == null) {
                "A device authentication rotation is pending"
            }
            queries.insertDeviceAuthenticationLastDeviceRecoveryKey(records.sealDeviceAuthenticationLastDeviceRecoveryKey(keyPair))
        }

        override suspend fun removePendingLastDeviceRecoveryKeyPair() {
            queries.deleteDeviceAuthenticationLastDeviceRecoveryKey()
        }

        // Like the other promotions: open (a damaged record throws and changes
        // nothing), reseal as the active key, all in the caller's transaction.
        override suspend fun promotePendingLastDeviceRecoveryKeyPair() {
            val sealed = checkNotNull(queries.selectDeviceAuthenticationLastDeviceRecoveryKey().awaitAsOneOrNull()) {
                "No pending last-device recovery key"
            }
            val keyPair = records.openDeviceAuthenticationLastDeviceRecoveryKey(sealed)
            try {
                val active = records.sealDeviceAuthenticationKey(keyPair)
                queries.deleteDeviceAuthenticationKey()
                queries.insertDeviceAuthenticationKey(active)
                queries.deleteDeviceAuthenticationLastDeviceRecoveryKey()
                queries.clearDeviceAuthenticationAwaitsUpgradeKey()
            } finally {
                keyPair.privateKey.fill(0)
            }
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

        override suspend fun record(address: DeviceAddress): RemoteIdentityRecord? =
            queries.selectRemoteIdentityRecord(address.userId.value, address.deviceId.value).awaitAsOneOrNull()
                ?.let { RemoteIdentityRecord(it.identity_key, verificationState(it.verification)) }

        override suspend fun setVerification(address: DeviceAddress, identityKey: ByteArray, verification: VerificationState) {
            val pinned = checkNotNull(identityKey(address)) { "No remote identity is pinned" }
            check(pinned.contentEquals(identityKey)) { "Another remote identity is pinned" }
            queries.updateRemoteIdentityVerification(verificationCode(verification), address.userId.value, address.deviceId.value, pinned)
        }

        override suspend fun replace(address: DeviceAddress, expectedIdentityKey: ByteArray, newIdentityKey: ByteArray) {
            require(!expectedIdentityKey.contentEquals(newIdentityKey)) { "The new identity key is the pinned one" }
            val pinned = checkNotNull(identityKey(address)) { "No remote identity is pinned" }
            check(pinned.contentEquals(expectedIdentityKey)) { "Another remote identity is pinned" }
            queries.replaceRemoteIdentity(newIdentityKey.copyOf(), address.userId.value, address.deviceId.value, pinned)
        }
    }

    override val sessions: SessionStore = object : SessionStore {
        override suspend fun load(address: DeviceAddress): SecureSession? =
            queries.selectSession(address.userId.value, address.deviceId.value).awaitAsOneOrNull()
                ?.let { records.openSession(address, it) }

        override suspend fun store(session: SecureSession) {
            queries.upsertSession(session.remote.userId.value, session.remote.deviceId.value, records.sealSession(session))
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
            queries.selectSignedPreKey(id.value.toLong()).awaitAsOneOrNull()?.let { records.openSignedPreKey(id, it) }

        override suspend fun currentSignedPreKey(): SignedPreKeyPair? =
            state().current_signed_pre_key_id?.let {
                val id = SignedPreKeyId(it.toInt())
                records.openSignedPreKey(id, queries.selectSignedPreKey(it).awaitAsOne())
            }

        override suspend fun storeCurrentSignedPreKey(preKey: SignedPreKeyPair, createdAt: Instant) {
            require(preKey.id.value > (highestSignedPreKeyId()?.value ?: -1)) { "Signed prekey ID already used" }
            val id = preKey.id.value.toLong()
            val millis = createdAt.toEpochMilliseconds()
            queries.insertSignedPreKey(id, records.sealSignedPreKey(preKey), millis)
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
            queries.selectOneTimePreKey(id.value.toLong()).awaitAsOneOrNull()?.let { records.openOneTimePreKey(id, it) }

        // Public keys are inside the sealed records too, so publishing reads and authenticates every record.
        override suspend fun publicOneTimePreKeys(): List<PublicOneTimePreKey> =
            queries.selectOneTimePreKeys().awaitAsList().map { row ->
                records.openOneTimePreKey(OneTimePreKeyId(row.id.toInt()), row.sealed_key_pair).toPublic()
            }

        override suspend fun oneTimePreKeyCount(): Int = queries.countOneTimePreKeys().awaitAsOne().toInt()

        override suspend fun storeOneTimePreKeys(preKeys: List<OneTimePreKeyPair>) {
            if (preKeys.isEmpty()) return
            val ids = preKeys.map { it.id.value }
            require(ids.toSet().size == ids.size) { "Duplicate one-time prekey ID" }
            val highest = highestOneTimePreKeyId()?.value ?: -1
            require(ids.all { it > highest }) { "One-time prekey ID already used" }
            for (preKey in preKeys) {
                queries.insertOneTimePreKey(preKey.id.value.toLong(), records.sealOneTimePreKey(preKey))
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

// Stored codes of remote_identity.verification (schema version 10, 9.sqm).
private const val UNVERIFIED_CODE = 0L
private const val VERIFIED_CODE = 1L

private fun verificationCode(state: VerificationState): Long = when (state) {
    VerificationState.UNVERIFIED -> UNVERIFIED_CODE
    VerificationState.VERIFIED -> VERIFIED_CODE
}

/** Fails closed: an unknown code is never read as verified. */
private fun verificationState(code: Long): VerificationState = when (code) {
    UNVERIFIED_CODE -> VerificationState.UNVERIFIED
    VERIFIED_CODE -> VerificationState.VERIFIED
    else -> throw IllegalStateException("Unknown remote identity verification state")
}
