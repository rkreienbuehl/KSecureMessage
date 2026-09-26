package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.storage.AuthenticationNonceRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationState
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacement
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.server.sqldelight.db.ServerDatabase
import dev.kreienbuehl.ksecuremessage.storage.server.sqldelight.db.ServerStateQueries
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Instant

/**
 * Persistent [ServerStorage] on SQLite through SQLDelight
 * (docs/server-storage.md).
 *
 * The host application creates, configures and owns the [SqlDriver]: it
 * chooses the database location, driver and connection settings, creates the
 * schema with [Schema] (for example `JdbcSqliteDriver(url, properties, Schema)`,
 * or `Schema.create(driver)` itself), and closes the driver on shutdown. This
 * class never creates, configures or closes a driver.
 *
 * Only SQLite-compatible, synchronous drivers are supported: the schema and
 * queries use the SQLite dialect. That the [SqlDriver] is configurable does
 * not mean arbitrary SQL databases are supported.
 *
 * Every repository call is one database transaction: if it throws, SQLite
 * rolls back all of its writes. Calls of one instance are serialized by a
 * [Mutex] and run on [dispatcher], because the drivers block and bind a
 * transaction to its thread. Use one instance per database, in one process;
 * uniqueness is additionally enforced by the schema's primary keys.
 *
 * The database holds public registration keys, public prekeys, opaque
 * encrypted envelopes with their routing metadata and nonce replay
 * metadata. It is not encrypted. Timestamps are stored as epoch
 * milliseconds.
 */
class SqlDelightServerStorage private constructor(
    driver: SqlDriver,
    private val dispatcher: CoroutineDispatcher,
) : ServerStorage {
    private val database = ServerDatabase(driver)
    private val queries = database.serverStateQueries
    private val mutex = Mutex()

    override val preKeys: PreKeyRepository = SqlDelightPreKeyRepository()

    override val mailboxes: MailboxRepository = SqlDelightMailboxRepository()

    override val devices: DeviceRegistrationRepository = SqlDelightDeviceRegistrationRepository()

    override val authenticationNonces: AuthenticationNonceRepository = SqlDelightAuthenticationNonceRepository()

    /** Runs [block] as one database transaction, serialized with every other call of this instance. */
    private suspend fun <T> transaction(block: ServerStateQueries.() -> T): T = mutex.withLock {
        withContext(dispatcher) {
            database.transactionWithResult { queries.block() }
        }
    }

    private inner class SqlDelightDeviceRegistrationRepository : DeviceRegistrationRepository {
        override suspend fun registration(address: DeviceAddress): DeviceRegistration? = transaction {
            selectRegistration(address.user, address.device).executeAsOneOrNull()?.let { DeviceRegistration(address, it) }
        }

        // INSERT OR IGNORE never overwrites: the primary key decides which key is stored.
        override suspend fun register(registration: DeviceRegistration): Boolean = transaction {
            val address = registration.address
            val publicKey = registration.publicKey
            if (insertRegistration(address.user, address.device, publicKey).value == 1L) return@transaction true
            val existing = selectRegistration(address.user, address.device).executeAsOne()
            if (!existing.contentEquals(publicKey)) throw DeviceRegistrationException.Conflict()
            false
        }

        override suspend fun registrationState(address: DeviceAddress): DeviceRegistrationState? = transaction {
            loadState(address)
        }

        // Checks, nonce claim and the guarded UPDATE in one transaction. The
        // UPDATE's WHERE clause repeats the key and epoch check, so only one
        // of two replacements (recoveries or rotations) verified against the
        // same state can change the row.
        override suspend fun replaceForRecovery(replacement: RecoveryReplacement): RecoveryReplacementResult {
            val target = replacement.target
            val newKey = replacement.replacementPublicKey
            return transaction {
                val current = loadState(target) ?: return@transaction RecoveryReplacementResult.TARGET_NOT_REGISTERED
                if (current.recoveryId == replacement.recoveryId) return@transaction RecoveryReplacementResult.ALREADY_APPLIED
                val authorizer = loadState(replacement.expectedAuthorizer.address)
                if (!current.matches(replacement.expectedTarget) ||
                    authorizer == null || !authorizer.matches(replacement.expectedAuthorizer) ||
                    current.registration.publicKey.contentEquals(newKey)
                ) {
                    return@transaction RecoveryReplacementResult.CONFLICT
                }
                when (
                    replaceKey(
                        current, newKey, replacement.nonce, replacement.timestamp, replacement.pruneBefore,
                        recoveryId = replacement.recoveryId, rotationId = null,
                    )
                ) {
                    KeyReplacement.REPLACED -> RecoveryReplacementResult.REPLACED
                    KeyReplacement.REPLAY -> RecoveryReplacementResult.REPLAY
                    KeyReplacement.EPOCH_EXHAUSTED -> RecoveryReplacementResult.EPOCH_EXHAUSTED
                }
            }
        }

        override suspend fun replaceForRotation(replacement: RotationReplacement): RotationReplacementResult {
            val newKey = replacement.replacementPublicKey
            return transaction {
                val current = loadState(replacement.address) ?: return@transaction RotationReplacementResult.NOT_REGISTERED
                if (current.rotationId == replacement.rotationId) return@transaction RotationReplacementResult.ALREADY_APPLIED
                if (!current.matches(replacement.expected) || current.registration.publicKey.contentEquals(newKey)) {
                    return@transaction RotationReplacementResult.CONFLICT
                }
                when (
                    replaceKey(
                        current, newKey, replacement.nonce, replacement.timestamp, replacement.pruneBefore,
                        recoveryId = null, rotationId = replacement.rotationId,
                    )
                ) {
                    KeyReplacement.REPLACED -> RotationReplacementResult.REPLACED
                    KeyReplacement.REPLAY -> RotationReplacementResult.REPLAY
                    KeyReplacement.EPOCH_EXHAUSTED -> RotationReplacementResult.EPOCH_EXHAUSTED
                }
            }
        }

        /**
         * The compare-and-set shared by recovery and rotation, inside their
         * transaction after their own idempotency and expected-state checks:
         * epoch exhaustion, nonce prune + claim under the device, then the
         * guarded UPDATE with exactly one transition ID.
         */
        private fun ServerStateQueries.replaceKey(
            current: DeviceRegistrationState,
            newKey: ByteArray,
            nonce: RequestNonce,
            timestamp: Instant,
            pruneBefore: Instant,
            recoveryId: DeviceRecoveryId?,
            rotationId: DeviceAuthenticationRotationId?,
        ): KeyReplacement {
            val address = current.address
            // Never let SQLite turn auth_epoch + 1 into a REAL: epochs do not wrap.
            if (current.authEpoch == Long.MAX_VALUE) return KeyReplacement.EPOCH_EXHAUSTED
            pruneNonces(pruneBefore.toEpochMilliseconds())
            if (insertNonce(address.user, address.device, nonce.bytes, timestamp.toEpochMilliseconds()).value != 1L) {
                return KeyReplacement.REPLAY
            }
            val updated = replaceRegistrationKey(
                replacement = newKey,
                recovery_id = recoveryId?.bytes,
                rotation_id = rotationId?.bytes,
                user_id = address.user,
                device_id = address.device,
                expected_key = current.registration.publicKey,
                expected_epoch = current.authEpoch,
            ).value
            // Cannot happen after the checks above in this transaction; never commit a half replacement.
            check(updated == 1L) { "Registration changed during key replacement" }
            return KeyReplacement.REPLACED
        }

        private fun ServerStateQueries.loadState(address: DeviceAddress): DeviceRegistrationState? =
            selectRegistrationState(address.user, address.device).executeAsOneOrNull()?.let {
                DeviceRegistrationState(
                    DeviceRegistration(address, it.auth_public_key),
                    it.auth_epoch,
                    it.recovery_id?.let(::DeviceRecoveryId),
                    it.rotation_id?.let(::DeviceAuthenticationRotationId),
                )
            }

        private fun DeviceRegistrationState.matches(expected: DeviceRegistrationState) =
            authEpoch == expected.authEpoch && registration.publicKey.contentEquals(expected.registration.publicKey)
    }

    /**
     * Pruning and the claim run in one transaction. The claim is never
     * combined with the protected operation that follows it: a claimed nonce
     * stays claimed even if that operation fails (docs/server-authentication.md).
     */
    private inner class SqlDelightAuthenticationNonceRepository : AuthenticationNonceRepository {
        override suspend fun claim(address: DeviceAddress, nonce: ByteArray, timestamp: Instant, pruneBefore: Instant): Boolean {
            val bytes = nonce.copyOf()
            return transaction {
                pruneNonces(pruneBefore.toEpochMilliseconds())
                insertNonce(address.user, address.device, bytes, timestamp.toEpochMilliseconds()).value == 1L
            }
        }
    }

    private inner class SqlDelightMailboxRepository : MailboxRepository {
        // Returns after the commit, so a relay is acknowledged only once the envelope is stored.
        override suspend fun enqueue(envelope: EncryptedEnvelope) {
            val payload = envelope.payload.copyOf()
            transaction {
                insertMessage(
                    sender_user_id = envelope.sender.user,
                    sender_device_id = envelope.sender.device,
                    recipient_user_id = envelope.recipient.user,
                    recipient_device_id = envelope.recipient.device,
                    envelope_id = envelope.id.value,
                    protocol_version = envelope.protocolVersion.toLong(),
                    payload = payload,
                )
            }
        }

        // Selects and deletes in the same transaction. Sequences only grow, so
        // "up to the highest selected" deletes exactly the selected rows.
        override suspend fun drain(recipient: DeviceAddress): List<EncryptedEnvelope> = transaction {
            val rows = selectMessages(recipient.user, recipient.device).executeAsList()
            if (rows.isNotEmpty()) deleteMessagesUpTo(recipient.user, recipient.device, rows.last().sequence)
            rows.map {
                EncryptedEnvelope(
                    id = MessageId(it.envelope_id),
                    sender = DeviceAddress(UserId(it.sender_user_id), DeviceId(it.sender_device_id)),
                    recipient = DeviceAddress(UserId(it.recipient_user_id), DeviceId(it.recipient_device_id)),
                    protocolVersion = it.protocol_version.toInt(),
                    payload = it.payload.copyOf(),
                )
            }
        }
    }

    private inner class SqlDelightPreKeyRepository : PreKeyRepository {
        override suspend fun publish(publication: PreKeyPublication) {
            val ids = publication.oneTimePreKeys.map { it.id }
            if (ids.toSet().size != ids.size) {
                throw PreKeyPublicationException.InvalidPublication("Duplicate one-time prekey ID")
            }
            val address = publication.address
            val signedPreKey = publication.signedPreKey.deepCopy()
            val identityKey = publication.identityKey.copyOf()
            val oneTimePreKeys = publication.oneTimePreKeys.map { PublicOneTimePreKey(it.id, it.publicKey.copyOf()) }
            // One transaction: any conflict below rolls back the signed prekey too.
            transaction {
                val existing = selectPreKeyState(address.user, address.device).executeAsOneOrNull()
                if (existing == null) {
                    insertPreKeyState(
                        address.user, address.device, identityKey,
                        signedPreKey.id.value.toLong(), signedPreKey.publicKey, signedPreKey.signature,
                    )
                } else {
                    if (!existing.identity_key.contentEquals(identityKey)) throw PreKeyPublicationException.IdentityKeyConflict()
                    val current = PublicSignedPreKey(
                        SignedPreKeyId(existing.signed_pre_key_id.toInt()),
                        existing.signed_pre_key,
                        existing.signed_pre_key_signature,
                    )
                    checkSignedPreKey(current, signedPreKey)
                    if (signedPreKey.id != current.id) {
                        updateSignedPreKey(
                            signedPreKey.id.value.toLong(), signedPreKey.publicKey, signedPreKey.signature,
                            address.user, address.device,
                        )
                    }
                }
                for (preKey in oneTimePreKeys) {
                    val id = preKey.id.value.toLong()
                    if (isConsumed(address.user, address.device, id).executeAsOne() > 0) continue
                    val stored = selectOneTimePreKey(address.user, address.device, id).executeAsOneOrNull()
                    when {
                        stored == null -> insertOneTimePreKey(address.user, address.device, id, preKey.publicKey)
                        !stored.contentEquals(preKey.publicKey) -> throw PreKeyPublicationException.OneTimePreKeyConflict(preKey.id)
                    }
                }
            }
        }

        private fun checkSignedPreKey(current: PublicSignedPreKey, published: PublicSignedPreKey) {
            when {
                published.id.value < current.id.value ->
                    throw PreKeyPublicationException.SignedPreKeyConflict("Signed prekey is older than the current one")
                published.id == current.id && (
                    !published.publicKey.contentEquals(current.publicKey) ||
                        !published.signature.contentEquals(current.signature)
                    ) ->
                    throw PreKeyPublicationException.SignedPreKeyConflict("Signed prekey ID already exists with other bytes")
            }
        }

        // Hand-out, removal and tombstone in one transaction: no two callers get the same one-time prekey.
        override suspend fun consumePreKeyBundle(address: DeviceAddress): PreKeyBundle? = transaction {
            val state = selectPreKeyState(address.user, address.device).executeAsOneOrNull() ?: return@transaction null
            val oneTimePreKey = selectLowestOneTimePreKey(address.user, address.device).executeAsOneOrNull()
            if (oneTimePreKey != null) {
                deleteOneTimePreKey(address.user, address.device, oneTimePreKey.pre_key_id)
                insertConsumed(address.user, address.device, oneTimePreKey.pre_key_id)
            }
            PreKeyBundle(
                address = address,
                identityKey = state.identity_key.copyOf(),
                signedPreKey = PublicSignedPreKey(
                    SignedPreKeyId(state.signed_pre_key_id.toInt()),
                    state.signed_pre_key.copyOf(),
                    state.signed_pre_key_signature.copyOf(),
                ),
                oneTimePreKey = oneTimePreKey?.let {
                    PublicOneTimePreKey(OneTimePreKeyId(it.pre_key_id.toInt()), it.public_key.copyOf())
                },
            )
        }

        override suspend fun oneTimePreKeyCount(address: DeviceAddress): Int =
            transaction { countOneTimePreKeys(address.user, address.device).executeAsOne().toInt() }
    }

    companion object {
        /**
         * Server database schema, version 3. Independent of the client
         * schema. `Schema.migrate(driver, 1, 3)` migrates a milestone 13
         * database, `Schema.migrate(driver, 2, 3)` a milestone 14/15 one
         * (docs/server-storage.md).
         */
        val Schema: SqlSchema<QueryResult.Value<Unit>> get() = ServerDatabase.Schema

        private const val FORMAT_V1 = 1L
        private const val FORMAT_V2 = 2L
        private const val FORMAT_V3 = 3L

        /**
         * Opens the server storage on [driver], whose database must already
         * have the current schema ([Schema]). Creates and migrates nothing
         * and never closes [driver]: the caller keeps owning it. Throws
         * [IllegalStateException] if the database was not created with this
         * schema, or is still at schema version 1 or 2 (migrate it with
         * [Schema] first). Blocking database calls run on [dispatcher].
         */
        suspend fun open(driver: SqlDriver, dispatcher: CoroutineDispatcher = Dispatchers.IO): SqlDelightServerStorage {
            val format = withContext(dispatcher) {
                try {
                    ServerDatabase(driver).serverStateQueries.selectFormat().executeAsOneOrNull()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    // The SQL error (missing table) stays out of the message.
                    throw IllegalStateException("Database has no server storage schema")
                }
            }
            check(format != FORMAT_V1) { "Database has server storage schema version 1; migrate it with SqlDelightServerStorage.Schema" }
            check(format != FORMAT_V2) { "Database has server storage schema version 2; migrate it with SqlDelightServerStorage.Schema" }
            check(format == FORMAT_V3) { "Database has no supported server storage schema" }
            return SqlDelightServerStorage(driver, dispatcher)
        }
    }
}

private enum class KeyReplacement { REPLACED, REPLAY, EPOCH_EXHAUSTED }

private val DeviceAddress.user get() = userId.value
private val DeviceAddress.device get() = deviceId.value

// Not named copy(): the data class member would win and copy shallowly.
private fun PublicSignedPreKey.deepCopy() = PublicSignedPreKey(id, publicKey.copyOf(), signature.copyOf())
