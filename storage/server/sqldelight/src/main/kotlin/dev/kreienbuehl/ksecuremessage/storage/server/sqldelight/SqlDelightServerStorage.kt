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
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.storage.AuthenticationNonceRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationState
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeIssue
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeRequest
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryKeyException
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryRepository
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacement
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.StoredLastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.storage.server.sqldelight.db.ServerDatabase
import dev.kreienbuehl.ksecuremessage.storage.server.sqldelight.db.ServerStateQueries
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Clock
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
 * The database holds public registration keys, public last-device recovery
 * keys and challenges, public prekeys, opaque encrypted envelopes with their
 * routing metadata and nonce replay metadata. It is not encrypted. Timestamps are stored as epoch
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

    override val lastDeviceRecovery: LastDeviceRecoveryRepository = SqlDelightLastDeviceRecoveryRepository()

    /** Runs [block] as one database transaction, serialized with every other call of this instance. */
    private suspend fun <T> transaction(block: ServerStateQueries.() -> T): T = mutex.withLock {
        withContext(dispatcher) {
            database.transactionWithResult { queries.block() }
        }
    }

    /** Gives migrated registrations without a key installation time [clock]'s time, in one transaction. */
    private suspend fun stampMissingInstallationTimes(clock: Clock) {
        transaction { stampMissingInstalledAt(clock.now().toEpochMilliseconds()) }
    }

    private inner class SqlDelightDeviceRegistrationRepository : DeviceRegistrationRepository {
        override suspend fun registration(address: DeviceAddress): DeviceRegistration? = transaction {
            selectRegistration(address.user, address.device).executeAsOneOrNull()?.let { DeviceRegistration(address, it) }
        }

        // INSERT OR IGNORE never overwrites: the primary key decides which key
        // is stored, and a retry keeps the stored installation time.
        override suspend fun register(registration: DeviceRegistration, installedAt: Instant): Boolean = transaction {
            val address = registration.address
            val publicKey = registration.publicKey
            if (insertRegistration(address.user, address.device, publicKey, installedAt.toEpochMilliseconds()).value == 1L) {
                return@transaction true
            }
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
                        current, newKey, replacement.installedAt,
                        recoveryId = replacement.recoveryId, rotationId = null, lastDeviceRecoveryId = null,
                    ) { claimNonce(target, replacement.nonce.bytes, replacement.timestamp, replacement.pruneBefore) }
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
                        current, newKey, replacement.installedAt,
                        recoveryId = null, rotationId = replacement.rotationId, lastDeviceRecoveryId = null,
                    ) { claimNonce(replacement.address, replacement.nonce.bytes, replacement.timestamp, replacement.pruneBefore) }
                ) {
                    KeyReplacement.REPLACED -> RotationReplacementResult.REPLACED
                    KeyReplacement.REPLAY -> RotationReplacementResult.REPLAY
                    KeyReplacement.EPOCH_EXHAUSTED -> RotationReplacementResult.EPOCH_EXHAUSTED
                }
            }
        }

        // Checks, challenge consumption and the guarded UPDATE in one
        // transaction. The challenge row carries the key and epoch it was
        // issued for; the UPDATE repeats the key and epoch check, so of
        // transitions verified against the same state only one changes the row.
        override suspend fun replaceForLastDeviceRecovery(
            replacement: LastDeviceRecoveryReplacement,
        ): LastDeviceRecoveryReplacementResult {
            val target = replacement.target
            val newKey = replacement.replacementPublicKey
            val recoveryKey = replacement.expectedRecoveryPublicKey
            val challengeNonce = replacement.challengeNonce
            val now = replacement.now.toEpochMilliseconds()
            return transaction {
                val current = loadState(target) ?: return@transaction LastDeviceRecoveryReplacementResult.NOT_REGISTERED
                if (current.lastDeviceRecoveryId == replacement.recoveryId) {
                    return@transaction LastDeviceRecoveryReplacementResult.ALREADY_APPLIED
                }
                val registeredRecoveryKey = selectRecoveryKey(target.user).executeAsOneOrNull()
                if (registeredRecoveryKey == null || !registeredRecoveryKey.contentEquals(recoveryKey)) {
                    return@transaction LastDeviceRecoveryReplacementResult.NOT_CONFIGURED
                }
                val stored = selectChallenge(target.user, target.device).executeAsOneOrNull()
                val result = when {
                    stored == null || !stored.challenge_id.contentEquals(replacement.challengeId.bytes) ||
                        !stored.challenge_nonce.contentEquals(challengeNonce) ->
                        LastDeviceRecoveryReplacementResult.CHALLENGE_INVALID
                    stored.expires_at < now -> LastDeviceRecoveryReplacementResult.EXPIRED
                    else -> null
                }
                pruneChallenges(now)
                if (result != null) return@transaction result
                checkNotNull(stored)
                if (!current.matches(replacement.expected) ||
                    stored.auth_epoch != current.authEpoch || !stored.auth_public_key.contentEquals(current.registration.publicKey) ||
                    current.registration.publicKey.contentEquals(newKey)
                ) {
                    return@transaction LastDeviceRecoveryReplacementResult.CONFLICT
                }
                when (
                    replaceKey(
                        current, newKey, replacement.now,
                        recoveryId = null, rotationId = null, lastDeviceRecoveryId = replacement.recoveryId,
                    ) {
                        deleteChallenge(target.user, target.device)
                        true
                    }
                ) {
                    KeyReplacement.REPLACED -> LastDeviceRecoveryReplacementResult.REPLACED
                    KeyReplacement.REPLAY -> error("A challenge consumption never replays")
                    KeyReplacement.EPOCH_EXHAUSTED -> LastDeviceRecoveryReplacementResult.EPOCH_EXHAUSTED
                }
            }
        }

        private fun ServerStateQueries.claimNonce(address: DeviceAddress, nonce: ByteArray, timestamp: Instant, pruneBefore: Instant): Boolean {
            pruneNonces(pruneBefore.toEpochMilliseconds())
            return insertNonce(address.user, address.device, nonce, timestamp.toEpochMilliseconds()).value == 1L
        }

        /**
         * The compare-and-set shared by recovery, rotation and last-device
         * recovery, inside their transaction after their own idempotency and
         * expected-state checks: epoch exhaustion, [claim] (nonce prune +
         * claim under the device, or the challenge consumption; `false` =
         * replay), then the guarded UPDATE with exactly one transition ID and
         * [installedAt].
         */
        private fun ServerStateQueries.replaceKey(
            current: DeviceRegistrationState,
            newKey: ByteArray,
            installedAt: Instant,
            recoveryId: DeviceRecoveryId?,
            rotationId: DeviceAuthenticationRotationId?,
            lastDeviceRecoveryId: LastDeviceRecoveryId?,
            claim: ServerStateQueries.() -> Boolean,
        ): KeyReplacement {
            val address = current.address
            // Never let SQLite turn auth_epoch + 1 into a REAL: epochs do not wrap.
            if (current.authEpoch == Long.MAX_VALUE) return KeyReplacement.EPOCH_EXHAUSTED
            if (!claim()) return KeyReplacement.REPLAY
            val updated = replaceRegistrationKey(
                replacement = newKey,
                recovery_id = recoveryId?.bytes,
                rotation_id = rotationId?.bytes,
                last_device_recovery_id = lastDeviceRecoveryId?.bytes,
                installed_at = installedAt.toEpochMilliseconds(),
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
                // open() stamped every migrated registration; a missing time is damage, never "now".
                val installedAt = checkNotNull(it.auth_key_installed_at) { "Registration has no key installation time" }
                DeviceRegistrationState(
                    DeviceRegistration(address, it.auth_public_key),
                    it.auth_epoch,
                    Instant.fromEpochMilliseconds(installedAt),
                    it.recovery_id?.let(::DeviceRecoveryId),
                    it.rotation_id?.let(::DeviceAuthenticationRotationId),
                    it.last_device_recovery_id?.let(::LastDeviceRecoveryId),
                )
            }

        private fun DeviceRegistrationState.matches(expected: DeviceRegistrationState) =
            authEpoch == expected.authEpoch && registration.publicKey.contentEquals(expected.registration.publicKey)
    }

    private inner class SqlDelightLastDeviceRecoveryRepository : LastDeviceRecoveryRepository {
        override suspend fun recoveryKey(userId: UserId): ByteArray? =
            transaction { selectRecoveryKey(userId.value).executeAsOneOrNull() }

        // A plain INSERT after the lookup, in one transaction: an existing key
        // is never overwritten, and the primary key rejects a second row.
        override suspend fun registerRecoveryKey(userId: UserId, publicKey: ByteArray, registeredAt: Instant): Boolean {
            require(publicKey.size == LastDeviceRecovery.PUBLIC_KEY_SIZE) { "Recovery public key has an invalid size" }
            val key = publicKey.copyOf()
            return transaction {
                val existing = selectRecoveryKey(userId.value).executeAsOneOrNull()
                when {
                    existing == null -> {
                        insertRecoveryKey(userId.value, key, registeredAt.toEpochMilliseconds())
                        true
                    }
                    existing.contentEquals(key) -> false
                    else -> throw LastDeviceRecoveryKeyException.Conflict()
                }
            }
        }

        override suspend fun issueChallenge(request: LastDeviceRecoveryChallengeRequest): LastDeviceRecoveryChallengeIssue {
            val target = request.target
            val nonce = request.candidateNonce
            val now = request.now.toEpochMilliseconds()
            return transaction {
                pruneChallenges(now)
                val registration = selectRegistrationState(target.user, target.device).executeAsOneOrNull()
                    ?: return@transaction LastDeviceRecoveryChallengeIssue.NotRegistered
                selectRecoveryKey(target.user).executeAsOneOrNull() ?: return@transaction LastDeviceRecoveryChallengeIssue.NotConfigured
                val existing = selectChallenge(target.user, target.device).executeAsOneOrNull()
                if (existing != null && existing.auth_epoch == registration.auth_epoch &&
                    existing.auth_public_key.contentEquals(registration.auth_public_key)
                ) {
                    return@transaction LastDeviceRecoveryChallengeIssue.Issued(
                        stored(target, existing.challenge_id, existing.challenge_nonce, existing.auth_epoch, existing.expires_at, existing.auth_public_key),
                    )
                }
                deleteChallenge(target.user, target.device)
                insertChallenge(
                    target.user, target.device, request.candidateId.bytes, nonce, registration.auth_epoch,
                    registration.auth_public_key, now, request.expiresAt.toEpochMilliseconds(),
                )
                LastDeviceRecoveryChallengeIssue.Issued(
                    stored(
                        target, request.candidateId.bytes, nonce, registration.auth_epoch,
                        request.expiresAt.toEpochMilliseconds(), registration.auth_public_key,
                    ),
                )
            }
        }

        override suspend fun challenge(target: DeviceAddress): StoredLastDeviceRecoveryChallenge? = transaction {
            selectChallenge(target.user, target.device).executeAsOneOrNull()?.let {
                stored(target, it.challenge_id, it.challenge_nonce, it.auth_epoch, it.expires_at, it.auth_public_key)
            }
        }

        private fun stored(
            target: DeviceAddress,
            id: ByteArray,
            nonce: ByteArray,
            authEpoch: Long,
            expiresAt: Long,
            authPublicKey: ByteArray,
        ) = StoredLastDeviceRecoveryChallenge(
            LastDeviceRecoveryChallenge(
                target, LastDeviceRecoveryChallengeId(id), nonce, authEpoch, Instant.fromEpochMilliseconds(expiresAt),
            ),
            authPublicKey,
        )
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
         * Server database schema, version 5. Independent of the client
         * schema. `Schema.migrate(driver, 1, 5)` migrates a milestone 13
         * database, `Schema.migrate(driver, 2, 5)` a milestone 14/15 one,
         * `Schema.migrate(driver, 3, 5)` a milestone 16 one and
         * `Schema.migrate(driver, 4, 5)` a milestone 17 one
         * (docs/server-storage.md).
         */
        val Schema: SqlSchema<QueryResult.Value<Unit>> get() = ServerDatabase.Schema

        private const val FORMAT_V1 = 1L
        private const val FORMAT_V2 = 2L
        private const val FORMAT_V3 = 3L
        private const val FORMAT_V4 = 4L
        private const val FORMAT_V5 = 5L

        /**
         * Opens the server storage on [driver], whose database must already
         * have the current schema ([Schema]). Creates and migrates no schema
         * and never closes [driver]: the caller keeps owning it. Throws
         * [IllegalStateException] if the database was not created with this
         * schema, or is still at schema version 1, 2, 3 or 4 (migrate it with
         * [Schema] first). Blocking database calls run on [dispatcher].
         *
         * Registrations that a migration from schema version 3 or older left
         * without a key installation time get [clock]'s current time, in one
         * transaction (docs/server-storage.md). That happens once: a stamped
         * time is never rewritten by a later open. Pass the server's clock.
         */
        suspend fun open(
            driver: SqlDriver,
            dispatcher: CoroutineDispatcher = Dispatchers.IO,
            clock: Clock = Clock.System,
        ): SqlDelightServerStorage {
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
            check(format != FORMAT_V3) { "Database has server storage schema version 3; migrate it with SqlDelightServerStorage.Schema" }
            check(format != FORMAT_V4) { "Database has server storage schema version 4; migrate it with SqlDelightServerStorage.Schema" }
            check(format == FORMAT_V5) { "Database has no supported server storage schema" }
            return SqlDelightServerStorage(driver, dispatcher).also { it.stampMissingInstallationTimes(clock) }
        }
    }
}

private enum class KeyReplacement { REPLACED, REPLAY, EPOCH_EXHAUSTED }

private val DeviceAddress.user get() = userId.value
private val DeviceAddress.device get() = deviceId.value

// Not named copy(): the data class member would win and copy shallowly.
private fun PublicSignedPreKey.deepCopy() = PublicSignedPreKey(id, publicKey.copyOf(), signature.copyOf())
