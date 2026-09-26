package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.UserId
import org.kotlincrypto.hash.sha2.SHA256
import kotlin.io.encoding.Base64
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

// Last-device recovery (docs/last-device-recovery.md): an offline Ed25519
// recovery key, registered per user by its public key only, authorizes the
// replacement of a device authentication key when no registered device of the
// user can (M14) and the device's own key is gone (M16). The server issues a
// single-use challenge; the recovery key signs it together with the
// replacement key, and the replacement key proves possession. Server
// authentication only; the messaging identity is never touched.

/**
 * The offline last-device recovery key of a user: a 32-byte Ed25519 seed and
 * its 32-byte public key. Created by
 * [ProtocolEngine.createLastDeviceRecoveryKey]; the application keeps it
 * offline (for example printed or in a password manager) in the canonical
 * text form [encode]. Only [publicKey] is ever sent to the server. The
 * library never persists it.
 *
 * Whoever holds this key can replace the server authentication key of every
 * registered device of the user it is registered for.
 *
 * Equality compares the public key. [toString] never prints key bytes.
 */
class LastDeviceRecoveryKey internal constructor(seed: ByteArray, publicKey: ByteArray) {
    private val seed: ByteArray = seed.copyOf()
    private val public: ByteArray = publicKey.copyOf()

    init {
        require(this.seed.size == Ed25519.SEED_SIZE) { "Recovery key has an invalid size" }
        require(public.size == Ed25519.PUBLIC_KEY_SIZE) { "Recovery public key has an invalid size" }
    }

    /** A copy of the 32-byte Ed25519 public key; the only part the server gets. */
    val publicKey: ByteArray get() = public.copyOf()

    /** The canonical text form: the seed in Base64url without padding, 43 characters. */
    fun encode(): String = TEXT.encode(seed)

    internal fun sign(data: ByteArray): ByteArray = Ed25519.sign(seed, data)

    override fun equals(other: Any?): Boolean = other is LastDeviceRecoveryKey && public.contentEquals(other.public)

    override fun hashCode(): Int = public.contentHashCode()

    override fun toString(): String = "LastDeviceRecoveryKey(<redacted>)"

    companion object {
        /** Length of [encode]'s result. */
        const val TEXT_LENGTH: Int = 43

        private val TEXT = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

        /**
         * Decodes the canonical text form. Strict: exactly [TEXT_LENGTH]
         * characters of the Base64url alphabet, no padding, no whitespace,
         * and the text must be the canonical encoding of its bytes. Throws
         * [IllegalArgumentException] otherwise.
         */
        fun decode(value: String): LastDeviceRecoveryKey {
            require(value.length == TEXT_LENGTH) { "Recovery key text has an invalid length" }
            require(value.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }) {
                "Recovery key text contains an invalid character"
            }
            val seed = try {
                TEXT.decode(value)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("Recovery key text is malformed")
            }
            try {
                require(seed.size == Ed25519.SEED_SIZE && TEXT.encode(seed) == value) { "Recovery key text is not canonical" }
                return fromSeed(seed)
            } finally {
                seed.fill(0)
            }
        }

        internal fun fromSeed(seed: ByteArray): LastDeviceRecoveryKey =
            LastDeviceRecoveryKey(seed, Ed25519.publicKey(seed))
    }
}

/**
 * A user's registration of [publicKey] as its last-device recovery key.
 * [proofOfPossession] is the recovery key's signature over
 * `u32 length | domain | u32 length | userId | publicKey`, so nobody can
 * register a key they do not hold (a registration cannot be replaced in
 * milestone 18).
 */
class LastDeviceRecoveryKeyRegistration(
    val userId: UserId,
    publicKey: ByteArray,
    proofOfPossession: ByteArray,
) {
    private val key: ByteArray = publicKey.copyOf()
    private val pop: ByteArray = proofOfPossession.copyOf()

    init {
        require(key.size == LastDeviceRecovery.PUBLIC_KEY_SIZE) { "Recovery public key has an invalid size" }
        require(pop.size == LastDeviceRecovery.SIGNATURE_SIZE) { "Proof of possession has an invalid size" }
    }

    /** A copy of the recovery public key. */
    val publicKey: ByteArray get() = key.copyOf()

    /** A copy of the proof-of-possession signature. */
    val proofOfPossession: ByteArray get() = pop.copyOf()

    override fun toString(): String = "LastDeviceRecoveryKeyRegistration(userId=$userId)"
}

/** Server-chosen identifier of one last-device recovery challenge: 16 random bytes. Not secret. */
class LastDeviceRecoveryChallengeId(bytes: ByteArray) {
    private val value: ByteArray = bytes.copyOf()

    init {
        require(value.size == SIZE) { "Challenge ID must have $SIZE bytes" }
    }

    /** A copy of the ID bytes. */
    val bytes: ByteArray get() = value.copyOf()

    override fun equals(other: Any?): Boolean = other is LastDeviceRecoveryChallengeId && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "LastDeviceRecoveryChallengeId(<redacted>)"

    companion object {
        const val SIZE: Int = 16
    }
}

/**
 * A server-issued, single-use challenge for recovering [target]: the random
 * [id] and [nonce], the target's authentication epoch [authEpoch] when the
 * challenge was issued, and [expiresAt] (whole milliseconds, server clock).
 * Contains no secret; the recovery is bound to it by the signatures.
 */
class LastDeviceRecoveryChallenge(
    val target: DeviceAddress,
    val id: LastDeviceRecoveryChallengeId,
    nonce: ByteArray,
    val authEpoch: Long,
    val expiresAt: Instant,
) {
    private val value: ByteArray = nonce.copyOf()

    init {
        require(value.size == NONCE_SIZE) { "Challenge nonce must have $NONCE_SIZE bytes" }
        require(authEpoch >= 1) { "Authentication epoch must be positive" }
        require(expiresAt.toEpochMilliseconds() >= 0) { "Expiry must not be before the epoch" }
        require(Instant.fromEpochMilliseconds(expiresAt.toEpochMilliseconds()) == expiresAt) {
            "Expiry must be whole milliseconds"
        }
    }

    /** A copy of the 32 nonce bytes. */
    val nonce: ByteArray get() = value.copyOf()

    override fun toString(): String = "LastDeviceRecoveryChallenge(target=$target, authEpoch=$authEpoch, expiresAt=$expiresAt)"

    companion object {
        const val NONCE_SIZE: Int = 32
    }
}

/**
 * The transition a last-device recovery asks for: [challenge]'s target, at
 * the challenge's epoch, gets [replacementPublicKey], authorized by the
 * recovery key [recoveryPublicKey]. The replacement key must differ from the
 * recovery key.
 */
class LastDeviceRecoveryStatement(
    val challenge: LastDeviceRecoveryChallenge,
    recoveryPublicKey: ByteArray,
    replacementPublicKey: ByteArray,
) {
    private val recovery: ByteArray = recoveryPublicKey.copyOf()
    private val replacement: ByteArray = replacementPublicKey.copyOf()

    init {
        require(recovery.size == LastDeviceRecovery.PUBLIC_KEY_SIZE) { "Recovery public key has an invalid size" }
        require(replacement.size == LastDeviceRecovery.PUBLIC_KEY_SIZE) { "Replacement key has an invalid size" }
        require(!recovery.contentEquals(replacement)) { "The replacement key must not be the recovery key" }
    }

    val target: DeviceAddress get() = challenge.target

    /** A copy of the recovery public key. */
    val recoveryPublicKey: ByteArray get() = recovery.copyOf()

    /** A copy of the replacement public key. */
    val replacementPublicKey: ByteArray get() = replacement.copyOf()

    override fun toString(): String = "LastDeviceRecoveryStatement($challenge)"
}

/**
 * A [statement] with both proofs: [recoverySignature] by the offline
 * recovery key, [proofOfPossession] by the replacement key.
 */
class LastDeviceRecoveryAuthorization(
    val statement: LastDeviceRecoveryStatement,
    recoverySignature: ByteArray,
    proofOfPossession: ByteArray,
) {
    private val signature: ByteArray = recoverySignature.copyOf()
    private val pop: ByteArray = proofOfPossession.copyOf()

    init {
        require(signature.size == LastDeviceRecovery.SIGNATURE_SIZE) { "Recovery signature has an invalid size" }
        require(pop.size == LastDeviceRecovery.SIGNATURE_SIZE) { "Proof of possession has an invalid size" }
    }

    /** A copy of the recovery key's signature. */
    val recoverySignature: ByteArray get() = signature.copyOf()

    /** A copy of the replacement key's signature. */
    val proofOfPossession: ByteArray get() = pop.copyOf()

    override fun toString(): String = "LastDeviceRecoveryAuthorization($statement)"
}

/**
 * Identifies one last-device recovery statement: 32 bytes, SHA-256 over the
 * domain `KSecureMessage-LastDeviceRecoveryId-v1` and the statement. The
 * server records the ID of the recovery that installed a device's current
 * key, so a retry of the same recovery is recognized. Never an authorization.
 */
class LastDeviceRecoveryId(bytes: ByteArray) {
    private val value: ByteArray = bytes.copyOf()

    init {
        require(value.size == SIZE) { "Last-device recovery ID must have $SIZE bytes" }
    }

    /** A copy of the 32 ID bytes. */
    val bytes: ByteArray get() = value.copyOf()

    override fun equals(other: Any?): Boolean = other is LastDeviceRecoveryId && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "LastDeviceRecoveryId(<redacted>)"

    companion object {
        const val SIZE: Int = 32
    }
}

/**
 * Last-device recovery, format version 1 (docs/last-device-recovery.md).
 * Recovery statement:
 *
 * ```
 * u32 length | target userId (UTF-8) | u32 length | target deviceId (UTF-8)
 * recovery public key (32)
 * challenge ID (16)
 * challenge nonce (32)
 * expected authentication epoch: i64 (>= 1)
 * challenge expiry: i64, epoch milliseconds
 * replacement public key (32)
 * ```
 *
 * Each construction prefixes `u32 length | domain (UTF-8)`:
 *
 * - recovery authorization, Ed25519 by the recovery key:
 *   `KSecureMessage-LastDeviceRecovery-v1`;
 * - proof of possession, Ed25519 by the replacement key:
 *   `KSecureMessage-LastDeviceRecovery-PoP-v1`;
 * - [LastDeviceRecoveryId], SHA-256: `KSecureMessage-LastDeviceRecoveryId-v1`.
 *
 * The key registration's proof of possession signs
 * `u32 length | KSecureMessage-LastDeviceRecoveryKey-PoP-v1 | u32 length | userId (UTF-8) | recovery public key (32)`.
 *
 * Integers are big-endian. No domain is shared with server request
 * authentication, device recovery or routine rotation.
 */
object LastDeviceRecovery {
    /** Size of a recovery or replacement public key (Ed25519). */
    const val PUBLIC_KEY_SIZE: Int = Ed25519.PUBLIC_KEY_SIZE

    /** Size of a signature (Ed25519). */
    const val SIGNATURE_SIZE: Int = Ed25519.SIGNATURE_SIZE

    /** How long a server-issued challenge is valid: `issuedAt + CHALLENGE_LIFETIME = expiresAt`. */
    val CHALLENGE_LIFETIME = 5.minutes

    /** The registration of [key] for [userId], with the key's proof of possession. */
    fun registerKey(key: LastDeviceRecoveryKey, userId: UserId): LastDeviceRecoveryKeyRegistration {
        val publicKey = key.publicKey
        return LastDeviceRecoveryKeyRegistration(userId, publicKey, key.sign(keyRegistrationInput(userId, publicKey)))
    }

    /** `true` if [registration]'s proof of possession verifies with its public key. */
    fun verifyKeyRegistration(registration: LastDeviceRecoveryKeyRegistration): Boolean =
        Ed25519.verify(
            registration.publicKey,
            keyRegistrationInput(registration.userId, registration.publicKey),
            registration.proofOfPossession,
        )

    /**
     * The recovery of [challenge]'s target to [replacement], signed by
     * [recoveryKey] and by [replacement]. Throws [IllegalArgumentException]
     * if both keys are the same.
     */
    fun authorize(
        recoveryKey: LastDeviceRecoveryKey,
        replacement: DeviceAuthenticationKeyPair,
        challenge: LastDeviceRecoveryChallenge,
    ): LastDeviceRecoveryAuthorization {
        val statement = LastDeviceRecoveryStatement(challenge, recoveryKey.publicKey, replacement.publicKey)
        return LastDeviceRecoveryAuthorization(
            statement,
            recoveryKey.sign(authorizationInput(statement)),
            Ed25519.sign(replacement.privateKey, proofOfPossessionInput(statement)),
        )
    }

    /**
     * `true` if [authorization]'s recovery signature verifies with
     * [recoveryPublicKey]. The server passes the user's **registered**
     * recovery key. Does not check the proof of possession.
     */
    fun verifyRecoverySignature(recoveryPublicKey: ByteArray, authorization: LastDeviceRecoveryAuthorization): Boolean =
        Ed25519.verify(recoveryPublicKey, authorizationInput(authorization.statement), authorization.recoverySignature)

    /** `true` if the proof of possession verifies with the statement's replacement key. */
    fun verifyProofOfPossession(authorization: LastDeviceRecoveryAuthorization): Boolean =
        Ed25519.verify(
            authorization.statement.replacementPublicKey,
            proofOfPossessionInput(authorization.statement),
            authorization.proofOfPossession,
        )

    /** The ID of [statement]. */
    fun recoveryId(statement: LastDeviceRecoveryStatement): LastDeviceRecoveryId =
        LastDeviceRecoveryId(SHA256().digest(domainInput(ID_DOMAIN, statement(statement))))

    /** The bytes the recovery key signs. */
    fun authorizationInput(statement: LastDeviceRecoveryStatement): ByteArray =
        domainInput(AUTHORIZATION_DOMAIN, statement(statement))

    /** The bytes the replacement key signs. */
    fun proofOfPossessionInput(statement: LastDeviceRecoveryStatement): ByteArray =
        domainInput(POP_DOMAIN, statement(statement))

    /** The bytes the recovery key signs when it is registered for [userId]. */
    fun keyRegistrationInput(userId: UserId, publicKey: ByteArray): ByteArray {
        require(publicKey.size == PUBLIC_KEY_SIZE) { "Recovery public key has an invalid size" }
        val out = BinaryWriter()
        out.bytes(userId.value.encodeToByteArray())
        out.fixed(publicKey)
        return domainInput(KEY_POP_DOMAIN, out.toByteArray())
    }

    internal fun statement(statement: LastDeviceRecoveryStatement): ByteArray {
        val challenge = statement.challenge
        val out = BinaryWriter()
        out.bytes(challenge.target.userId.value.encodeToByteArray())
        out.bytes(challenge.target.deviceId.value.encodeToByteArray())
        out.fixed(statement.recoveryPublicKey)
        out.fixed(challenge.id.bytes)
        out.fixed(challenge.nonce)
        out.long(challenge.authEpoch)
        out.long(challenge.expiresAt.toEpochMilliseconds())
        out.fixed(statement.replacementPublicKey)
        return out.toByteArray()
    }

    private fun domainInput(domain: ByteArray, statement: ByteArray): ByteArray {
        val out = BinaryWriter()
        out.bytes(domain)
        out.fixed(statement)
        return out.toByteArray()
    }

    private val AUTHORIZATION_DOMAIN = ProtocolConstants.LAST_DEVICE_RECOVERY_DOMAIN.encodeToByteArray()
    private val POP_DOMAIN = ProtocolConstants.LAST_DEVICE_RECOVERY_POP_DOMAIN.encodeToByteArray()
    private val ID_DOMAIN = ProtocolConstants.LAST_DEVICE_RECOVERY_ID_DOMAIN.encodeToByteArray()
    private val KEY_POP_DOMAIN = ProtocolConstants.LAST_DEVICE_RECOVERY_KEY_POP_DOMAIN.encodeToByteArray()
}
