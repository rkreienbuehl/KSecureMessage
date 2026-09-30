package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.client.LastDeviceRecoveryKeyResetCancellationResult
import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.AuthenticationFailure
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RecoveryKeyFailure
import dev.kreienbuehl.ksecuremessage.client.ktor.KtorSecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKey
import dev.kreienbuehl.ksecuremessage.server.DeviceRegistrationAuthorizationRequest
import dev.kreienbuehl.ksecuremessage.server.DeviceRegistrationAuthorizationResult
import dev.kreienbuehl.ksecuremessage.server.DeviceRegistrationAuthorizer
import dev.kreienbuehl.ksecuremessage.server.RecoveryKeyResetPolicy
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import io.ktor.client.HttpClient
import kotlinx.coroutines.runBlocking
import java.io.File
import java.sql.Connection
import java.sql.SQLException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days

/**
 * The offline pre-S1 cleanup of docs/operating-the-server.md (S1.2, finding
 * N5), executed verbatim from the page against a file-backed server
 * database at schema version 8 with its real constraints.
 *
 * Scenario: before S1, an attacker registered `alice/evil` under Alice's
 * user (no host authorization existed) and registered its own offline
 * recovery key R1. The legitimate `alice/phone` requested a recovery key
 * reset; the attacker holds a last-device recovery challenge for the phone.
 * After the upgrade the host authorizes registrations and recognizes only
 * `alice/phone` and `bob/phone`.
 */
class PreS1CleanupTest {
    private val clock = ManualClock()
    private val engine = KodiumProtocolEngine()
    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val evil = DeviceAddress(UserId("alice"), DeviceId("evil"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val r1: LastDeviceRecoveryKey = runBlocking { engine.createLastDeviceRecoveryKey() }
    private val r2: LastDeviceRecoveryKey = runBlocking { engine.createLastDeviceRecoveryKey() }

    /** Before S1 every registration succeeded; after the upgrade the host recognizes only its own devices. */
    private class UpgradingAuthorizer(private val recognized: Set<DeviceAddress>) : DeviceRegistrationAuthorizer<TestRegistrationPrincipal> {
        @Volatile var preS1 = true

        override suspend fun authorize(context: TestRegistrationPrincipal, request: DeviceRegistrationAuthorizationRequest) =
            if (preS1 || (context.userId == request.address.userId && request.address in recognized)) {
                DeviceRegistrationAuthorizationResult.Authorized
            } else {
                DeviceRegistrationAuthorizationResult.Denied
            }
    }

    private inner class Scenario(val storage: ReopenableServerStorage, http: HttpClient, val authorizer: UpgradingAuthorizer) {
        val transport = KtorSecureMessageTransport("", http)
        val phoneClient = client(phone)
        val evilClient = client(evil)
        val bobClient = client(bob)
        lateinit var pendingReset: RecoveryKeyResetStatus.Pending
        lateinit var staleRecovery: LastDeviceRecoveryAuthorization

        fun client(address: DeviceAddress) =
            SecureMessageClient(address, InMemoryClientStorage(), engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 3), clock)

        suspend fun setUp() {
            for (client in listOf(phoneClient, evilClient, bobClient)) {
                client.initialize()
                client.registerDevice()
                client.publishPreKeys()
            }
            // The attacker's pre-S1 authority: its own offline recovery key for Alice.
            evilClient.registerLastDeviceRecoveryKey(r1)
            assertEquals(1L, assertIs<LastDeviceRecoveryKeyStatus.Active>(phoneClient.lastDeviceRecoveryKeyStatus()).epoch)
            // The legitimate user noticed and started a reset.
            pendingReset = phoneClient.requestLastDeviceRecoveryKeyReset()
            // Mailbox traffic in every direction.
            bobClient.send(phone, "bob to phone".encodeToByteArray())
            phoneClient.send(bob, "phone to bob".encodeToByteArray())
            evilClient.send(bob, "evil to bob".encodeToByteArray())
            bobClient.send(evil, "bob to evil".encodeToByteArray())
            // The attacker prepares a takeover of the phone: a challenge signed with R1.
            val challenge = transport.lastDeviceRecoveryChallenge(phone)
            staleRecovery = LastDeviceRecovery.authorize(r1, engine.createDeviceAuthenticationKey(), challenge)
        }

        /** The server upgrade: from now on only recognized devices can register. */
        fun upgrade() {
            authorizer.preS1 = false
        }

        suspend fun runDocBlock(name: String, transform: (String) -> String = { it }) =
            storage.offline { connection -> connection.runScript(transform(docBlock(name))) }

        suspend fun <T> query(sql: String, read: (java.sql.ResultSet) -> T): List<T> =
            storage.offline { connection -> connection.select(sql, read) }

        suspend fun phoneKey(): ByteArray = assertNotNull(storage.devices.registration(phone)).publicKey
    }

    private fun scenario(block: suspend Scenario.() -> Unit) = ReopenableServerStorage().use { storage ->
        val authorizer = UpgradingAuthorizer(setOf(phone, bob))
        testServer(authorizer, storage, clock, RecoveryKeyResetPolicy(1.days)) { _, http ->
            val scenario = Scenario(storage, http, authorizer)
            scenario.setUp()
            scenario.upgrade()
            scenario.block()
        }
    }

    // Root cause: the pre-S1.2 guidance removed only the device.

    @Test
    fun n5DeviceOnlyCleanupLeavesAttackerRecoveryAuthority() = scenario {
        // Only part 1 of the script (device-scoped rows): what S1.1 told operators to do.
        runDocBlock(CLEANUP) { it.substringBefore("-- 2.") + "DROP TABLE ksm_cleanup_device;\nCOMMIT;\n" }
        assertNull(storage.devices.registration(evil), "the device is gone")
        // ... but its recovery key R1 still vetoes the legitimate reset ...
        val cancelled = client(evil).cancelLastDeviceRecoveryKeyResetByRecoveryKey(r1, pendingReset)
        assertEquals(LastDeviceRecoveryKeyResetCancellationResult.Cancelled, cancelled)
        // ... and takes over the legitimate phone through last-device recovery.
        val legitimateKey = phoneKey()
        val takeover = client(phone)
        takeover.initialize()
        takeover.prepareLastDeviceRecovery()
        takeover.recoverLastDevice(r1)
        assertFalse(phoneKey().contentEquals(legitimateKey), "the attacker now owns alice/phone's server authentication")
    }

    // S1.2: the documented cleanup revokes the planted authority.

    @Test
    fun n5PreS1CleanupRevokesCompromisedRecoveryAuthority() = scenario {
        val phoneBefore = assertNotNull(storage.devices.registrationState(phone))
        val bobBefore = assertNotNull(storage.devices.registrationState(bob))
        val noncesBefore = nonceCounts()
        val bobOneTimePreKeys = storage.preKeys.oneTimePreKeyCount(bob)
        val phoneOneTimePreKeys = storage.preKeys.oneTimePreKeyCount(phone)
        assertEquals(1, query("SELECT count(*) FROM last_device_recovery_key_reset WHERE user_id = 'alice'") { it.getInt(1) }.single())
        assertEquals(1, query("SELECT count(*) FROM last_device_recovery_challenge WHERE user_id = 'alice'") { it.getInt(1) }.single())

        runDocBlock(CLEANUP)

        // The suspicious device is gone and cannot come back.
        assertNull(storage.devices.registration(evil))
        for (table in listOf("device_prekey_state", "available_one_time_prekey", "consumed_one_time_prekey", "authentication_nonce")) {
            assertEquals(0, query("SELECT count(*) FROM $table WHERE user_id = 'alice' AND device_id = 'evil'") { it.getInt(1) }.single(), table)
        }
        assertEquals(noncesBefore - evil, nonceCounts(), "other devices' nonces kept")
        assertEquals(
            AuthenticationFailure.NOT_REGISTERED,
            assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { evilClient.receive() }.failure,
        )
        assertEquals(
            AuthenticationFailure.NOT_REGISTERED,
            assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { evilClient.publishPreKeys() }.failure,
        )
        assertFailsWith<SecureMessageTransportException.DeviceRegistrationNotAuthorized> { evilClient.registerDevice() }
        assertNull(storage.devices.registration(evil), "the host refused the re-registration")
        assertFailsWith<SecureMessageTransportException.DeviceNotFound> { transport.fetchPreKeyBundle(evil) }
        assertEquals(0, storage.preKeys.oneTimePreKeyCount(evil))

        // The recovery authority is revoked at epoch + 1; reset and challenges are gone.
        assertEquals(LastDeviceRecoveryKeyStatus.Revoked::class, phoneClient.lastDeviceRecoveryKeyStatus()::class)
        assertEquals(2L, (phoneClient.lastDeviceRecoveryKeyStatus() as LastDeviceRecoveryKeyStatus.Revoked).epoch)
        assertEquals(
            listOf(listOf<Any?>(2, 2L, null, null, null, null, null)),
            query(
                "SELECT state, epoch, public_key, installed_at, rotation_id, revocation_id, reset_completion_id " +
                    "FROM last_device_recovery_key_state WHERE user_id = 'alice'",
            ) { r -> listOf<Any?>(r.getInt(1), r.getLong(2), r.getBytes(3), r.getObject(4), r.getBytes(5), r.getBytes(6), r.getBytes(7)) },
        )
        assertEquals(0, query("SELECT count(*) FROM last_device_recovery_key_reset WHERE user_id = 'alice'") { it.getInt(1) }.single())
        assertEquals(0, query("SELECT count(*) FROM last_device_recovery_challenge WHERE user_id = 'alice'") { it.getInt(1) }.single())

        // Legitimate state survives unchanged.
        val phoneAfter = assertNotNull(storage.devices.registrationState(phone))
        assertContentEquals(phoneBefore.registration.publicKey, phoneAfter.registration.publicKey)
        assertEquals(phoneBefore.authEpoch, phoneAfter.authEpoch)
        assertEquals(phoneBefore.authKeyInstalledAt, phoneAfter.authKeyInstalledAt)
        val bobAfter = assertNotNull(storage.devices.registrationState(bob))
        assertContentEquals(bobBefore.registration.publicKey, bobAfter.registration.publicKey)
        assertEquals(bobBefore.authEpoch, bobAfter.authEpoch)
        assertEquals(bobOneTimePreKeys, storage.preKeys.oneTimePreKeyCount(bob))
        assertEquals(phoneOneTimePreKeys, storage.preKeys.oneTimePreKeyCount(phone))
        assertEquals(
            listOf("alice/phone -> bob/phone", "bob/phone -> alice/phone"),
            query(
                "SELECT sender_user_id || '/' || sender_device_id || ' -> ' || recipient_user_id || '/' || recipient_device_id " +
                    "FROM mailbox_message ORDER BY 1",
            ) { it.getString(1) },
            "envelopes to and from the removed device are gone; everything else stays",
        )
        // The legitimate devices keep working.
        assertEquals(listOf(bob), phoneClient.receive().map { it.sender })
        assertEquals(listOf(phone), bobClient.receive().map { it.sender })
        transport.fetchPreKeyBundle(phone)
    }

    @Test
    fun n5OldRecoveryKeyCannotRecoverAfterOfflineCleanup() = scenario {
        val legitimateKey = phoneKey()
        runDocBlock(CLEANUP)

        // R1 can no longer veto or read the (deleted) reset.
        val cancellation = runCatching { client(evil).cancelLastDeviceRecoveryKeyResetByRecoveryKey(r1, pendingReset) }
        assertNotEquals<Any?>(LastDeviceRecoveryKeyResetCancellationResult.Cancelled, cancellation.getOrNull(), "R1 cannot cancel")
        cancellation.exceptionOrNull()?.let { assertIs<SecureMessageTransportException.RecoveryKeyResetRejected>(it) }
        assertFailsWith<SecureMessageTransportException.RecoveryKeyResetRejected> {
            client(evil).lastDeviceRecoveryKeyResetStatusByRecoveryKey(r1)
        }
        // The statement the attacker signed before the cleanup is dead.
        assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { transport.recoverLastDevice(staleRecovery) }
        // No new takeover either: no challenge is issued without an active recovery key.
        assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { transport.lastDeviceRecoveryChallenge(phone) }
        val takeover = client(phone)
        takeover.initialize()
        takeover.prepareLastDeviceRecovery()
        assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { takeover.recoverLastDevice(r1) }
        assertContentEquals(legitimateKey, phoneKey(), "alice/phone is still the legitimate device")
        assertIs<LastDeviceRecoveryKeyStatus.Revoked>(phoneClient.lastDeviceRecoveryKeyStatus())
    }

    @Test
    fun n5LegitimateDeviceCanProvisionFreshRecoveryKeyAfterCleanup() = scenario {
        runDocBlock(CLEANUP)

        // The documented provisioning step: a legitimate device registers a fresh key.
        phoneClient.registerLastDeviceRecoveryKey(r2)
        val status = assertIs<LastDeviceRecoveryKeyStatus.Active>(phoneClient.lastDeviceRecoveryKeyStatus())
        assertEquals(3L, status.epoch, "epoch 1 (R1) -> 2 (offline revocation) -> 3 (R2)")
        assertContentEquals(r2.publicKey, status.publicKey)
        assertEquals(RecoveryKeyResetStatus.None, phoneClient.lastDeviceRecoveryKeyResetStatus(), "no reset survived")

        // New challenges are bound to the new epoch; R1 still cannot use them.
        transport.lastDeviceRecoveryChallenge(phone)
        assertEquals(listOf(3L), query("SELECT recovery_key_epoch FROM last_device_recovery_challenge WHERE user_id = 'alice'") { it.getLong(1) })
        val legitimateKey = phoneKey()
        val attacker = client(phone)
        attacker.initialize()
        attacker.prepareLastDeviceRecovery()
        assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { attacker.recoverLastDevice(r1) }
        assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { transport.recoverLastDevice(staleRecovery) }
        assertContentEquals(legitimateKey, phoneKey())

        // R2 is the working authority: the user can recover a lost phone with it.
        val reinstalled = client(phone)
        reinstalled.initialize()
        reinstalled.prepareLastDeviceRecovery()
        reinstalled.recoverLastDevice(r2)
        assertFalse(phoneKey().contentEquals(legitimateKey))
    }

    @Test
    fun n5CleanupAtExhaustedEpochFailsClosedAndRollsBack() = scenario {
        storage.offline { it.createStatement().use { s -> s.executeUpdate("UPDATE last_device_recovery_key_state SET epoch = 9223372036854775807 WHERE user_id = 'alice'") } }

        // The script aborts at the recovery key UPDATE; closing without COMMIT rolls everything back.
        assertFailsWith<SQLException> { runDocBlock(CLEANUP) }
        assertNotNull(storage.devices.registration(evil), "nothing of the aborted script was applied")
        assertIs<LastDeviceRecoveryKeyStatus.Active>(phoneClient.lastDeviceRecoveryKeyStatus())
        assertEquals(1, query("SELECT count(*) FROM last_device_recovery_key_reset") { it.getInt(1) }.single())

        // The documented manual alternative: revoke without an epoch change (fail-closed).
        val exhausted = docBlock(CLEANUP_EXHAUSTED).trim()
        runDocBlock(CLEANUP) { script ->
            val start = script.indexOf("UPDATE last_device_recovery_key_state")
            val end = script.indexOf(';', start)
            script.substring(0, start) + exhausted + script.substring(end + 1)
        }
        assertNull(storage.devices.registration(evil))
        assertEquals(Long.MAX_VALUE, assertIs<LastDeviceRecoveryKeyStatus.Revoked>(phoneClient.lastDeviceRecoveryKeyStatus()).epoch)
        assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { transport.recoverLastDevice(staleRecovery) }
        assertFailsWith<SecureMessageTransportException.RecoveryKeyResetRejected> { client(evil).lastDeviceRecoveryKeyResetStatusByRecoveryKey(r1) }
        assertEquals(
            RecoveryKeyFailure.EPOCH_EXHAUSTED,
            assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryKeyRejected> { phoneClient.registerLastDeviceRecoveryKey(r2) }.reason,
            "never wraps: this user can no longer configure a recovery key",
        )
    }

    @Test
    fun n5AuditQueriesRunOnSchemaV8() = scenario {
        val attackerKey = assertNotNull(storage.devices.registration(evil)).publicKey
        val results = storage.offline { connection ->
            statements(docBlock(AUDIT)).map { sql ->
                connection.createStatement().use { s ->
                    s.executeQuery(sql).use { r ->
                        val columns = (1..r.metaData.columnCount).map { r.metaData.getColumnLabel(it) }
                        val rows = buildList { while (r.next()) add(columns.associateWith { r.getString(it) }) }
                        columns to rows
                    }
                }
            }
        }
        val (registrationColumns, registrations) = results[0]
        assertTrue(
            registrationColumns.containsAll(
                listOf("user_id", "device_id", "auth_public_key", "auth_epoch", "auth_key_installed_at", "recovery_id", "rotation_id", "last_device_recovery_id"),
            ),
            "addresses alone are not enough: $registrationColumns",
        )
        assertEquals(attackerKey.toHex(), registrations.single { it["device_id"] == "evil" }["auth_public_key"], "the attacker's key is visible")
        val (stateColumns, states) = results[1]
        assertTrue(
            stateColumns.containsAll(
                listOf("user_id", "state", "epoch", "public_key", "installed_at", "transitioned_at", "rotation_id", "revocation_id", "reset_completion_id"),
            ),
            "$stateColumns",
        )
        assertEquals(r1.publicKey.toHex(), states.single()["public_key"], "the planted recovery key is visible")
        val (resetColumns, resets) = results[2]
        assertTrue(
            resetColumns.containsAll(listOf("user_id", "reset_id", "requested_by_device", "expected_epoch", "expected_public_key", "requested_at", "eligible_at")),
            "$resetColumns",
        )
        assertEquals("phone", resets.single()["requested_by_device"])
        val (challengeColumns, challenges) = results[3]
        assertTrue(challengeColumns.containsAll(listOf("user_id", "device_id", "auth_public_key", "recovery_key_epoch")), "$challengeColumns")
        assertEquals(1, challenges.size)
    }

    private suspend fun Scenario.nonceCounts(): Map<DeviceAddress, Int> =
        query("SELECT user_id, device_id, count(*) FROM authentication_nonce GROUP BY user_id, device_id") {
            DeviceAddress(UserId(it.getString(1)), DeviceId(it.getString(2))) to it.getInt(3)
        }.toMap()

    private companion object {
        const val CLEANUP = "pre-s1-cleanup"
        const val CLEANUP_EXHAUSTED = "pre-s1-cleanup-exhausted"
        const val AUDIT = "pre-s1-audit"

        val operatingServerDoc: String by lazy {
            File(requireNotNull(System.getProperty("ksm.docs.operatingServer")) { "ksm.docs.operatingServer not set" }).readText()
        }

        /** The fenced SQL between `<!-- ksm-sql:<name>:begin -->` and `<!-- ksm-sql:<name>:end -->`, verbatim. */
        fun docBlock(name: String): String {
            val begin = "<!-- ksm-sql:$name:begin -->"
            val end = "<!-- ksm-sql:$name:end -->"
            val doc = operatingServerDoc
            check(doc.split(begin).size == 2) { "exactly one $begin expected" }
            val region = doc.substringAfter(begin).substringBefore(end)
            return region.substringAfter("```sql\n").substringBeforeLast("```")
        }

        /** Statements of an operator script: sqlite3 dot-commands and `--` comments removed. */
        fun statements(script: String): List<String> = script.lines()
            .filterNot { it.trimStart().startsWith(".") }
            .joinToString("\n") { it.substringBefore("--") }
            .split(';')
            .map(String::trim)
            .filter(String::isNotEmpty)

        /** Runs [script] like `sqlite3` with `.bail on`: in autocommit mode, stopping at the first error. */
        fun Connection.runScript(script: String) {
            autoCommit = true
            for (statement in statements(script)) createStatement().use { it.execute(statement) }
        }

        fun <T> Connection.select(sql: String, read: (java.sql.ResultSet) -> T): List<T> =
            createStatement().use { s -> s.executeQuery(sql).use { r -> buildList { while (r.next()) add(read(r)) } } }

        fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it) }
    }
}
