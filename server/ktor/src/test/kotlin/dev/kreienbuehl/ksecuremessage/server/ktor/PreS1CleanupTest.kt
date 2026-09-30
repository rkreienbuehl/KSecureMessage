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
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
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
 * The offline pre-S1 cleanup (docs/operating-the-server.md, "Pre-S1
 * cleanup"; S1.2 finding N5, S1.3 finding N6): the operator script
 * docs/operator/ksecuremessage-pre-s1-cleanup.sql, executed exactly as the
 * page tells operators to, with the real `sqlite3` shell
 * (`sqlite3 -bail <db> < <script>`), against a file-backed server database at
 * schema version 8 with its real constraints.
 *
 * Scenario: before S1, an attacker registered `alice/evil` under Alice's
 * user (no host authorization existed) and registered its own offline
 * recovery key R1. The legitimate `alice/phone` requested a recovery key
 * reset; the attacker holds a last-device recovery challenge for the phone.
 * After the upgrade the host authorizes registrations and recognizes only
 * the legitimate devices.
 */
class PreS1CleanupTest {
    private val clock = ManualClock()
    private val engine = KodiumProtocolEngine()
    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val evil = DeviceAddress(UserId("alice"), DeviceId("evil"))
    private val evil2 = DeviceAddress(UserId("alice"), DeviceId("evil2"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val carolPhone = DeviceAddress(UserId("carol"), DeviceId("phone"))
    private val carolEvil = DeviceAddress(UserId("carol"), DeviceId("evil"))
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

    private class CliResult(val exitCode: Int, val stdout: String, val stderr: String)

    private inner class Scenario(val storage: ReopenableServerStorage, http: HttpClient, val authorizer: UpgradingAuthorizer) {
        val transport = KtorSecureMessageTransport("", http)
        val phoneClient = client(phone)
        val evilClient = client(evil)
        val bobClient = client(bob)
        lateinit var pendingReset: RecoveryKeyResetStatus.Pending
        lateinit var staleRecovery: LastDeviceRecoveryAuthorization

        fun client(address: DeviceAddress) =
            SecureMessageClient(address, InMemoryClientStorage(), engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 3), clock)

        suspend fun registered(address: DeviceAddress) = client(address).also {
            it.initialize()
            it.registerDevice()
            it.publishPreKeys()
        }

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

        /**
         * Runs the operator script with [devices] and [exhaustedUsers] filled into its input
         * section, exactly as documented: `sqlite3 -bail <db> < <script>`, server stopped.
         */
        suspend fun runCleanup(
            vararg devices: DeviceAddress,
            exhaustedUsers: List<String> = emptyList(),
            interactive: Boolean = false,
            transform: (String) -> String = { it },
        ): CliResult {
            val script = transform(cleanupScript(devices.toList(), exhaustedUsers))
            return storage.offlineFile { database -> sqlite3(database, script, interactive) }
        }

        suspend fun <T> query(sql: String, read: (java.sql.ResultSet) -> T): List<T> =
            storage.offline { connection -> connection.select(sql, read) }

        suspend fun count(sql: String): Int = query(sql) { it.getInt(1) }.single()

        suspend fun execute(sql: String) = storage.offline { c -> c.createStatement().use { it.executeUpdate(sql) } }

        /** Every row of every server table, for "nothing changed" comparisons. */
        suspend fun snapshot(): Map<String, List<String>> = storage.offline { connection ->
            TABLES.associateWith { table ->
                connection.select("SELECT * FROM $table") { r ->
                    (1..r.metaData.columnCount).joinToString("|") { i -> r.getObject(i).let { if (it is ByteArray) it.toHex() else it?.toString() ?: "NULL" } }
                }.sorted()
            }
        }

        suspend fun recoveryKeyRow(user: String): List<Any?> = query(
            "SELECT state, epoch, public_key, installed_at, transitioned_at, rotation_id, revocation_id, reset_completion_id " +
                "FROM last_device_recovery_key_state WHERE user_id = '$user'",
        ) { r -> listOf<Any?>(r.getInt(1), r.getLong(2), r.getBytes(3)?.toHex(), r.getObject(4), r.getObject(5), r.getBytes(6)?.toHex(), r.getBytes(7)?.toHex(), r.getBytes(8)?.toHex()) }.single()

        suspend fun phoneKey(): ByteArray = assertNotNull(storage.devices.registration(phone)).publicKey

        suspend fun consumedOneTimePreKeyIds(address: DeviceAddress): Set<Int> = query(
            "SELECT pre_key_id FROM consumed_one_time_prekey WHERE user_id = '${address.userId.value}' AND device_id = '${address.deviceId.value}'",
        ) { it.getInt(1) }.toSet()

        fun assertFailedWithoutChange(result: CliResult, reason: String) {
            assertNotEquals(0, result.exitCode, "sqlite3 must exit non-zero: ${result.stdout} ${result.stderr}")
            assertTrue(result.stderr.contains(reason), "the error names $reason: ${result.stderr}")
            assertFalse(result.stdout.contains(PASSED), "no verification after a failure")
        }
    }

    private fun scenario(preUpgrade: suspend Scenario.() -> Unit = {}, block: suspend Scenario.() -> Unit) = ReopenableServerStorage().use { storage ->
        val authorizer = UpgradingAuthorizer(setOf(phone, bob, carolPhone))
        testServer(authorizer, storage, clock, RecoveryKeyResetPolicy(1.days)) { _, http ->
            val scenario = Scenario(storage, http, authorizer)
            scenario.setUp()
            scenario.preUpgrade()
            scenario.upgrade()
            scenario.block()
        }
    }

    // Root cause of N5: the pre-S1.2 guidance removed only the device.

    @Test
    fun n5DeviceOnlyCleanupLeavesAttackerRecoveryAuthority() = scenario {
        // Only part 1 of the script (device-scoped rows): what S1.1 told operators to do.
        val result = runCleanup(evil) { it.substringBefore("-- 2.") + "COMMIT;\n" }
        assertEquals(0, result.exitCode, result.stderr)
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

    // S1.2 / S1.3: the documented cleanup revokes the planted authority.

    @Test
    fun n5PreS1CleanupRevokesCompromisedRecoveryAuthority() = scenario {
        val phoneBefore = assertNotNull(storage.devices.registrationState(phone))
        val bobBefore = assertNotNull(storage.devices.registrationState(bob))
        val noncesBefore = nonceCounts()
        val bobOneTimePreKeys = storage.preKeys.oneTimePreKeyCount(bob)
        val phoneOneTimePreKeys = storage.preKeys.oneTimePreKeyCount(phone)
        val evilTombstones = consumedOneTimePreKeyIds(evil)
        assertTrue(evilTombstones.isNotEmpty(), "bob consumed one of evil's one-time prekeys")
        assertEquals(1, count("SELECT count(*) FROM last_device_recovery_key_reset WHERE user_id = 'alice'"))
        assertEquals(1, count("SELECT count(*) FROM last_device_recovery_challenge WHERE user_id = 'alice'"))

        val result = runCleanup(evil)
        assertEquals(0, result.exitCode, result.stderr)

        // The suspicious device is gone and cannot come back.
        assertNull(storage.devices.registration(evil))
        for (table in listOf("device_prekey_state", "available_one_time_prekey", "authentication_nonce")) {
            assertEquals(0, count("SELECT count(*) FROM $table WHERE user_id = 'alice' AND device_id = 'evil'"), table)
        }
        assertEquals(evilTombstones, consumedOneTimePreKeyIds(evil), "consumed one-time prekey IDs stay tombstoned (INFO-3)")
        assertEquals(noncesBefore - evil, nonceCounts(), "other devices' nonces kept")
        assertEquals(
            AuthenticationFailure.NOT_REGISTERED,
            assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { evilClient.receive() }.failure,
        )
        assertEquals(
            AuthenticationFailure.NOT_REGISTERED,
            assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { evilClient.publishPreKeys() }.failure,
        )
        // F1/F2 stay closed: the removed device cannot return without the host's authorization.
        assertFailsWith<SecureMessageTransportException.DeviceRegistrationNotAuthorized> { evilClient.registerDevice() }
        assertNull(storage.devices.registration(evil), "the host refused the re-registration")
        assertFailsWith<SecureMessageTransportException.DeviceNotFound> { transport.fetchPreKeyBundle(evil) }
        assertEquals(0, storage.preKeys.oneTimePreKeyCount(evil))

        // The recovery authority is revoked at epoch + 1; reset and challenges are gone.
        assertEquals(2L, assertIs<LastDeviceRecoveryKeyStatus.Revoked>(phoneClient.lastDeviceRecoveryKeyStatus()).epoch)
        val state = recoveryKeyRow("alice")
        assertEquals(listOf<Any?>(2, 2L, null, null), state.take(4))
        assertNotNull(state[4], "transitioned_at is the cleanup time")
        assertEquals(listOf<Any?>(null, null, null), state.drop(5))
        assertEquals(0, count("SELECT count(*) FROM last_device_recovery_key_reset WHERE user_id = 'alice'"))
        assertEquals(0, count("SELECT count(*) FROM last_device_recovery_challenge WHERE user_id = 'alice'"))

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
            listOf("alice/evil -> bob/phone", "alice/phone -> bob/phone", "bob/phone -> alice/phone"),
            mailbox(),
            "envelopes to the removed device are gone; envelopes sent as it and everything else stay",
        )
        // The legitimate devices keep working.
        assertEquals(listOf(bob), phoneClient.receive().map { it.sender })
        assertTrue(phone in bobClient.receive().map { it.sender })
        transport.fetchPreKeyBundle(phone)
    }

    @Test
    fun n5OldRecoveryKeyCannotRecoverAfterOfflineCleanup() = scenario {
        val legitimateKey = phoneKey()
        assertEquals(0, runCleanup(evil).exitCode)

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
        assertEquals(0, runCleanup(evil).exitCode)

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

    // N6 (S1.3): operator mistakes fail before anything changes.

    @Test
    fun n6OperatorPageDocumentsExactlyTheTestedInvocation() {
        val page = operatingServerDoc.replace(Regex("""\s+"""), " ")
        assertTrue(page.contains(DOCUMENTED_COMMAND), "the page names the command this test runs")
        assertTrue(page.contains("""--8<-- "$SCRIPT_PATH""""), "the page shows the script file itself, not a copy")
        assertFalse(operatingServerDoc.contains("ksm-sql:pre-s1-cleanup:begin"), "no second executable copy in the page")
        assertTrue(page.contains("Do not paste the cleanup statements interactively"))
    }

    @Test
    fun n6MissingListedDeviceAbortsWithoutChanges() = scenario {
        val before = snapshot()
        // A typo: the malicious device is alice/evil.
        val result = runCleanup(DeviceAddress(UserId("alice"), DeviceId("evl")))
        assertFailedWithoutChange(result, "every_listed_device_is_registered")
        assertEquals(before, snapshot(), "nothing changed")
        // Also when the typo is listed next to a correct row.
        assertFailedWithoutChange(runCleanup(evil, DeviceAddress(UserId("alice"), DeviceId("evl"))), "every_listed_device_is_registered")
        assertEquals(before, snapshot(), "nothing changed")
        assertIs<LastDeviceRecoveryKeyStatus.Active>(phoneClient.lastDeviceRecoveryKeyStatus())
    }

    @Test
    fun n6DuplicateListedDeviceAbortsWithoutChanges() = scenario {
        val before = snapshot()
        assertFailedWithoutChange(runCleanup(evil, evil), "UNIQUE constraint failed: ksm_cleanup_device")
        assertEquals(before, snapshot())
    }

    @Test
    fun n6EmptyCleanupIsRejected() = scenario {
        val before = snapshot()
        assertFailedWithoutChange(runCleanup(), "at_least_one_device_listed")
        // The unedited file as shipped is refused the same way.
        val shipped = storage.offlineFile { sqlite3(it, cleanupTemplate, interactive = false) }
        assertFailedWithoutChange(shipped, "at_least_one_device_listed")
        assertEquals(before, snapshot())
    }

    @Test
    fun n6CleanupFailureRollsBackEverything() = scenario {
        val before = snapshot()
        // A statement that fails after every destructive statement ran, just before COMMIT.
        val result = runCleanup(evil) { script ->
            val commit = script.indexOf("\nCOMMIT;")
            script.substring(0, commit) + "\nINSERT INTO main.server_storage (id, format) VALUES (0, 8);" + script.substring(commit)
        }
        assertFailedWithoutChange(result, "UNIQUE constraint failed: server_storage.id")
        assertEquals(before, snapshot(), "the open transaction was rolled back: no partial cleanup")
        assertNotNull(storage.devices.registration(evil))
    }

    @Test
    fun n6SchemaGuardRejectsAnotherServerSchema() = scenario {
        val before = snapshot()
        val result = storage.offlineFile { database ->
            java.sql.DriverManager.getConnection("jdbc:sqlite:$database").use { c -> c.createStatement().use { it.executeUpdate("UPDATE server_storage SET format = 7") } }
            try {
                sqlite3(database, cleanupScript(listOf(evil), emptyList()), interactive = false)
            } finally {
                java.sql.DriverManager.getConnection("jdbc:sqlite:$database").use { c -> c.createStatement().use { it.executeUpdate("UPDATE server_storage SET format = 8") } }
            }
        }
        assertFailedWithoutChange(result, "server_schema_is_version_8")
        assertEquals(before, snapshot())
    }

    /** Root cause of N6: executed interactively, the shell ignores `.bail on`, runs on after a failure and commits. */
    @Test
    fun n6InteractiveExecutionCommitsPartialCleanupRootCause() = scenario {
        val result = runCleanup(DeviceAddress(UserId("alice"), DeviceId("evl")), interactive = true)
        assertTrue(result.stderr.contains("every_listed_device_is_registered") || result.stdout.contains("every_listed_device_is_registered"))
        // The guard failed, yet the recovery key UPDATE and COMMIT still ran: a partial cleanup.
        assertIs<LastDeviceRecoveryKeyStatus.Revoked>(phoneClient.lastDeviceRecoveryKeyStatus())
        assertNotNull(storage.devices.registration(evil), "the attacker's device is still registered")
    }

    @Test
    fun n6GuardRunsBeforeFirstDestructiveStatement() {
        val statements = statements(cleanupTemplate)
        val guard = statements.indexOfFirst { it.startsWith("INSERT INTO ksm_cleanup_guard") }
        val input = statements.indexOfFirst { it.startsWith("CREATE TEMP TABLE ksm_cleanup_device") }
        val firstDestructive = statements.indexOfFirst { it.startsWith("DELETE") || it.startsWith("UPDATE") }
        val begin = statements.indexOf("BEGIN IMMEDIATE")
        val commit = statements.indexOf("COMMIT")
        assertTrue(begin in 0 until input, "the transaction is open before anything is listed")
        assertTrue(guard in (input + 1) until firstDestructive, "guard after the input, before the first DELETE/UPDATE: $statements")
        assertTrue(firstDestructive < commit)
        assertTrue(statements.drop(commit).none { it.startsWith("DELETE") || it.startsWith("UPDATE") }, "nothing destructive after COMMIT")
        assertTrue(cleanupTemplate.lines().first { it.isNotBlank() && !it.startsWith("--") } == ".bail on")
    }

    @Test
    fun n6VerificationOutputReportsZeroViolations() = scenario {
        val result = runCleanup(evil)
        assertEquals(0, result.exitCode, result.stderr)
        val lines = result.stdout.lines().filter(String::isNotBlank)
        assertEquals(PASSED, lines.last())
        val checks = lines.dropLast(1).associate { it.substringBefore('|') to it.substringAfter('|') }
        assertEquals(
            setOf(
                "listed_registrations_remaining", "listed_nonces_remaining", "listed_prekey_state_remaining",
                "listed_available_one_time_prekeys_remaining", "listed_mailbox_rows_remaining",
                "affected_users_with_active_recovery_key", "affected_users_pending_resets", "affected_users_challenges",
            ),
            checks.keys,
        )
        assertTrue(checks.values.all { it == "0" }, "$checks")
    }

    @Test
    fun n6VerificationFailsLoudly() = scenario {
        // A script that lost its recovery key revocation still commits the device part, but must not report success.
        val result = runCleanup(evil) { script ->
            val start = script.indexOf("-- 2.")
            val end = script.indexOf("\nCOMMIT;")
            script.substring(0, start) + script.substring(end)
        }
        assertNotEquals(0, result.exitCode)
        assertTrue(result.stdout.contains("affected_users_with_active_recovery_key|1"), result.stdout)
        assertTrue(result.stderr.contains("post_cleanup_verification_found_no_violations"), result.stderr)
        assertFalse(result.stdout.contains(PASSED))
    }

    @Test
    fun n6MultipleDevicesOfOneUserIncrementEpochOnce() = scenario(preUpgrade = { registered(evil2) }) {
        val result = runCleanup(evil, evil2)
        assertEquals(0, result.exitCode, result.stderr)
        assertNull(storage.devices.registration(evil))
        assertNull(storage.devices.registration(evil2))
        assertEquals(2L, assertIs<LastDeviceRecoveryKeyStatus.Revoked>(phoneClient.lastDeviceRecoveryKeyStatus()).epoch, "one transition, not one per device")
    }

    @Test
    fun n6MultipleUsersRemainIsolated() = scenario(preUpgrade = {
        registered(carolPhone)
        registered(carolEvil).registerLastDeviceRecoveryKey(engine.createLastDeviceRecoveryKey())
        // Bob configures his own recovery key; he is not affected.
        bobClient.registerLastDeviceRecoveryKey(r2)
    }) {
        val bobBefore = recoveryKeyRow("bob")
        val result = runCleanup(evil, carolEvil)
        assertEquals(0, result.exitCode, result.stderr)
        assertEquals(2L, assertIs<LastDeviceRecoveryKeyStatus.Revoked>(phoneClient.lastDeviceRecoveryKeyStatus()).epoch)
        assertEquals(listOf<Any?>(2, 2L), recoveryKeyRow("carol").take(2), "carol: one transition of her own")
        assertEquals(bobBefore, recoveryKeyRow("bob"), "an unaffected user is untouched")
        assertNotNull(storage.devices.registration(carolPhone))
        assertNull(storage.devices.registration(carolEvil))
    }

    @Test
    fun n6AlreadyRevokedUserIsUnchanged() = scenario(preUpgrade = { evilClient.revokeLastDeviceRecoveryKey(r1) }) {
        val before = recoveryKeyRow("alice")
        assertEquals(listOf<Any?>(2, 2L), before.take(2))
        val result = runCleanup(evil)
        assertEquals(0, result.exitCode, result.stderr)
        assertEquals(before, recoveryKeyRow("alice"), "idempotent: no second epoch step, same transition time")
        assertNull(storage.devices.registration(evil))
    }

    @Test
    fun n6ExhaustedEpochAbortsUnlessListed() = scenario {
        execute("UPDATE last_device_recovery_key_state SET epoch = 9223372036854775807 WHERE user_id = 'alice'")
        val before = snapshot()
        assertFailedWithoutChange(runCleanup(evil), "no_unlisted_exhausted_epoch")
        assertEquals(before, snapshot())
        assertIs<LastDeviceRecoveryKeyStatus.Active>(phoneClient.lastDeviceRecoveryKeyStatus())
    }

    @Test
    fun n6ListingANonExhaustedUserAsExhaustedAborts() = scenario {
        val before = snapshot()
        assertFailedWithoutChange(runCleanup(evil, exhaustedUsers = listOf("alice")), "every_exhausted_user_is_listed_active_and_exhausted")
        // A user without a listed device is refused too.
        assertFailedWithoutChange(runCleanup(evil, exhaustedUsers = listOf("bob")), "every_exhausted_user_is_listed_active_and_exhausted")
        assertEquals(before, snapshot())
    }

    @Test
    fun n6ExhaustedEpochPathAffectsOnlyListedUsers() = scenario(preUpgrade = {
        registered(carolPhone)
        registered(carolEvil).registerLastDeviceRecoveryKey(engine.createLastDeviceRecoveryKey())
    }) {
        execute("UPDATE last_device_recovery_key_state SET epoch = 9223372036854775807 WHERE user_id = 'alice'")
        val result = runCleanup(evil, carolEvil, exhaustedUsers = listOf("alice"))
        assertEquals(0, result.exitCode, result.stderr)
        assertTrue(result.stdout.contains(PASSED))

        // Alice (exhausted, listed): old key dead, REVOKED, epoch stays Long.MAX_VALUE ...
        assertEquals(Long.MAX_VALUE, assertIs<LastDeviceRecoveryKeyStatus.Revoked>(phoneClient.lastDeviceRecoveryKeyStatus()).epoch)
        assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { transport.recoverLastDevice(staleRecovery) }
        assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { transport.lastDeviceRecoveryChallenge(phone) }
        assertFailsWith<SecureMessageTransportException.RecoveryKeyResetRejected> { client(evil).lastDeviceRecoveryKeyResetStatusByRecoveryKey(r1) }
        assertNull(storage.devices.registration(evil))
        // ... and a later recovery key can never be provisioned (never wraps).
        assertEquals(
            RecoveryKeyFailure.EPOCH_EXHAUSTED,
            assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryKeyRejected> { phoneClient.registerLastDeviceRecoveryKey(r2) }.reason,
        )
        // Carol (not exhausted) gets the normal revocation at epoch + 1 and can provision again.
        assertEquals(listOf<Any?>(2, 2L), recoveryKeyRow("carol").take(2))
    }

    // INFO-3 (S1.3): the cleanup removes authority, not history.

    @Test
    fun info3ConsumedOneTimePreKeyIdIsNotReissued() = scenario {
        // Bob's first message consumed one of the phone's one-time prekeys (bundle fetch in setUp).
        val consumed = consumedOneTimePreKeyIds(phone)
        assertTrue(consumed.isNotEmpty())
        // The phone's key is suspect (for example a pre-S1 recovery replaced it): its address is cleaned up.
        assertEquals(0, runCleanup(phone, evil).exitCode)
        assertEquals(consumed, consumedOneTimePreKeyIds(phone), "tombstones kept")

        // The legitimate phone returns under host authorization and publishes its prekeys again,
        // including its still unused private one-time prekeys.
        phoneClient.registerDevice()
        phoneClient.publishPreKeys()
        val handedOut = generateSequence { runBlocking { transport.fetchPreKeyBundle(phone).oneTimePreKey?.id?.value } }.toList()
        assertTrue(handedOut.isNotEmpty(), "the returned device serves one-time prekeys again")
        assertTrue(handedOut.none { it in consumed }, "a consumed one-time prekey ID is never handed out again: $handedOut vs $consumed")
    }

    @Test
    fun info3KnownAddressWithAttackerKeyCanReturn() = scenario(preUpgrade = {
        // Before S1 the attacker took over alice/phone's server authentication with R1.
        val takeover = client(phone)
        takeover.initialize()
        takeover.prepareLastDeviceRecovery()
        takeover.recoverLastDevice(r1)
        attackerOnPhone = takeover
    }) {
        val attackerKey = phoneKey()
        val consumed = consumedOneTimePreKeyIds(phone)
        val result = runCleanup(phone, evil)
        assertEquals(0, result.exitCode, result.stderr)

        // The attacker's key is dead and the recovery authority revoked.
        assertEquals(
            AuthenticationFailure.NOT_REGISTERED,
            assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { attackerOnPhone.receive() }.failure,
        )
        assertEquals(listOf<Any?>(2, 2L), recoveryKeyRow("alice").take(2))
        // Envelopes queued for the invalidated instance are gone; the phone's earlier envelope to Bob is kept.
        assertEquals(listOf("alice/evil -> bob/phone", "alice/phone -> bob/phone"), mailbox())

        // The legitimate phone re-registers its own key (host-authorized) and publishes fresh prekeys.
        phoneClient.registerDevice()
        assertFalse(phoneKey().contentEquals(attackerKey))
        assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { attackerOnPhone.receive() }
        phoneClient.publishPreKeys()
        assertEquals(RecoveryKeyResetStatus.None, phoneClient.lastDeviceRecoveryKeyResetStatus())
        assertIs<LastDeviceRecoveryKeyStatus.Revoked>(phoneClient.lastDeviceRecoveryKeyStatus())
        val handedOut = generateSequence { runBlocking { transport.fetchPreKeyBundle(phone).oneTimePreKey?.id?.value } }.toList()
        assertTrue(handedOut.none { it in consumed }, "no consumed one-time prekey ID handed out again")
        // Bob still gets the phone's legitimate message sent before the compromise.
        assertTrue(phone in bobClient.receive().map { it.sender })
        // A fresh recovery key can be provisioned by the returned phone.
        phoneClient.registerLastDeviceRecoveryKey(r2)
        assertEquals(3L, assertIs<LastDeviceRecoveryKeyStatus.Active>(phoneClient.lastDeviceRecoveryKeyStatus()).epoch)
    }

    private lateinit var attackerOnPhone: SecureMessageClient

    private suspend fun Scenario.mailbox(): List<String> = query(
        "SELECT sender_user_id || '/' || sender_device_id || ' -> ' || recipient_user_id || '/' || recipient_device_id " +
            "FROM mailbox_message ORDER BY 1",
    ) { it.getString(1) }

    private suspend fun Scenario.nonceCounts(): Map<DeviceAddress, Int> =
        query("SELECT user_id, device_id, count(*) FROM authentication_nonce GROUP BY user_id, device_id") {
            DeviceAddress(UserId(it.getString(1)), DeviceId(it.getString(2))) to it.getInt(3)
        }.toMap()

    private companion object {
        const val AUDIT = "pre-s1-audit"
        const val SCRIPT_PATH = "docs/operator/ksecuremessage-pre-s1-cleanup.sql"
        const val DOCUMENTED_COMMAND = "sqlite3 -bail /path/to/server.db < ksecuremessage-pre-s1-cleanup.sql"
        const val PASSED = "ksm-pre-s1-cleanup: verification passed"
        const val INPUT_BEGIN = "-- ksm-cleanup-input:begin"
        const val INPUT_END = "-- ksm-cleanup-input:end"
        val TABLES = listOf(
            "server_storage", "device_registration", "authentication_nonce", "authentication_nonce_watermark",
            "device_prekey_state", "available_one_time_prekey", "consumed_one_time_prekey", "mailbox_message",
            "last_device_recovery_key_state", "last_device_recovery_key_reset", "last_device_recovery_challenge",
        )

        val operatingServerDoc: String by lazy {
            File(requireNotNull(System.getProperty("ksm.docs.operatingServer")) { "ksm.docs.operatingServer not set" }).readText()
        }

        /** The operator script as shipped: the single executable source of truth. */
        val cleanupTemplate: String by lazy {
            File(requireNotNull(System.getProperty("ksm.operator.preS1Cleanup")) { "ksm.operator.preS1Cleanup not set" }).readText()
        }

        /** The script with its input section edited the way the page tells operators to. */
        fun cleanupScript(devices: List<DeviceAddress>, exhaustedUsers: List<String>): String {
            check(cleanupTemplate.split(INPUT_BEGIN).size == 2 && cleanupTemplate.split(INPUT_END).size == 2)
            val rows = devices.map { "INSERT INTO ksm_cleanup_device (user_id, device_id) VALUES ('${it.userId.value}', '${it.deviceId.value}');" } +
                exhaustedUsers.map { "INSERT INTO ksm_exhausted_user (user_id) VALUES ('$it');" }
            return cleanupTemplate.substringBefore(INPUT_BEGIN) + INPUT_BEGIN + "\n" + rows.joinToString("\n") + "\n" +
                INPUT_END + cleanupTemplate.substringAfter(INPUT_END)
        }

        /** The `sqlite3` shell on PATH; the cleanup is verified only with the real tool, never skipped. */
        val sqlite3Executable: String by lazy {
            System.getenv("PATH").orEmpty().split(File.pathSeparator)
                .map { File(it, "sqlite3") }
                .firstOrNull { it.isFile && it.canExecute() }
                ?.absolutePath
                ?: error("sqlite3 is required for the pre-S1 cleanup verification: expected the executable 'sqlite3' on PATH")
        }

        /**
         * `sqlite3 -bail <database> < <script>`, the documented invocation, or with
         * [interactive] the shell's interactive mode (what pasting into its prompt does).
         */
        fun sqlite3(database: Path, script: String, interactive: Boolean): CliResult {
            val scriptFile = Files.createTempFile("ksecuremessage-pre-s1-cleanup", ".sql")
            try {
                Files.writeString(scriptFile, script)
                val command = if (interactive) listOf(sqlite3Executable, "-interactive", database.toString()) else listOf(sqlite3Executable, "-bail", database.toString())
                val process = ProcessBuilder(command).redirectInput(scriptFile.toFile()).start()
                val stdout = process.inputStream.bufferedReader().readText()
                val stderr = process.errorStream.bufferedReader().readText()
                check(process.waitFor(60, TimeUnit.SECONDS)) { "sqlite3 did not finish" }
                return CliResult(process.exitValue(), stdout, stderr)
            } finally {
                Files.deleteIfExists(scriptFile)
            }
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

        /** Statements of an SQL script: sqlite3 dot-commands and `--` comments removed. */
        fun statements(script: String): List<String> = script.lines()
            .filterNot { it.trimStart().startsWith(".") }
            .joinToString("\n") { it.substringBefore("--") }
            .split(';')
            .map { it.trim().replace(Regex("""\s+"""), " ") }
            .filter(String::isNotEmpty)

        fun <T> java.sql.Connection.select(sql: String, read: (java.sql.ResultSet) -> T): List<T> =
            createStatement().use { s -> s.executeQuery(sql).use { r -> buildList { while (r.next()) add(read(r)) } } }

        fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it) }
    }
}
