package dev.kreienbuehl.ksecuremessage.server

import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.server.inmemory.InMemoryServerStorage
import dev.kreienbuehl.ksecuremessage.storage.server.sqldelight.SqlDelightServerStorage
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import java.nio.file.Files
import java.nio.file.Path
import java.util.Properties
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.deleteIfExists
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * S1.1, finding N2: registrations that race, with every host decision held
 * open until all of them are inside the authorizer, so no decision can have
 * seen another registration's write. Who wins membership is decided by the
 * host's principal alone; the only storage precondition ("address not
 * registered") is enforced by the atomic write. Runs against every server
 * storage adapter. No sleeps: gates only.
 */
abstract class RegistrationRaceTest {
    protected abstract fun newStorage(): ServerStorage

    private val engine = KodiumProtocolEngine()
    private val alice = TestRegistrationPrincipal(UserId("alice"))
    private val mallory = TestRegistrationPrincipal(UserId("mallory"))

    private fun newKey(): DeviceAuthenticationKeyPair = runBlocking { engine.createDeviceAuthenticationKey() }

    private sealed interface Outcome {
        data object Registered : Outcome
        data object NotAuthorized : Outcome
        data object Conflict : Outcome
    }

    private suspend fun SecureMessageServer<TestRegistrationPrincipal>.attempt(
        principal: TestRegistrationPrincipal,
        address: DeviceAddress,
        key: DeviceAuthenticationKeyPair,
    ): Outcome {
        val body = "register".encodeToByteArray() + key.publicKey
        val request = ServerRequest(address, "PUT", ServerApiPaths.device(address, ServerApiPaths.REGISTRATION), body)
        val authentication = ServerRequestAuthentication.sign(key, request, Clock.System.now(), RequestNonce.random())
        return try {
            check(registerDevice(principal, DeviceRegistration(address, key.publicKey), body, authentication)) { "not a retry" }
            Outcome.Registered
        } catch (e: DeviceRegistrationException.NotAuthorized) {
            Outcome.NotAuthorized
        } catch (e: DeviceRegistrationException.Conflict) {
            Outcome.Conflict
        }
    }

    /** An authorizer (reference policy) whose decisions all wait until [parties] of them are open. */
    private fun barrierAuthorizer(parties: Int): TestDeviceRegistrationAuthorizer {
        val arrived = AtomicInteger()
        val allInside = CompletableDeferred<Unit>()
        return TestDeviceRegistrationAuthorizer.principalOwnsUser { _, _ ->
            if (arrived.incrementAndGet() == parties) allInside.complete(Unit)
            allInside.await()
        }
    }

    /** Runs [attempts] concurrently, all released by one start gate. */
    private suspend fun <T> race(attempts: List<suspend () -> T>): List<T> = withContext(Dispatchers.Default) {
        val start = CompletableDeferred<Unit>()
        val running = attempts.map { attempt -> async { start.await(); attempt() } }
        start.complete(Unit)
        running.awaitAll()
    }

    @Test
    fun n2ConcurrentFirstDeviceClaimsCannotBothWin() = runTest {
        // A new user: no device of "alice" exists. 16 claims by Alice's principal, 16 by Mallory's,
        // for 32 different device IDs of alice, all decided at the same moment.
        val storage = newStorage()
        val server = SecureMessageServer(storage, Clock.System, barrierAuthorizer(32))
        val claims = List(32) { i -> Triple(if (i % 2 == 0) alice else mallory, DeviceAddress(UserId("alice"), DeviceId("d$i")), newKey()) }
        val outcomes = race(claims.map { (principal, address, key) -> suspend { server.attempt(principal, address, key) } })

        claims.zip(outcomes).forEach { (claim, outcome) ->
            val (principal, address, key) = claim
            if (principal == alice) {
                assertEquals(Outcome.Registered, outcome, "$address")
                assertContentEquals(key.publicKey, storage.devices.registration(address)?.publicKey)
            } else {
                assertEquals(Outcome.NotAuthorized, outcome, "$address: being early is no authority")
                assertNull(storage.devices.registration(address))
            }
        }
    }

    @Test
    fun n2LegitimateAndAttackerFirstDeviceRaceOnlyThePrincipalWins() = runTest {
        // Both orders of the decisions completing: the attacker never wins, the legitimate device always does.
        for (attackerDecidesFirst in listOf(true, false)) {
            val storage = newStorage()
            val carol = TestRegistrationPrincipal(UserId("carol"))
            val legitimate = DeviceAddress(UserId("carol"), DeviceId("phone"))
            val attacker = DeviceAddress(UserId("carol"), DeviceId("evil"))
            val arrived = AtomicInteger()
            val bothInside = CompletableDeferred<Unit>()
            val release = mapOf(carol to CompletableDeferred<Unit>(), mallory to CompletableDeferred<Unit>())
            val authorizer = TestDeviceRegistrationAuthorizer.principalOwnsUser { principal, _ ->
                if (arrived.incrementAndGet() == 2) bothInside.complete(Unit)
                release.getValue(principal).await()
            }
            val server = SecureMessageServer(storage, Clock.System, authorizer)

            val outcomes = withContext(Dispatchers.Default) {
                val legit = async { server.attempt(carol, legitimate, newKey()) }
                val evil = async { server.attempt(mallory, attacker, newKey()) }
                // Carol has no device yet; both claims are inside the host decision at once.
                bothInside.await()
                val (first, second) = if (attackerDecidesFirst) mallory to carol else carol to mallory
                release.getValue(first).complete(Unit)
                (if (first == carol) legit else evil).await()
                release.getValue(second).complete(Unit)
                listOf(legit.await(), evil.await())
            }
            assertEquals(listOf(Outcome.Registered, Outcome.NotAuthorized), outcomes, "attackerDecidesFirst=$attackerDecidesFirst")
            assertTrue(storage.devices.registration(legitimate) != null)
            assertNull(storage.devices.registration(attacker), "the loser is not registered")
            assertEquals(setOf(carol, mallory), authorizer.contexts.toSet())
        }
    }

    @Test
    fun n2SameAddressConflictingKeysHaveExactlyOneWinner() = runTest {
        // 32 authorized claims of one address with 32 keys: the atomic write picks exactly one.
        val storage = newStorage()
        val server = SecureMessageServer(storage, Clock.System, barrierAuthorizer(32))
        val address = DeviceAddress(UserId("alice"), DeviceId("phone"))
        val keys = List(32) { newKey() }
        val outcomes = race(keys.map { key -> suspend { server.attempt(alice, address, key) } })
        assertEquals(1, outcomes.count { it == Outcome.Registered })
        assertEquals(31, outcomes.count { it == Outcome.Conflict })
        val winner = keys[outcomes.indexOf(Outcome.Registered)]
        assertContentEquals(winner.publicKey, storage.devices.registration(address)?.publicKey)
    }
}

class InMemoryRegistrationRaceTest : RegistrationRaceTest() {
    override fun newStorage(): ServerStorage = InMemoryServerStorage()
}

class SqlDelightRegistrationRaceTest : RegistrationRaceTest() {
    private val drivers = mutableListOf<SqlDriver>()

    override fun newStorage(): ServerStorage = runBlocking {
        SqlDelightServerStorage.open(JdbcSqliteDriver(JdbcSqliteDriver.IN_MEMORY, Properties(), SqlDelightServerStorage.Schema).also { drivers += it })
    }

    @AfterTest
    fun closeDrivers() = drivers.forEach { it.close() }
}

/** File-backed: JDBC uses one connection per thread, so the races go through real SQLite transactions. */
class FileBackedRegistrationRaceTest : RegistrationRaceTest() {
    private val drivers = mutableListOf<SqlDriver>()
    private val paths = mutableListOf<Path>()

    override fun newStorage(): ServerStorage = runBlocking {
        val path = Files.createTempFile("ksm-server-race-", ".db").also { paths.add(it) }
        SqlDelightServerStorage.open(JdbcSqliteDriver("jdbc:sqlite:${path.toAbsolutePath()}", Properties(), SqlDelightServerStorage.Schema).also { drivers += it })
    }

    @AfterTest
    fun cleanUp() {
        drivers.forEach { it.close() }
        paths.forEach { path -> listOf("", "-journal", "-wal", "-shm").forEach { Path.of("$path$it").deleteIfExists() } }
    }
}
