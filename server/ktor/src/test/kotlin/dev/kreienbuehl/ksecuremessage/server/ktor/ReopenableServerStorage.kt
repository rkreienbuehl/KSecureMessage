package dev.kreienbuehl.ksecuremessage.server.ktor

import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.storage.AuthenticationNonceRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.server.sqldelight.SqlDelightServerStorage
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.nio.file.Path
import java.util.Properties
import kotlin.io.path.deleteIfExists
import kotlin.time.Instant

/**
 * Host-side test setup: a temporary SQLite file with [SqlDelightServerStorage]
 * on a driver this class creates and owns, as a host application would.
 * [restart] closes the driver and opens the same file with a new driver and a
 * new storage instance, like a server restart. The repositories delegate to
 * the current instance, so the running routes see the restarted storage.
 * Not for concurrent use with [restart].
 */
internal class ReopenableServerStorage : ServerStorage, AutoCloseable {
    private val path: Path = Files.createTempFile("ksm-server-http-", ".db")
    var driver: SqlDriver = newDriver()
        private set
    private var current: SqlDelightServerStorage = runBlocking { SqlDelightServerStorage.open(driver) }

    private fun newDriver(): SqlDriver =
        JdbcSqliteDriver("jdbc:sqlite:${path.toAbsolutePath()}", Properties(), SqlDelightServerStorage.Schema)

    suspend fun restart() {
        driver.close()
        driver = newDriver()
        current = SqlDelightServerStorage.open(driver)
    }

    override fun close() {
        driver.close()
        listOf("", "-journal", "-wal", "-shm").forEach { Path.of("$path$it").deleteIfExists() }
    }

    override val preKeys: PreKeyRepository = object : PreKeyRepository {
        override suspend fun publish(publication: PreKeyPublication) = current.preKeys.publish(publication)
        override suspend fun consumePreKeyBundle(address: DeviceAddress) = current.preKeys.consumePreKeyBundle(address)
        override suspend fun oneTimePreKeyCount(address: DeviceAddress) = current.preKeys.oneTimePreKeyCount(address)
    }

    override val mailboxes: MailboxRepository = object : MailboxRepository {
        override suspend fun enqueue(envelope: EncryptedEnvelope) = current.mailboxes.enqueue(envelope)
        override suspend fun drain(recipient: DeviceAddress) = current.mailboxes.drain(recipient)
    }

    override val devices: DeviceRegistrationRepository = object : DeviceRegistrationRepository {
        override suspend fun registration(address: DeviceAddress) = current.devices.registration(address)
        override suspend fun register(registration: DeviceRegistration) = current.devices.register(registration)
    }

    override val authenticationNonces: AuthenticationNonceRepository = object : AuthenticationNonceRepository {
        override suspend fun claim(address: DeviceAddress, nonce: ByteArray, timestamp: Instant, pruneBefore: Instant) =
            current.authenticationNonces.claim(address, nonce, timestamp, pruneBefore)
    }
}
