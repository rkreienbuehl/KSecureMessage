package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.testing.DeviceRegistrationRepositoryContractTest
import kotlin.test.AfterTest

/** The shared contract on SQLite (one in-memory database per repository). */
class SqlDelightDeviceRegistrationRepositoryTest : DeviceRegistrationRepositoryContractTest() {
    private val drivers = mutableListOf<SqlDriver>()

    override suspend fun newRepository(): DeviceRegistrationRepository =
        SqlDelightServerStorage.open(inMemoryDriver().also { drivers += it }).devices

    @AfterTest
    fun closeDrivers() = drivers.forEach { it.close() }
}
