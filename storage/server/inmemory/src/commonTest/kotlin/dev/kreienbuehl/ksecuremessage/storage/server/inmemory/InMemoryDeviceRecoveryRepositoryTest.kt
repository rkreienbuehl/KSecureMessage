package dev.kreienbuehl.ksecuremessage.storage.server.inmemory

import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.testing.DeviceRecoveryRepositoryContractTest

class InMemoryDeviceRecoveryRepositoryTest : DeviceRecoveryRepositoryContractTest() {
    override suspend fun newStorage(): ServerStorage = InMemoryServerStorage()
}
