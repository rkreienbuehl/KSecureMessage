package dev.kreienbuehl.ksecuremessage.storage.server.inmemory

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.testing.LastDeviceRecoveryRepositoryContractTest

class InMemoryLastDeviceRecoveryRepositoryTest : LastDeviceRecoveryRepositoryContractTest() {
    override suspend fun newStorage(): ServerStorage = InMemoryServerStorage()

    override suspend fun setAuthEpoch(storage: ServerStorage, address: DeviceAddress, authEpoch: Long) =
        (storage as InMemoryServerStorage).setAuthEpochForTesting(address, authEpoch)
}
