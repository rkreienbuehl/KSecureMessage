package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetId
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import dev.kreienbuehl.ksecuremessage.model.UserId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Instant

private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

/**
 * Frozen vectors of the delayed recovery key reset format version 1
 * (docs/recovery-key-reset.md): the completion proof of possession and ID,
 * the recovery key cancellation and the recovery key status query. Every
 * reset a server completed or cancelled depends on them. Computed
 * independently (Python struct, hashlib and the `cryptography` package's
 * Ed25519) from the documented layout; the same script first reproduced the
 * frozen recovery key rotation vectors (RecoveryKeyLifecycleTest "base").
 */
class RecoveryKeyResetTest {
    private val recovery1 = LastDeviceRecoveryKey.fromSeed(ByteArray(32) { (0xC0 + it).toByte() })
    private val recovery2 = LastDeviceRecoveryKey.fromSeed(ByteArray(32) { (0xA0 + it).toByte() })
    private val recovery3 = LastDeviceRecoveryKey.fromSeed(ByteArray(32) { (0xE0 + it).toByte() })

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val tablet = DeviceAddress(UserId("alice"), DeviceId("tablet"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val encoded = DeviceAddress(UserId("ä b/c"), DeviceId("dev~1"))
    private val reset1 = RecoveryKeyResetId(ByteArray(16) { (0x10 + it).toByte() })
    private val reset2 = RecoveryKeyResetId(ByteArray(16) { (0x90 + it).toByte() })
    private val requestedAt = Instant.fromEpochMilliseconds(1_767_225_600_000)
    private val eligibleAt = requestedAt + 72.hours

    private fun pending(
        user: UserId = UserId("alice"),
        resetId: RecoveryKeyResetId = reset1,
        epoch: Long = 3,
        current: LastDeviceRecoveryKey = recovery1,
        requestedAt: Instant = this.requestedAt,
        eligibleAt: Instant = this.eligibleAt,
    ) = RecoveryKeyResetStatus.Pending(resetId, DeviceAddress(user, DeviceId("requester")), requestedAt, eligibleAt, epoch, current.publicKey)

    private fun completion(
        user: DeviceAddress = phone,
        completer: DeviceAddress = user,
        resetId: RecoveryKeyResetId = reset1,
        epoch: Long = 3,
        current: LastDeviceRecoveryKey = recovery1,
        new: LastDeviceRecoveryKey = recovery2,
        requestedAt: Instant = this.requestedAt,
        eligibleAt: Instant = this.eligibleAt,
    ) = RecoveryKeyReset.complete(new, pending(user.userId, resetId, epoch, current, requestedAt, eligibleAt), completer)

    private fun cancellation(
        user: UserId = UserId("alice"),
        resetId: RecoveryKeyResetId = reset1,
        epoch: Long = 3,
        current: LastDeviceRecoveryKey = recovery1,
        requestedAt: Instant = this.requestedAt,
        eligibleAt: Instant = this.eligibleAt,
    ) = RecoveryKeyReset.cancel(current, pending(user, resetId, epoch, current, requestedAt, eligibleAt))

    private fun query(
        user: UserId = UserId("alice"),
        current: LastDeviceRecoveryKey = recovery1,
        timestamp: Instant = requestedAt,
    ) = RecoveryKeyReset.statusQuery(current, user, timestamp)

    private class CompletionVector(
        val authorization: RecoveryKeyResetCompletionAuthorization,
        val proofOfPossessionInput: String,
        val completionId: String,
        val proofOfPossession: String,
    )

    private class SignatureVector<T>(val value: T, val input: String, val signature: String)

    private val completionVectors by lazy {
        mapOf(
            "base" to CompletionVector(
                completion(),
                "0000002c4b5365637572654d6573736167652d5265636f766572794b657952657365742d4e65774b6579506f502d763100000005616c69" +
                "6365101112131415161718191a1b1c1d1e1f0000000000000003dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a" +
                "495ff84fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c40000019b76daa8000000019b864dbc0000000005" +
                "616c6963650000000570686f6e65",
                "a89df6fb22be8438c8ffa127fe989cceb141d563855edf1f6d5e4d5560234565",
                "23d3d9081220416afc5fcfb236ed591e9e14630644cb72c1937cfb4559fa8a36d8c9f7136a716d79b6ba2a1c2970097264cca1ca8179e9" +
                "b3f462ea92cf996e05",
            ),
            "other user" to CompletionVector(
                completion(user = bob),
                "0000002c4b5365637572654d6573736167652d5265636f766572794b657952657365742d4e65774b6579506f502d763100000003626f62" +
                "101112131415161718191a1b1c1d1e1f0000000000000003dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495f" +
                "f84fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c40000019b76daa8000000019b864dbc0000000003626f" +
                "620000000570686f6e65",
                "67a46b080b3ad5b9b62fa817ba08f17f65a70393e190e958072f215f62c351e0",
                "0bf49ad010019bb448db3e49526bb98295587e12e517d3fc98490e2b0106442f74964da47b3418b789bab7f8135eddb6ddbcd365f78738" +
                "9070b9a2a0c8c6a108",
            ),
            "other completer" to CompletionVector(
                completion(completer = tablet),
                "0000002c4b5365637572654d6573736167652d5265636f766572794b657952657365742d4e65774b6579506f502d763100000005616c69" +
                "6365101112131415161718191a1b1c1d1e1f0000000000000003dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a" +
                "495ff84fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c40000019b76daa8000000019b864dbc0000000005" +
                "616c696365000000067461626c6574",
                "3808f45514ce68d3144464afae748bb60fb629d889ce3f567cea1bb9fdc7e80f",
                "ce8ab4e87be3dee4b56a66df4065cb3e36d50149b7f6d2d6d5b4200477df8dbd92f2359135eed3b4549669c4c8c97121ec614a6cb1294c" +
                "e21e2245670f41cd0d",
            ),
            "other reset" to CompletionVector(
                completion(resetId = reset2),
                "0000002c4b5365637572654d6573736167652d5265636f766572794b657952657365742d4e65774b6579506f502d763100000005616c69" +
                "6365909192939495969798999a9b9c9d9e9f0000000000000003dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a" +
                "495ff84fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c40000019b76daa8000000019b864dbc0000000005" +
                "616c6963650000000570686f6e65",
                "80c9bcda7d4cf0668e48b71802a9ac2ecffe35b411abca59f00230032c4cc539",
                "15d1806df47eb4134dc7ec9d8e9a9d5a8ffe52bd6058cc5d69a69e43cd86e56cacd64edfd4d2ba9de8b3308e0c1cfb0cf378fc0bff541b" +
                "fef3ecd72ec5197706",
            ),
            "other current" to CompletionVector(
                completion(current = recovery3),
                "0000002c4b5365637572654d6573736167652d5265636f766572794b657952657365742d4e65774b6579506f502d763100000005616c69" +
                "6365101112131415161718191a1b1c1d1e1f000000000000000313d9908a70925992ed546007d27f50da68ba7217ef62ac3cca784529ff" +
                "10471c4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c40000019b76daa8000000019b864dbc0000000005" +
                "616c6963650000000570686f6e65",
                "0d2b24f57b326d980769ea710dad044403474ac297c04922e55ffc54f342eec3",
                "d7d31348e2f15c9db7c5444163c79d5c0a4de307e55dc8db030e756b7132b87343e9c39e7a281e27f12cf8a67a4b4d444d90925ffd3f31" +
                "3e7c8910828766e40f",
            ),
            "other new" to CompletionVector(
                completion(new = recovery3),
                "0000002c4b5365637572654d6573736167652d5265636f766572794b657952657365742d4e65774b6579506f502d763100000005616c69" +
                "6365101112131415161718191a1b1c1d1e1f0000000000000003dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a" +
                "495ff813d9908a70925992ed546007d27f50da68ba7217ef62ac3cca784529ff10471c0000019b76daa8000000019b864dbc0000000005" +
                "616c6963650000000570686f6e65",
                "e0090e3bb9ec3173b465d735dd4ab89f191a693d14cf4c460bd14228e1321dc5",
                "d61c06501b05c94084e2de88495848fd08d30a888f255bf3bfe565d4a663c031f0fb84e3dcbca34e223aea6dabd7031555ddbc52b963e5" +
                "80060a87e88b93960c",
            ),
            "other epoch" to CompletionVector(
                completion(epoch = 4),
                "0000002c4b5365637572654d6573736167652d5265636f766572794b657952657365742d4e65774b6579506f502d763100000005616c69" +
                "6365101112131415161718191a1b1c1d1e1f0000000000000004dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a" +
                "495ff84fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c40000019b76daa8000000019b864dbc0000000005" +
                "616c6963650000000570686f6e65",
                "a6ff2e0936ebb9b6fc3a10ccb33f3e90b746828170bab16e60fde590eea1940a",
                "233e8dca8c59e7ea9d00c2885dc977a37d06562c672d28af5cc804886a18c513b32e22d00a797d744634a84419daeb2871d8af3bda8f1d" +
                "91cbc456cd81f76d0a",
            ),
            "other requestedAt" to CompletionVector(
                completion(requestedAt = requestedAt + 1.milliseconds),
                "0000002c4b5365637572654d6573736167652d5265636f766572794b657952657365742d4e65774b6579506f502d763100000005616c69" +
                "6365101112131415161718191a1b1c1d1e1f0000000000000003dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a" +
                "495ff84fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c40000019b76daa8010000019b864dbc0000000005" +
                "616c6963650000000570686f6e65",
                "99bd1e4dc5ec780bbbdd3a22ebdeb341977787ab895af7b8cd51da49ac32411b",
                "052a1c2e39b4311c1e099540481c98ae40967a70b5a912db1f726324303b8f275b01e9fe7ddd60d4e39174ef603ced35261a506daaa14e" +
                "e7399aa3f1d44e3907",
            ),
            "other eligibleAt" to CompletionVector(
                completion(eligibleAt = eligibleAt + 1.milliseconds),
                "0000002c4b5365637572654d6573736167652d5265636f766572794b657952657365742d4e65774b6579506f502d763100000005616c69" +
                "6365101112131415161718191a1b1c1d1e1f0000000000000003dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a" +
                "495ff84fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c40000019b76daa8000000019b864dbc0100000005" +
                "616c6963650000000570686f6e65",
                "c0c536fe0083bec004a7eeed2de7cec3900544fe1766532b73a607155a7db48a",
                "afffd62ae3f4a1ef673ccbd0a7bd450df13ed3210967e47f43fe3d0dc9a41cd995f25974fefa574e7cd789d92994f4c475963f00938466" +
                "05a611c9dd2bbe7504",
            ),
            "utf8" to CompletionVector(
                completion(user = encoded),
                "0000002c4b5365637572654d6573736167652d5265636f766572794b657952657365742d4e65774b6579506f502d763100000006c3a420" +
                "622f63101112131415161718191a1b1c1d1e1f0000000000000003dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd" +
                "6a495ff84fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c40000019b76daa8000000019b864dbc00000000" +
                "06c3a420622f63000000056465767e31",
                "a6ac361b3b7d64916c1035d12f36263446c49b1704d361c9a4e7840c29096443",
                "c16c29f6cc71ff1beaa30f65e27cd3c2dfc5009a1b75c8f9c33cc901f252353dcc60225b150358e6c6652bc25aef8b89ec1b10bfb8bb4d" +
                "1bb6bf293a1edda10f",
            ),
        )
    }

    private val cancellationVectors by lazy {
        mapOf(
            "base" to SignatureVector(
                cancellation(),
                "000000294b5365637572654d6573736167652d5265636f766572794b657952657365742d43616e63656c2d763100000005616c69636510" +
                "1112131415161718191a1b1c1d1e1f0000000000000003dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8" +
                "0000019b76daa8000000019b864dbc00",
                "9a2d5677995220bccffb1e12c980149f0f3520a8b86bada94ab085c17e85d3867571c881e052cb5a1a5cf86cb21aae44937a0e0c6bf043" +
                "213e88639cebbd0403",
            ),
            "other user" to SignatureVector(
                cancellation(user = UserId("bob")),
                "000000294b5365637572654d6573736167652d5265636f766572794b657952657365742d43616e63656c2d763100000003626f62101112" +
                "131415161718191a1b1c1d1e1f0000000000000003dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff80000" +
                "019b76daa8000000019b864dbc00",
                "72d026e9969158a8c9ba18cd49bb8de95921741108670618c49d5123fb39023a9ed1a3d9960d54d92d100dcf80cb6ded8c0ff9dfe11b3f" +
                "dfd88ded12e2d1fa03",
            ),
            "other reset" to SignatureVector(
                cancellation(resetId = reset2),
                "000000294b5365637572654d6573736167652d5265636f766572794b657952657365742d43616e63656c2d763100000005616c69636590" +
                "9192939495969798999a9b9c9d9e9f0000000000000003dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8" +
                "0000019b76daa8000000019b864dbc00",
                "9df3ce959671a8613acbd97a194b793b4fdb1348b837570d38977e18b8a46294e31826ebd6dc2e47c553786ad3df7af961dcf1cda245ef" +
                "a743ac940c69268901",
            ),
            "other epoch" to SignatureVector(
                cancellation(epoch = 4),
                "000000294b5365637572654d6573736167652d5265636f766572794b657952657365742d43616e63656c2d763100000005616c69636510" +
                "1112131415161718191a1b1c1d1e1f0000000000000004dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8" +
                "0000019b76daa8000000019b864dbc00",
                "c027e9621c6ddb89d0766cafaa497dd0709c5fd22e34cb0fbd5f7e68e4960d4dc3c7d8c2cebabfb976b2871c71ad0bf24b3048ff97ad9d" +
                "f00561a20cbf42830b",
            ),
            "other current" to SignatureVector(
                cancellation(current = recovery3),
                "000000294b5365637572654d6573736167652d5265636f766572794b657952657365742d43616e63656c2d763100000005616c69636510" +
                "1112131415161718191a1b1c1d1e1f000000000000000313d9908a70925992ed546007d27f50da68ba7217ef62ac3cca784529ff10471c" +
                "0000019b76daa8000000019b864dbc00",
                "92b8aaf68917dccc1fa58f21d076ec9087e28b7ec80351989710a75234a4b06ec12017c5c53c26933e0b6c91232dbd6ac0cf7a2308df30" +
                "33db849542e0283901",
            ),
            "other requestedAt" to SignatureVector(
                cancellation(requestedAt = requestedAt + 1.milliseconds),
                "000000294b5365637572654d6573736167652d5265636f766572794b657952657365742d43616e63656c2d763100000005616c69636510" +
                "1112131415161718191a1b1c1d1e1f0000000000000003dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8" +
                "0000019b76daa8010000019b864dbc00",
                "61d5d1a66c2e6dd864817673ff65ed13e635760bbeba3b0488621b68d2a3cf98cfd9ee13c334a994d54137a9738397aba54cf2a7b4e005" +
                "091bddd34ce25c8a0b",
            ),
            "other eligibleAt" to SignatureVector(
                cancellation(eligibleAt = eligibleAt + 1.milliseconds),
                "000000294b5365637572654d6573736167652d5265636f766572794b657952657365742d43616e63656c2d763100000005616c69636510" +
                "1112131415161718191a1b1c1d1e1f0000000000000003dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8" +
                "0000019b76daa8000000019b864dbc01",
                "c2bb93af1000e4185d47c7b47aa089af141e3bbed2cdb9ce052df00336d1ae690291e9ab9fbd3d2cb625845f11c448ef80e5735dcf49b3" +
                "2d32806b77bcbca60e",
            ),
            "utf8" to SignatureVector(
                cancellation(user = encoded.userId),
                "000000294b5365637572654d6573736167652d5265636f766572794b657952657365742d43616e63656c2d763100000006c3a420622f63" +
                "101112131415161718191a1b1c1d1e1f0000000000000003dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495f" +
                "f80000019b76daa8000000019b864dbc00",
                "f0d3a7879229a3a6f8d5f8940cefc544c55fe94ba0d9e5ebb39f4e8624cd9f5275f1353568a9722e9a4117b0afcb2c07ffea55ec199b34" +
                "42aa6638fd28b05e0f",
            ),
        )
    }

    private val queryVectors by lazy {
        mapOf(
            "base" to SignatureVector(
                query(),
                "0000002d4b5365637572654d6573736167652d5265636f766572794b6579526573657453746174757351756572792d763100000005616c" +
                "696365dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff80000019b76daa800",
                "3a57e93c34d3e752ff95a8ccfedbcafa26d5b1cfaf0e288e45f78bba376287f2fdee2ca4daada07ae3a158698494e46ae46da93432a274" +
                "b48a111eb562cff10b",
            ),
            "other user" to SignatureVector(
                query(user = UserId("bob")),
                "0000002d4b5365637572654d6573736167652d5265636f766572794b6579526573657453746174757351756572792d763100000003626f" +
                "62dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff80000019b76daa800",
                "ecbb1c3c606383f1af203cccc7ace30966bf165ed56f6644c8ab639b74d063b6717cdfbd8d397ccfed0224564e62f6da3728eab15e5282" +
                "f9149b3ba051a5210c",
            ),
            "other current" to SignatureVector(
                query(current = recovery3),
                "0000002d4b5365637572654d6573736167652d5265636f766572794b6579526573657453746174757351756572792d763100000005616c" +
                "69636513d9908a70925992ed546007d27f50da68ba7217ef62ac3cca784529ff10471c0000019b76daa800",
                "0544b543bea8caad676393e5eeb54139a1bb7b4c9be300382d8635b090ff5bd1ee9ca855b4a09e45c345acd36423ec8f14eb9eb90d173f" +
                "821726a3876f92490b",
            ),
            "other timestamp" to SignatureVector(
                query(timestamp = requestedAt + 1.milliseconds),
                "0000002d4b5365637572654d6573736167652d5265636f766572794b6579526573657453746174757351756572792d763100000005616c" +
                "696365dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff80000019b76daa801",
                "bd2afdb54275c53eee03d3bc24c19eafd2961691d672cf9808e635ca9ce4eac1dd2155b459fbcff6c4a991ea3eac042e6a494dec65ea7b" +
                "69db5746fb99368708",
            ),
            "utf8" to SignatureVector(
                query(user = encoded.userId),
                "0000002d4b5365637572654d6573736167652d5265636f766572794b6579526573657453746174757351756572792d763100000006c3a4" +
                "20622f63dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff80000019b76daa800",
                "77e7486c0511a2c2b172317af784b531681bd096d3943fcf3eb73986388e54213d1826bf6457bd965362b47078d97dcc7ccfc91af0486b" +
                "b8720aceec8403d607",
            ),
        )
    }

    @Test
    fun completionIsFrozen() {
        for ((name, vector) in completionVectors) {
            val authorization = vector.authorization
            val statement = authorization.statement
            assertEquals(vector.proofOfPossessionInput, RecoveryKeyReset.proofOfPossessionInput(statement).toHex(), name)
            assertEquals(vector.completionId, RecoveryKeyReset.completionId(statement).bytes.toHex(), name)
            assertEquals(vector.proofOfPossession, authorization.newKeyProofOfPossession.toHex(), name)
            assertTrue(RecoveryKeyReset.verifyNewKeyProofOfPossession(authorization), name)
        }
        assertEquals(completionVectors.size, completionVectors.values.map { it.completionId }.toSet().size)
    }

    @Test
    fun cancellationIsFrozen() {
        for ((name, vector) in cancellationVectors) {
            val authorization = vector.value
            assertEquals(vector.input, RecoveryKeyReset.cancellationInput(authorization.statement).toHex(), name)
            assertEquals(vector.signature, authorization.signature.toHex(), name)
            assertTrue(RecoveryKeyReset.verifyCancellation(authorization.statement.currentPublicKey, authorization), name)
        }
        assertEquals(cancellationVectors.size, cancellationVectors.values.map { it.input }.toSet().size)
    }

    @Test
    fun statusQueryIsFrozen() {
        for ((name, vector) in queryVectors) {
            val query = vector.value
            assertEquals(vector.input, RecoveryKeyReset.statusQueryInput(query.statement).toHex(), name)
            assertEquals(vector.signature, query.signature.toHex(), name)
            assertTrue(RecoveryKeyReset.verifyStatusQuery(query.statement.currentPublicKey, query), name)
        }
        assertEquals(queryVectors.size, queryVectors.values.map { it.input }.toSet().size)
    }

    @Test
    fun statusQueryTimestampIsTruncatedToMilliseconds() {
        val query = RecoveryKeyReset.statusQuery(recovery1, UserId("alice"), Instant.fromEpochSeconds(1_767_225_600, 999_999))
        assertEquals(requestedAt, query.statement.timestamp)
        assertEquals(queryVectors.getValue("base").signature, query.signature.toHex())
    }

    @Test
    fun everyCompletionFieldIsBoundByTheProofOfPossession() {
        val authorization = completion()
        val s = authorization.statement
        val r1 = s.currentPublicKey
        val r2 = s.newPublicKey
        val swapped = listOf(
            RecoveryKeyResetCompletionStatement(UserId("bob"), s.resetId, s.expectedEpoch, r1, r2, s.requestedAt, s.eligibleAt, bob),
            RecoveryKeyResetCompletionStatement(s.userId, reset2, s.expectedEpoch, r1, r2, s.requestedAt, s.eligibleAt, s.completer),
            RecoveryKeyResetCompletionStatement(s.userId, s.resetId, 4, r1, r2, s.requestedAt, s.eligibleAt, s.completer),
            RecoveryKeyResetCompletionStatement(s.userId, s.resetId, s.expectedEpoch, recovery3.publicKey, r2, s.requestedAt, s.eligibleAt, s.completer),
            RecoveryKeyResetCompletionStatement(s.userId, s.resetId, s.expectedEpoch, r1, recovery3.publicKey, s.requestedAt, s.eligibleAt, s.completer),
            RecoveryKeyResetCompletionStatement(s.userId, s.resetId, s.expectedEpoch, r1, r2, s.requestedAt + 1.milliseconds, s.eligibleAt, s.completer),
            RecoveryKeyResetCompletionStatement(s.userId, s.resetId, s.expectedEpoch, r1, r2, s.requestedAt, s.eligibleAt - 1.milliseconds, s.completer),
            RecoveryKeyResetCompletionStatement(s.userId, s.resetId, s.expectedEpoch, r1, r2, s.requestedAt, s.eligibleAt, tablet),
        )
        for (other in swapped) {
            val forged = RecoveryKeyResetCompletionAuthorization(other, authorization.newKeyProofOfPossession)
            assertFalse(RecoveryKeyReset.verifyNewKeyProofOfPossession(forged), other.toString())
            assertNotEquals(RecoveryKeyReset.completionId(s), RecoveryKeyReset.completionId(other))
        }
    }

    @Test
    fun everyCancellationAndQueryFieldIsBoundByTheSignature() {
        val authorization = cancellation()
        val s = authorization.statement
        val swapped = listOf(
            RecoveryKeyResetCancellationStatement(UserId("bob"), s.resetId, s.expectedEpoch, s.currentPublicKey, s.requestedAt, s.eligibleAt),
            RecoveryKeyResetCancellationStatement(s.userId, reset2, s.expectedEpoch, s.currentPublicKey, s.requestedAt, s.eligibleAt),
            RecoveryKeyResetCancellationStatement(s.userId, s.resetId, 4, s.currentPublicKey, s.requestedAt, s.eligibleAt),
            RecoveryKeyResetCancellationStatement(s.userId, s.resetId, s.expectedEpoch, recovery3.publicKey, s.requestedAt, s.eligibleAt),
            RecoveryKeyResetCancellationStatement(s.userId, s.resetId, s.expectedEpoch, s.currentPublicKey, s.requestedAt + 1.milliseconds, s.eligibleAt),
            RecoveryKeyResetCancellationStatement(s.userId, s.resetId, s.expectedEpoch, s.currentPublicKey, s.requestedAt, s.eligibleAt + 1.milliseconds),
        )
        for (other in swapped) {
            assertFalse(RecoveryKeyReset.verifyCancellation(recovery1.publicKey, RecoveryKeyResetCancellationAuthorization(other, authorization.signature)))
        }
        val q = query()
        val qs = q.statement
        for (other in listOf(
            RecoveryKeyResetStatusQueryStatement(UserId("bob"), qs.currentPublicKey, qs.timestamp),
            RecoveryKeyResetStatusQueryStatement(qs.userId, recovery3.publicKey, qs.timestamp),
            RecoveryKeyResetStatusQueryStatement(qs.userId, qs.currentPublicKey, qs.timestamp + 1.milliseconds),
        )) {
            assertFalse(RecoveryKeyReset.verifyStatusQuery(recovery1.publicKey, RecoveryKeyResetStatusQuery(other, q.signature)))
        }
    }

    @Test
    fun wrongKeysDoNotVerify() {
        assertFalse(RecoveryKeyReset.verifyCancellation(recovery2.publicKey, cancellation()))
        assertFalse(RecoveryKeyReset.verifyCancellation(ByteArray(31), cancellation()))
        assertFalse(RecoveryKeyReset.verifyStatusQuery(recovery2.publicKey, query()))
        // A proof of possession is made by the new key: signed by the current key it does not verify.
        val authorization = completion()
        val byCurrent = recovery1.sign(RecoveryKeyReset.proofOfPossessionInput(authorization.statement))
        assertFalse(RecoveryKeyReset.verifyNewKeyProofOfPossession(RecoveryKeyResetCompletionAuthorization(authorization.statement, byCurrent)))
        // The cancellation and the status query never verify for each other.
        val cancel = cancellation()
        val q = query()
        assertFalse(RecoveryKeyReset.verifyCancellation(recovery1.publicKey, RecoveryKeyResetCancellationAuthorization(cancel.statement, q.signature)))
        assertFalse(RecoveryKeyReset.verifyStatusQuery(recovery1.publicKey, RecoveryKeyResetStatusQuery(q.statement, cancel.signature)))
    }

    @Test
    fun domainsAreDistinctFromEveryOtherSignature() {
        val complete = completion()
        val cancel = cancellation()
        val q = query()
        val rotation = RecoveryKeyRotation.authorize(recovery1, recovery2, phone, 3, requestedAt, RequestNonce(ByteArray(16)))
        val revocation = RecoveryKeyRevocation.authorize(recovery1, phone, 3, requestedAt, RequestNonce(ByteArray(16)))
        val lastDeviceRecovery = LastDeviceRecovery.authorize(
            recovery1,
            DeviceAuthenticationKeyPair(recovery2.publicKey, ByteArray(32) { (0xA0 + it).toByte() }),
            LastDeviceRecoveryChallenge(phone, LastDeviceRecoveryChallengeId(ByteArray(16)), ByteArray(32), 3, requestedAt),
        )
        val registration = LastDeviceRecovery.registerKey(recovery1, UserId("alice"))
        val asKeyPair = DeviceAuthenticationKeyPair(recovery1.publicKey, ByteArray(32) { (0xC0 + it).toByte() })
        val newAsKeyPair = DeviceAuthenticationKeyPair(recovery2.publicKey, ByteArray(32) { (0xA0 + it).toByte() })
        val deviceRotation = DeviceAuthenticationRotation.create(asKeyPair, newAsKeyPair, phone, 3, requestedAt, RequestNonce(ByteArray(16)))
        val deviceRecovery = DeviceRecovery.prepare(newAsKeyPair, phone, tablet, requestedAt, RequestNonce(ByteArray(16)))
        val serverRequest = ServerRequest(
            phone, "PUT", ServerApiPaths.device(phone, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_RESET_COMPLETION),
            RecoveryKeyReset.proofOfPossessionInput(complete.statement),
        )
        val serverAuth = ServerRequestAuthentication.sign(asKeyPair, serverRequest, requestedAt, RequestNonce(ByteArray(16)))
        val foreign = listOf(
            rotation.currentKeySignature, rotation.newKeyProofOfPossession, revocation.signature,
            lastDeviceRecovery.recoverySignature, lastDeviceRecovery.proofOfPossession, registration.proofOfPossession,
            deviceRotation.authorizationSignature, deviceRotation.proofOfPossession, deviceRecovery.proofOfPossession, serverAuth.signature,
        )
        for (signature in foreign) {
            assertFalse(RecoveryKeyReset.verifyNewKeyProofOfPossession(RecoveryKeyResetCompletionAuthorization(complete.statement, signature)))
            assertFalse(RecoveryKeyReset.verifyCancellation(recovery1.publicKey, RecoveryKeyResetCancellationAuthorization(cancel.statement, signature)))
            assertFalse(RecoveryKeyReset.verifyStatusQuery(recovery1.publicKey, RecoveryKeyResetStatusQuery(q.statement, signature)))
        }
        // And the other way round: reset signatures verify for no other protocol.
        for (signature in listOf(complete.newKeyProofOfPossession, cancel.signature, q.signature)) {
            assertFalse(RecoveryKeyRotation.verifyCurrentKeySignature(recovery1.publicKey, RecoveryKeyRotationAuthorization(rotation.statement, signature, signature)))
            assertFalse(RecoveryKeyRotation.verifyNewKeyProofOfPossession(RecoveryKeyRotationAuthorization(rotation.statement, signature, signature)))
            assertFalse(RecoveryKeyRevocation.verifySignature(recovery1.publicKey, RecoveryKeyRevocationAuthorization(revocation.statement, signature)))
            assertFalse(LastDeviceRecovery.verifyRecoverySignature(recovery1.publicKey, LastDeviceRecoveryAuthorization(lastDeviceRecovery.statement, signature, signature)))
            assertFalse(LastDeviceRecovery.verifyProofOfPossession(LastDeviceRecoveryAuthorization(lastDeviceRecovery.statement, signature, signature)))
            assertFalse(LastDeviceRecovery.verifyKeyRegistration(LastDeviceRecoveryKeyRegistration(UserId("alice"), recovery1.publicKey, signature)))
            assertFalse(DeviceAuthenticationRotation.verifyAuthorization(recovery1.publicKey, DeviceAuthenticationRotationAuthorization(deviceRotation.statement, signature, signature)))
            assertFalse(DeviceAuthenticationRotation.verifyProofOfPossession(DeviceAuthenticationRotationAuthorization(deviceRotation.statement, signature, signature)))
            assertFalse(DeviceRecovery.verifyProofOfPossession(DeviceRecoveryRequest(phone, tablet, recovery2.publicKey, deviceRecovery.timestamp, deviceRecovery.nonce, signature)))
            assertFalse(ServerRequestAuthentication.verify(recovery1.publicKey, serverRequest, RequestAuthentication(serverAuth.timestamp, serverAuth.nonce, signature)))
        }
        val own = setOf(
            ProtocolConstants.RECOVERY_KEY_RESET_NEW_KEY_POP_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_RESET_ID_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_RESET_CANCEL_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_RESET_STATUS_QUERY_DOMAIN,
        )
        assertEquals(4, own.size)
        val others = setOf(
            ProtocolConstants.SERVER_AUTH_DOMAIN,
            ProtocolConstants.DEVICE_RECOVERY_DOMAIN,
            ProtocolConstants.DEVICE_RECOVERY_POP_DOMAIN,
            ProtocolConstants.DEVICE_RECOVERY_ID_DOMAIN,
            ProtocolConstants.DEVICE_AUTH_ROTATION_DOMAIN,
            ProtocolConstants.DEVICE_AUTH_ROTATION_POP_DOMAIN,
            ProtocolConstants.DEVICE_AUTH_ROTATION_ID_DOMAIN,
            ProtocolConstants.LAST_DEVICE_RECOVERY_DOMAIN,
            ProtocolConstants.LAST_DEVICE_RECOVERY_POP_DOMAIN,
            ProtocolConstants.LAST_DEVICE_RECOVERY_ID_DOMAIN,
            ProtocolConstants.LAST_DEVICE_RECOVERY_KEY_POP_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_ROTATION_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_ROTATION_NEW_KEY_POP_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_ROTATION_ID_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_REVOCATION_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_REVOCATION_ID_DOMAIN,
            ProtocolConstants.SAFETY_NUMBER_DOMAIN,
            ProtocolConstants.PROCESSED_MESSAGE_DOMAIN,
        )
        assertTrue(own.none { it in others })
    }

    @Test
    fun invalidValuesAreRejected() {
        val r1 = recovery1.publicKey
        val r2 = recovery2.publicKey
        val alice = UserId("alice")
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetCompletionStatement(alice, reset1, 3, r1, r2, requestedAt, eligibleAt, bob) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetCompletionStatement(alice, reset1, 3, r1, r1, requestedAt, eligibleAt, phone) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetCompletionStatement(alice, reset1, 3, ByteArray(31), r2, requestedAt, eligibleAt, phone) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetCompletionStatement(alice, reset1, 3, r1, ByteArray(33), requestedAt, eligibleAt, phone) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetCompletionStatement(alice, reset1, 0, r1, r2, requestedAt, eligibleAt, phone) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetCompletionStatement(alice, reset1, 3, r1, r2, requestedAt, requestedAt, phone) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetCompletionStatement(alice, reset1, 3, r1, r2, Instant.fromEpochMilliseconds(-1), eligibleAt, phone) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetCompletionStatement(alice, reset1, 3, r1, r2, requestedAt, Instant.fromEpochSeconds(1_800_000_000, 1), phone) }
        assertFailsWith<IllegalArgumentException> { completion(new = recovery1) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetCompletionAuthorization(completion().statement, ByteArray(63)) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetCompletionId(ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetCancellationStatement(alice, reset1, 0, r1, requestedAt, eligibleAt) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetCancellationStatement(alice, reset1, 3, ByteArray(31), requestedAt, eligibleAt) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetCancellationStatement(alice, reset1, 3, r1, eligibleAt, requestedAt) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetCancellationAuthorization(cancellation().statement, ByteArray(65)) }
        // The recovery key can only cancel a reset of itself.
        assertFailsWith<IllegalArgumentException> { RecoveryKeyReset.cancel(recovery2, pending()) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetStatusQueryStatement(alice, ByteArray(31), requestedAt) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetStatusQueryStatement(alice, r1, Instant.fromEpochMilliseconds(-1)) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetStatusQuery(query().statement, ByteArray(63)) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetId(ByteArray(15)) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetStatus.Pending(reset1, phone, requestedAt, requestedAt, 3, r1) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetStatus.Pending(reset1, phone, requestedAt, eligibleAt, 0, r1) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetStatus.Pending(reset1, phone, requestedAt, eligibleAt, 3, ByteArray(31)) }
    }

    @Test
    fun resetIdTextFormIsStrict() {
        assertEquals("EBESExQVFhcYGRobHB0eHw", reset1.encode())
        assertEquals(reset1, RecoveryKeyResetId.decode(reset1.encode()))
        for (bad in listOf("", "EBESExQVFhcYGRobHB0eHw==", "EBESExQVFhcYGRobHB0eH", "EBESExQVFhcYGRobHB0eHx", "EBESExQVFhcYGRobHB0e+w", " EBESExQVFhcYGRobHB0eHw")) {
            assertFailsWith<IllegalArgumentException>(bad) { RecoveryKeyResetId.decode(bad) }
        }
    }

    @Test
    fun maximumEpochIsRepresentable() {
        val authorization = completion(epoch = Long.MAX_VALUE)
        assertTrue(RecoveryKeyReset.verifyNewKeyProofOfPossession(authorization))
        assertTrue(RecoveryKeyReset.proofOfPossessionInput(authorization.statement).toHex().contains("7fffffffffffffff"))
    }

    @Test
    fun valuesAreDefensivelyCopiedAndRedacted() {
        val key = recovery1.publicKey
        val reset = RecoveryKeyResetStatus.Pending(reset1, phone, requestedAt, eligibleAt, 3, key)
        key.fill(0)
        reset.recoveryPublicKey.fill(0)
        assertEquals(recovery1.publicKey.toHex(), reset.recoveryPublicKey.toHex())
        val idBytes = ByteArray(16) { 7 }
        val id = RecoveryKeyResetId(idBytes)
        idBytes.fill(0)
        id.bytes.fill(0)
        assertEquals(RecoveryKeyResetId(ByteArray(16) { 7 }), id)
        val text = completion().toString() + cancellation() + query() + reset + reset1 +
            RecoveryKeyReset.completionId(completion().statement)
        for (secret in listOf(recovery1.publicKey.toHex(), recovery2.publicKey.toHex(), recovery1.encode(), recovery2.encode(), reset1.encode(), reset1.bytes.toHex())) {
            assertFalse(text.contains(secret), secret)
        }
    }
}
