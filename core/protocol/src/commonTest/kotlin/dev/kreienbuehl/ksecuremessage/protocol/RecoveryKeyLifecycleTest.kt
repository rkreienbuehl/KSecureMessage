package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Instant

private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

/**
 * Frozen vectors of recovery key rotation and revocation format version 1
 * (docs/recovery-key-lifecycle.md). Every recovery key transition a server
 * accepted depends on them. Computed independently (Python struct, hashlib
 * and the `cryptography` package's Ed25519) from the documented layout; the
 * same script first reproduced the frozen last-device recovery vectors.
 */
class RecoveryKeyLifecycleTest {
    private val recovery1 = LastDeviceRecoveryKey.fromSeed(ByteArray(32) { (0xC0 + it).toByte() })
    private val recovery2 = LastDeviceRecoveryKey.fromSeed(ByteArray(32) { (0xA0 + it).toByte() })
    private val recovery3 = LastDeviceRecoveryKey.fromSeed(ByteArray(32) { (0xE0 + it).toByte() })

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val tablet = DeviceAddress(UserId("alice"), DeviceId("tablet"))
    private val bobPhone = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val encoded = DeviceAddress(UserId("ä b/c"), DeviceId("dev~1"))
    private val timestamp = Instant.fromEpochMilliseconds(1_767_225_600_000)
    private val nonce1 = RequestNonce(ByteArray(16) { (0x30 + it).toByte() })
    private val nonce2 = RequestNonce(ByteArray(16) { (0xEF - it).toByte() })

    private fun rotation(
        authorizer: DeviceAddress = phone,
        current: LastDeviceRecoveryKey = recovery1,
        new: LastDeviceRecoveryKey = recovery2,
        epoch: Long = 3,
        timestamp: Instant = this.timestamp,
        nonce: RequestNonce = nonce1,
    ) = RecoveryKeyRotation.authorize(current, new, authorizer, epoch, timestamp, nonce)

    private fun revocation(
        authorizer: DeviceAddress = phone,
        current: LastDeviceRecoveryKey = recovery1,
        epoch: Long = 3,
        nonce: RequestNonce = nonce1,
    ) = RecoveryKeyRevocation.authorize(current, authorizer, epoch, timestamp, nonce)

    private class RotationVector(
        val authorization: RecoveryKeyRotationAuthorization,
        val authorizationInput: String,
        val proofOfPossessionInput: String,
        val rotationId: String,
        val currentKeySignature: String,
        val newKeyProofOfPossession: String,
    )

    private class RevocationVector(
        val authorization: RecoveryKeyRevocationAuthorization,
        val authorizationInput: String,
        val revocationId: String,
        val signature: String,
    )

    private val rotationVectors by lazy {
        mapOf(
            "base" to RotationVector(
                rotation(),
                "000000254b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d763100000005616c6963650000000561" +
                    "6c6963650000000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff84fd099ccd47d7893dfe9" +
                    "ec24414ecb0d9b5420232aad30d91c465be33cbe65c400000000000000030000019b76daa800303132333435363738393a3b3c3d3e3f",
                "0000002f4b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d4e65774b6579506f502d763100000005" +
                    "616c69636500000005616c6963650000000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8" +
                    "4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c400000000000000030000019b76daa80030313233343536" +
                    "3738393a3b3c3d3e3f",
                "d817e194fb443f23137abf56df39cce95018ba68a75c36185556804a8c4c2d93",
                "ae6e74184cade568f7e7433bc13a4652e959416b01cbddaeb93ac55fbd88c8e0f670fe628cdcdc796b96f583fc81351e3e3d352ace4573" +
                    "5c42b3235378a54506",
                "fc5d6475030528cd98f9b2acede9ada12c3bfbaed75e9c72e67112e3ad6b5d81c077a2845712e2adbcb324818a023dbb2dabef4851aa3b" +
                    "70150e789d3c346e03",
            ),
            "other user" to RotationVector(
                rotation(authorizer = bobPhone),
                "000000254b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d763100000003626f6200000003626f62" +
                    "0000000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff84fd099ccd47d7893dfe9ec24414e" +
                    "cb0d9b5420232aad30d91c465be33cbe65c400000000000000030000019b76daa800303132333435363738393a3b3c3d3e3f",
                "0000002f4b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d4e65774b6579506f502d763100000003" +
                    "626f6200000003626f620000000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff84fd099cc" +
                    "d47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c400000000000000030000019b76daa800303132333435363738393a" +
                    "3b3c3d3e3f",
                "6e5e1abe6231d54c7fe3a3b5fe05317aa93a0d1a73b2e51b46709bef35776908",
                "bbf644cc9216b8fd409061706f8ccf6e307f649cbc5c55368c52a02ad45708ca2b3ff620cf663df79751afc950a1a20c3ebfdf51ed87fa" +
                    "68143e26a0a2b17506",
                "cc744cf9cd8b4931ef075746e0a689f46eb98aa3d71043c26fb112f47b336e9a473f2f6232e032ec14db079076c8570e3c5b8ec7d6b394" +
                    "bad3de5a5de134ae0e",
            ),
            "other authorizer" to RotationVector(
                rotation(authorizer = tablet),
                "000000254b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d763100000005616c6963650000000561" +
                    "6c696365000000067461626c6574dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff84fd099ccd47d7893df" +
                    "e9ec24414ecb0d9b5420232aad30d91c465be33cbe65c400000000000000030000019b76daa800303132333435363738393a3b3c3d3e3f",
                "0000002f4b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d4e65774b6579506f502d763100000005" +
                    "616c69636500000005616c696365000000067461626c6574dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495f" +
                    "f84fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c400000000000000030000019b76daa800303132333435" +
                    "363738393a3b3c3d3e3f",
                "ff3af252da67517f164bbcb59d542d3297d91f2075620d95eb81ce6bd61b8db4",
                "a6d50b48d7874919865f4ea6d1104349dcdb1d392b4031970bc5bb4aeb7b540f7c20422886dd6a5df67fdbc3bf3c8317f365064cba166a" +
                    "4d76b609ce9addd003",
                "d0520dc913fcfc61a21a7b96d1478474170613e590fbf00ef812b22bdf35d404a4c87128d9c427a7dcef1f0a016fe32f7c0b6224524827" +
                    "8a2cc93842027c140a",
            ),
            "other current" to RotationVector(
                rotation(current = recovery3),
                "000000254b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d763100000005616c6963650000000561" +
                    "6c6963650000000570686f6e6513d9908a70925992ed546007d27f50da68ba7217ef62ac3cca784529ff10471c4fd099ccd47d7893dfe9" +
                    "ec24414ecb0d9b5420232aad30d91c465be33cbe65c400000000000000030000019b76daa800303132333435363738393a3b3c3d3e3f",
                "0000002f4b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d4e65774b6579506f502d763100000005" +
                    "616c69636500000005616c6963650000000570686f6e6513d9908a70925992ed546007d27f50da68ba7217ef62ac3cca784529ff10471c" +
                    "4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c400000000000000030000019b76daa80030313233343536" +
                    "3738393a3b3c3d3e3f",
                "d147fde84b65f9328a0e08c41ef7d3c5cf8fe4f9a54ab4c8f1468d4ae0b8a89c",
                "c7b00d06cc5769fed40f873674e8af46960399b3e257c63468cd5e330c51ded54cdd42e0f5133fdda5a78b08a2dcde8d68409bec2f9296" +
                    "3652beaa2081a07a02",
                "8bc016da035dc11144266b497ed5dd5dd624561aa40d8f3b021c991e9386ba3da5c275c43a2780d2e13c0ae288b28b6f20b9e58e48d788" +
                    "71dac7d2bc08470506",
            ),
            "other new" to RotationVector(
                rotation(new = recovery3),
                "000000254b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d763100000005616c6963650000000561" +
                    "6c6963650000000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff813d9908a70925992ed54" +
                    "6007d27f50da68ba7217ef62ac3cca784529ff10471c00000000000000030000019b76daa800303132333435363738393a3b3c3d3e3f",
                "0000002f4b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d4e65774b6579506f502d763100000005" +
                    "616c69636500000005616c6963650000000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8" +
                    "13d9908a70925992ed546007d27f50da68ba7217ef62ac3cca784529ff10471c00000000000000030000019b76daa80030313233343536" +
                    "3738393a3b3c3d3e3f",
                "b4d517c779f0f33b3d4045709fd039e9522d10fe346820bb39b02a5e122f3926",
                "3e718ddb695372cf7952ff4b8645569b9c76918eea86a13fc31d68cd092460a6f6193c3a75276eb0a4fa50d8479442661c8258d1a744dc" +
                    "04325e8df8f5a8f30d",
                "ceee78e49265efa8692e262886e4e7aabe300bb2f6d856436cddd70784aceec68d734c4f03a11f84acd2a0eddfe9cc87451cc19a01a80a" +
                    "3fe46b0aa229b29b06",
            ),
            "other epoch" to RotationVector(
                rotation(epoch = 4),
                "000000254b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d763100000005616c6963650000000561" +
                    "6c6963650000000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff84fd099ccd47d7893dfe9" +
                    "ec24414ecb0d9b5420232aad30d91c465be33cbe65c400000000000000040000019b76daa800303132333435363738393a3b3c3d3e3f",
                "0000002f4b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d4e65774b6579506f502d763100000005" +
                    "616c69636500000005616c6963650000000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8" +
                    "4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c400000000000000040000019b76daa80030313233343536" +
                    "3738393a3b3c3d3e3f",
                "dadb3764104bf323ec865d6c252175ae0ef84a00c1de877b25799b6841d5d5ff",
                "5ceba22bbd0fd9074c0f50edc32556f106618abbbe5181181ca6b605c7cc8d3952931d5f240934025ae5dfc46cf9d6806e1d221ca50675" +
                    "952c2275f8c01ab50f",
                "7cbc259cf818dacbe923394d2b8c8c9d1e9fdb398ca35400e18a182ff4969a2a29434a2ab08e8fc284c7e1072987672cd7d7dce2a48637" +
                    "0ab7903c25b47a3c0f",
            ),
            "other timestamp" to RotationVector(
                rotation(timestamp = timestamp + 1.milliseconds),
                "000000254b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d763100000005616c6963650000000561" +
                    "6c6963650000000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff84fd099ccd47d7893dfe9" +
                    "ec24414ecb0d9b5420232aad30d91c465be33cbe65c400000000000000030000019b76daa801303132333435363738393a3b3c3d3e3f",
                "0000002f4b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d4e65774b6579506f502d763100000005" +
                    "616c69636500000005616c6963650000000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8" +
                    "4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c400000000000000030000019b76daa80130313233343536" +
                    "3738393a3b3c3d3e3f",
                "cc1afb41864059e660c3c54e0f423327f4c90b02725d5aaf526690327a9e8eba",
                "60623e34093be7fd69640fb68f961f32480343afb8437086dfe1b1b4d9bfb5eef0da388db0582432afbe20796bf0bad68e34c958e1ff28" +
                    "51bfe2f2422fd58901",
                "0c79123b4b8fbdb0b1df5b9b0df8cdd812cc39356b681d95c34bec9518e4d441af5119dc9127f90b7a01fcf6dd617762bf182c30685f0d" +
                    "d16054e80b16efc206",
            ),
            "other nonce" to RotationVector(
                rotation(nonce = nonce2),
                "000000254b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d763100000005616c6963650000000561" +
                    "6c6963650000000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff84fd099ccd47d7893dfe9" +
                    "ec24414ecb0d9b5420232aad30d91c465be33cbe65c400000000000000030000019b76daa800efeeedecebeae9e8e7e6e5e4e3e2e1e0",
                "0000002f4b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d4e65774b6579506f502d763100000005" +
                    "616c69636500000005616c6963650000000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8" +
                    "4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c400000000000000030000019b76daa800efeeedecebeae9" +
                    "e8e7e6e5e4e3e2e1e0",
                "2e43577ecf2a0389af11fa707c8442df5d1c117fc746c8087c017bae10a761c9",
                "6b7bd7056a78fd6be4fd38401eafa883971f4f6dd625f70f7f504246783121a9c2300bcd285176e4e94955a7be197e012917be97f47867" +
                    "d0a57a54ee0f9a1409",
                "0e7a6faa9fbd6e65abd38abde3fe73a376cefa26d97d995951c453b100f4c8b8b27d7fb5c4be53dd613c4a7b0e177126e6b742e559ecae" +
                    "2b825630aa182a050d",
            ),
            "utf8" to RotationVector(
                rotation(authorizer = encoded),
                "000000254b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d763100000006c3a420622f6300000006" +
                    "c3a420622f63000000056465767e31dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff84fd099ccd47d7893" +
                    "dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c400000000000000030000019b76daa800303132333435363738393a3b3c3d3e" +
                    "3f",
                "0000002f4b5365637572654d6573736167652d5265636f766572794b6579526f746174696f6e2d4e65774b6579506f502d763100000006" +
                    "c3a420622f6300000006c3a420622f63000000056465767e31dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a49" +
                    "5ff84fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c400000000000000030000019b76daa8003031323334" +
                    "35363738393a3b3c3d3e3f",
                "40bbd10cd3cba9dfab02ad3d2c430e56ca8b638595f819340624e8512123db0d",
                "f7a5cf044c50052fe04c57908e29a6fb18e0e2e40794e5cc991ff11d045eaa4d4ede42ee120b1f5a6f43b398ed998791c90f8debe64813" +
                    "371684889063d5b001",
                "d7c4fafc4b1efc89f8836ce151eeb6b11301070b98aa58f4a8b45dc3a76a1f8810d25d2debbe89fe6e860131308f5a82c3971e2970bf73" +
                    "92ff95811ecb432d06",
            ),
        )
    }

    private val revocationVectors by lazy {
        mapOf(
            "base" to RevocationVector(
                revocation(),
                "000000274b5365637572654d6573736167652d5265636f766572794b65795265766f636174696f6e2d763100000005616c696365000000" +
                    "05616c6963650000000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff80000000000000003" +
                    "0000019b76daa800303132333435363738393a3b3c3d3e3f",
                "983119e0fa7491ac88da1a68febcf1865b77331875ce8a558b2d2a753d14f8cf",
                "4fe47411e5561e6490bdae171dc52aec9a3ec5c94c7c6c305c3428f4d751d0080c8491251cfdf33b32fdb89116a4913627a266e315e241" +
                    "490efd2f9f2f0b9d08",
            ),
            "other epoch" to RevocationVector(
                revocation(epoch = 4),
                "000000274b5365637572654d6573736167652d5265636f766572794b65795265766f636174696f6e2d763100000005616c696365000000" +
                    "05616c6963650000000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff80000000000000004" +
                    "0000019b76daa800303132333435363738393a3b3c3d3e3f",
                "57209f78f7e0d00ae0769db428fe22ec0bd4d2b96e86317b4ebff0d0fcd631e8",
                "fe99aad4644c50a1217992babe481782de834b3a9f68321782cece6df640b7dbd8014c1cc92874dc611038808b79d1417fa0de4c7a43ff" +
                    "73aee41adc987d8a0f",
            ),
            "other authorizer" to RevocationVector(
                revocation(authorizer = tablet),
                "000000274b5365637572654d6573736167652d5265636f766572794b65795265766f636174696f6e2d763100000005616c696365000000" +
                    "05616c696365000000067461626c6574dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff800000000000000" +
                    "030000019b76daa800303132333435363738393a3b3c3d3e3f",
                "8536b49c3e938f5dbeb4e893a5eb059d5ff87bb64c28727f4a1e0c7af1e00309",
                "a83c1738123d55f22ea980f21b82ec2066b7a7846aaa83d4e033d361bddcbebec3f07fc91c792ae77c134570332b2c5e4d2b8e5662d364" +
                    "822222c31203069006",
            ),
            "other nonce" to RevocationVector(
                revocation(nonce = nonce2),
                "000000274b5365637572654d6573736167652d5265636f766572794b65795265766f636174696f6e2d763100000005616c696365000000" +
                    "05616c6963650000000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff80000000000000003" +
                    "0000019b76daa800efeeedecebeae9e8e7e6e5e4e3e2e1e0",
                "4f77f87b97b02059bf99718164a188fd7c1ccc495f2eff07ab0239b881043789",
                "5efdc9940399598b4b6e3a13dee89109e452c15f1d0b12f31d24af6d2bacfb6d95d5256385bd72f130144fbe96912f2fa591a155723658" +
                    "a6e7900664e168fa03",
            ),
            "utf8" to RevocationVector(
                revocation(authorizer = encoded),
                "000000274b5365637572654d6573736167652d5265636f766572794b65795265766f636174696f6e2d763100000006c3a420622f630000" +
                    "0006c3a420622f63000000056465767e31dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8000000000000" +
                    "00030000019b76daa800303132333435363738393a3b3c3d3e3f",
                "58a44a13f0f42736e66a43e135c8441c863b28cd64d5e19c3857051bb5cb2366",
                "80e1a253e5c21eace65b36123947936f50c12dc797f3c1bdceab5f15c68557acabc3dbd6b7cede2066562ab31793d2efe50df1aa71173e" +
                    "400560f260e867320e",
            ),
        )
    }

    @Test
    fun keysAreTheDocumentedOnes() {
        assertEquals("4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c4", recovery2.publicKey.toHex())
        assertEquals("13d9908a70925992ed546007d27f50da68ba7217ef62ac3cca784529ff10471c", recovery3.publicKey.toHex())
    }

    @Test
    fun rotationIsFrozen() {
        for ((name, vector) in rotationVectors) {
            val authorization = vector.authorization
            val statement = authorization.statement
            assertEquals(vector.authorizationInput, RecoveryKeyRotation.authorizationInput(statement).toHex(), name)
            assertEquals(vector.proofOfPossessionInput, RecoveryKeyRotation.proofOfPossessionInput(statement).toHex(), name)
            assertEquals(vector.rotationId, RecoveryKeyRotation.rotationId(statement).bytes.toHex(), name)
            assertEquals(vector.currentKeySignature, authorization.currentKeySignature.toHex(), name)
            assertEquals(vector.newKeyProofOfPossession, authorization.newKeyProofOfPossession.toHex(), name)
            assertTrue(RecoveryKeyRotation.verifyCurrentKeySignature(statement.currentPublicKey, authorization), name)
            assertTrue(RecoveryKeyRotation.verifyNewKeyProofOfPossession(authorization), name)
        }
        assertEquals(rotationVectors.size, rotationVectors.values.map { it.rotationId }.toSet().size)
    }

    @Test
    fun revocationIsFrozen() {
        for ((name, vector) in revocationVectors) {
            val authorization = vector.authorization
            val statement = authorization.statement
            assertEquals(vector.authorizationInput, RecoveryKeyRevocation.authorizationInput(statement).toHex(), name)
            assertEquals(vector.revocationId, RecoveryKeyRevocation.revocationId(statement).bytes.toHex(), name)
            assertEquals(vector.signature, authorization.signature.toHex(), name)
            assertTrue(RecoveryKeyRevocation.verifySignature(statement.currentPublicKey, authorization), name)
        }
        assertEquals(revocationVectors.size, revocationVectors.values.map { it.revocationId }.toSet().size)
    }

    @Test
    fun timestampIsTruncatedToMilliseconds() {
        val authorization = RecoveryKeyRotation.authorize(recovery1, recovery2, phone, 3, Instant.fromEpochSeconds(1_767_225_600, 999_999), nonce1)
        assertEquals(timestamp, authorization.statement.timestamp)
        assertEquals(
            rotationVectors.getValue("base").rotationId,
            RecoveryKeyRotation.rotationId(authorization.statement).bytes.toHex(),
        )
    }

    @Test
    fun everyRotationFieldIsBoundByBothSignatures() {
        val authorization = rotation()
        val s = authorization.statement
        val swapped = listOf(
            RecoveryKeyRotationStatement(UserId("bob"), bobPhone, s.currentPublicKey, s.newPublicKey, s.expectedEpoch, s.timestamp, s.nonce),
            RecoveryKeyRotationStatement(s.userId, tablet, s.currentPublicKey, s.newPublicKey, s.expectedEpoch, s.timestamp, s.nonce),
            RecoveryKeyRotationStatement(s.userId, s.authorizer, recovery3.publicKey, s.newPublicKey, s.expectedEpoch, s.timestamp, s.nonce),
            RecoveryKeyRotationStatement(s.userId, s.authorizer, s.currentPublicKey, recovery3.publicKey, s.expectedEpoch, s.timestamp, s.nonce),
            RecoveryKeyRotationStatement(s.userId, s.authorizer, s.currentPublicKey, s.newPublicKey, 4, s.timestamp, s.nonce),
            RecoveryKeyRotationStatement(s.userId, s.authorizer, s.currentPublicKey, s.newPublicKey, s.expectedEpoch, s.timestamp + 1.milliseconds, s.nonce),
            RecoveryKeyRotationStatement(s.userId, s.authorizer, s.currentPublicKey, s.newPublicKey, s.expectedEpoch, s.timestamp, nonce2),
        )
        for (other in swapped) {
            val forged = RecoveryKeyRotationAuthorization(other, authorization.currentKeySignature, authorization.newKeyProofOfPossession)
            assertFalse(RecoveryKeyRotation.verifyCurrentKeySignature(recovery1.publicKey, forged), other.toString())
            assertFalse(RecoveryKeyRotation.verifyNewKeyProofOfPossession(forged), other.toString())
            assertNotEquals(RecoveryKeyRotation.rotationId(s), RecoveryKeyRotation.rotationId(other))
        }
    }

    @Test
    fun everyRevocationFieldIsBoundByTheSignature() {
        val authorization = revocation()
        val s = authorization.statement
        val swapped = listOf(
            RecoveryKeyRevocationStatement(UserId("bob"), bobPhone, s.currentPublicKey, s.expectedEpoch, s.timestamp, s.nonce),
            RecoveryKeyRevocationStatement(s.userId, tablet, s.currentPublicKey, s.expectedEpoch, s.timestamp, s.nonce),
            RecoveryKeyRevocationStatement(s.userId, s.authorizer, recovery3.publicKey, s.expectedEpoch, s.timestamp, s.nonce),
            RecoveryKeyRevocationStatement(s.userId, s.authorizer, s.currentPublicKey, 4, s.timestamp, s.nonce),
            RecoveryKeyRevocationStatement(s.userId, s.authorizer, s.currentPublicKey, s.expectedEpoch, s.timestamp + 1.milliseconds, s.nonce),
            RecoveryKeyRevocationStatement(s.userId, s.authorizer, s.currentPublicKey, s.expectedEpoch, s.timestamp, nonce2),
        )
        for (other in swapped) {
            assertFalse(RecoveryKeyRevocation.verifySignature(recovery1.publicKey, RecoveryKeyRevocationAuthorization(other, authorization.signature)))
            assertNotEquals(RecoveryKeyRevocation.revocationId(s), RecoveryKeyRevocation.revocationId(other))
        }
    }

    @Test
    fun wrongKeysAndSwappedSignaturesDoNotVerify() {
        val authorization = rotation()
        assertFalse(RecoveryKeyRotation.verifyCurrentKeySignature(recovery2.publicKey, authorization))
        assertFalse(RecoveryKeyRotation.verifyCurrentKeySignature(recovery3.publicKey, authorization))
        assertFalse(RecoveryKeyRotation.verifyCurrentKeySignature(ByteArray(31), authorization))
        val swapped = RecoveryKeyRotationAuthorization(authorization.statement, authorization.newKeyProofOfPossession, authorization.currentKeySignature)
        assertFalse(RecoveryKeyRotation.verifyCurrentKeySignature(recovery1.publicKey, swapped))
        assertFalse(RecoveryKeyRotation.verifyNewKeyProofOfPossession(swapped))
        // A revocation signature is not a rotation signature over the same key and epoch, and the other way round.
        val revoke = revocation()
        assertFalse(
            RecoveryKeyRotation.verifyCurrentKeySignature(
                recovery1.publicKey,
                RecoveryKeyRotationAuthorization(authorization.statement, revoke.signature, authorization.newKeyProofOfPossession),
            ),
        )
        assertFalse(RecoveryKeyRevocation.verifySignature(recovery1.publicKey, RecoveryKeyRevocationAuthorization(revoke.statement, authorization.currentKeySignature)))
        assertFalse(RecoveryKeyRevocation.verifySignature(recovery2.publicKey, revoke))
    }

    @Test
    fun domainsAreDistinctFromEveryOtherSignature() {
        val authorization = rotation()
        val revoke = revocation()
        val lastDeviceRecovery = LastDeviceRecovery.authorize(
            recovery1,
            DeviceAuthenticationKeyPair(recovery2.publicKey, ByteArray(32) { (0xA0 + it).toByte() }),
            LastDeviceRecoveryChallenge(phone, LastDeviceRecoveryChallengeId(ByteArray(16)), ByteArray(32), 3, timestamp),
        )
        val registration = LastDeviceRecovery.registerKey(recovery1, UserId("alice"))
        val asKeyPair = DeviceAuthenticationKeyPair(recovery1.publicKey, ByteArray(32) { (0xC0 + it).toByte() })
        val newAsKeyPair = DeviceAuthenticationKeyPair(recovery2.publicKey, ByteArray(32) { (0xA0 + it).toByte() })
        val deviceRotation = DeviceAuthenticationRotation.create(asKeyPair, newAsKeyPair, phone, 3, timestamp, nonce1)
        val deviceRecovery = DeviceRecovery.prepare(newAsKeyPair, phone, tablet, timestamp, nonce1)
        val serverRequest = ServerRequest(phone, "PUT", ServerApiPaths.device(phone, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_ROTATION), RecoveryKeyRotation.authorizationInput(authorization.statement))
        val serverAuth = ServerRequestAuthentication.sign(asKeyPair, serverRequest, timestamp, nonce1)
        val foreign = listOf(
            lastDeviceRecovery.recoverySignature, lastDeviceRecovery.proofOfPossession, registration.proofOfPossession,
            deviceRotation.authorizationSignature, deviceRotation.proofOfPossession, deviceRecovery.proofOfPossession, serverAuth.signature,
        )
        for (signature in foreign) {
            val forged = RecoveryKeyRotationAuthorization(authorization.statement, signature, signature)
            assertFalse(RecoveryKeyRotation.verifyCurrentKeySignature(recovery1.publicKey, forged))
            assertFalse(RecoveryKeyRotation.verifyNewKeyProofOfPossession(forged))
            assertFalse(RecoveryKeyRevocation.verifySignature(recovery1.publicKey, RecoveryKeyRevocationAuthorization(revoke.statement, signature)))
        }
        // And the other way round: recovery key lifecycle signatures verify for no other protocol.
        for (signature in listOf(authorization.currentKeySignature, authorization.newKeyProofOfPossession, revoke.signature)) {
            assertFalse(LastDeviceRecovery.verifyRecoverySignature(recovery1.publicKey, LastDeviceRecoveryAuthorization(lastDeviceRecovery.statement, signature, signature)))
            assertFalse(LastDeviceRecovery.verifyProofOfPossession(LastDeviceRecoveryAuthorization(lastDeviceRecovery.statement, signature, signature)))
            assertFalse(LastDeviceRecovery.verifyKeyRegistration(LastDeviceRecoveryKeyRegistration(UserId("alice"), recovery1.publicKey, signature)))
            assertFalse(DeviceAuthenticationRotation.verifyAuthorization(recovery1.publicKey, DeviceAuthenticationRotationAuthorization(deviceRotation.statement, signature, signature)))
            assertFalse(DeviceAuthenticationRotation.verifyProofOfPossession(DeviceAuthenticationRotationAuthorization(deviceRotation.statement, signature, signature)))
            assertFalse(DeviceRecovery.verifyProofOfPossession(DeviceRecoveryRequest(phone, tablet, recovery2.publicKey, deviceRecovery.timestamp, deviceRecovery.nonce, signature)))
            assertFalse(ServerRequestAuthentication.verify(recovery1.publicKey, serverRequest, RequestAuthentication(serverAuth.timestamp, serverAuth.nonce, signature)))
        }
        val own = setOf(
            ProtocolConstants.RECOVERY_KEY_ROTATION_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_ROTATION_NEW_KEY_POP_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_ROTATION_ID_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_REVOCATION_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_REVOCATION_ID_DOMAIN,
        )
        assertEquals(5, own.size)
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
            ProtocolConstants.SAFETY_NUMBER_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_RESET_NEW_KEY_POP_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_RESET_ID_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_RESET_CANCEL_DOMAIN,
            ProtocolConstants.RECOVERY_KEY_RESET_STATUS_QUERY_DOMAIN,
        )
        assertTrue(own.none { it in others })
    }

    @Test
    fun invalidValuesAreRejected() {
        val r1 = recovery1.publicKey
        val r2 = recovery2.publicKey
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRotationStatement(UserId("alice"), bobPhone, r1, r2, 3, timestamp, nonce1) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRotationStatement(UserId("alice"), phone, r1, r1, 3, timestamp, nonce1) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRotationStatement(UserId("alice"), phone, ByteArray(31), r2, 3, timestamp, nonce1) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRotationStatement(UserId("alice"), phone, r1, ByteArray(33), 3, timestamp, nonce1) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRotationStatement(UserId("alice"), phone, r1, r2, 0, timestamp, nonce1) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRotationStatement(UserId("alice"), phone, r1, r2, 3, Instant.fromEpochMilliseconds(-1), nonce1) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRotationStatement(UserId("alice"), phone, r1, r2, 3, Instant.fromEpochSeconds(1, 1), nonce1) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRotation.authorize(recovery1, recovery1, phone, 3, timestamp) }
        val statement = rotation().statement
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRotationAuthorization(statement, ByteArray(63), ByteArray(64)) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRotationAuthorization(statement, ByteArray(64), ByteArray(65)) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRotationId(ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRevocationStatement(UserId("alice"), bobPhone, r1, 3, timestamp, nonce1) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRevocationStatement(UserId("alice"), phone, ByteArray(31), 3, timestamp, nonce1) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRevocationStatement(UserId("alice"), phone, r1, 0, timestamp, nonce1) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRevocationAuthorization(revocation().statement, ByteArray(63)) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyRevocationId(ByteArray(33)) }
    }

    @Test
    fun maximumEpochIsRepresentable() {
        val authorization = rotation(epoch = Long.MAX_VALUE)
        assertTrue(RecoveryKeyRotation.verifyCurrentKeySignature(recovery1.publicKey, authorization))
        assertTrue(RecoveryKeyRotation.authorizationInput(authorization.statement).toHex().contains("7fffffffffffffff"))
    }

    @Test
    fun valuesAreDefensivelyCopiedAndRedacted() {
        val key = recovery1.publicKey
        val statement = RecoveryKeyRotationStatement(UserId("alice"), phone, key, recovery2.publicKey, 3, timestamp, nonce1)
        key.fill(0)
        statement.currentPublicKey.fill(0)
        assertEquals(recovery1.publicKey.toHex(), statement.currentPublicKey.toHex())
        val text = rotation().toString() + revocation().toString() + RecoveryKeyRotation.rotationId(statement)
        assertFalse(text.contains(recovery1.publicKey.toHex()))
        assertFalse(text.contains(recovery1.encode()))
    }
}
