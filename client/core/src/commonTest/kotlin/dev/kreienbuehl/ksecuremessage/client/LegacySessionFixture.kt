package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair

/**
 * Frozen pre-S1 sessions (session initiation version 1, milestones 1–25)
 * between [ALICE] and [BOB], generated once with the pre-S1 engine code
 * (core:protocol's test-only LegacySessions) and never regenerated. They
 * stand for sessions an upgraded device still has in its storage.
 *
 * - [alicePendingV3] / [bobAcceptedV3]: state format 3 (milestones 7–25).
 *   Alice initiated with Bob's [bobSignedPreKey] and [bobOneTimePreKey] and
 *   sent one message ("legacy hi"); Bob accepted it; Alice has not seen a
 *   reply yet, so she still sends version 1 PreKeyMessages.
 * - [aliceEstablishedV1] / [bobEstablishedV1]: state format 1 (before
 *   milestone 6, so no stored origin). Bob replied ("legacy ack") and Alice
 *   decrypted it: established in both directions.
 *
 * No remote identity pins exist for these sessions (created before
 * milestone 5 pinning), so the fixture is installed without pins.
 */
internal object LegacySessionFixture {
    val aliceIdentity get() = LocalIdentity(hex(ALICEIDENTITYPUBLIC), hex(ALICEIDENTITYPRIVATE))
    val bobIdentity get() = LocalIdentity(hex(BOBIDENTITYPUBLIC), hex(BOBIDENTITYPRIVATE))

    /** The signed prekey Alice's pending initiation names. */
    val bobSignedPreKey get() = SignedPreKeyPair(
        SignedPreKeyId(1), hex(BOBSIGNEDPREKEYPUBLIC), hex(BOBSIGNEDPREKEYSIGNATURE), hex(BOBSIGNEDPREKEYPRIVATE),
    )

    /** The one-time prekey Alice's pending initiation names. */
    val bobOneTimePreKey get() = OneTimePreKeyPair(OneTimePreKeyId(100), hex(BOBONETIMEPREKEYPUBLIC), hex(BOBONETIMEPREKEYPRIVATE))

    val alicePendingV3 get() = SecureSession(BOB, hex(ALICEPENDINGV3))
    val bobAcceptedV3 get() = SecureSession(ALICE, hex(BOBACCEPTEDV3))
    val aliceEstablishedV1 get() = SecureSession(BOB, hex(ALICEESTABLISHEDV1))
    val bobEstablishedV1 get() = SecureSession(ALICE, hex(BOBESTABLISHEDV1))

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private const val ALICEIDENTITYPUBLIC =
        "bd21a84f7f745338683c3b8346bba67d0b21e827d70cbeba92ca5dfdb9755d08acd37e2b5a0a2b0ec18ca3f876f42b228a74" +
        "eb8d1d540949effcfe4db1a1fdd5"
    private const val ALICEIDENTITYPRIVATE =
        "9f2222c1dc944003a26fb501277ad28f449953e2e82828dc47bacbe3f9488d68"
    private const val BOBIDENTITYPUBLIC =
        "dc57e7db07b0367497b69a56d3392498c2a1de52625f8aca48147b5613f01e5a26c3c112a59affb9425c4bf7b7f6b0058ecc" +
        "cc341e793292c44e6b1b9b3b0768"
    private const val BOBIDENTITYPRIVATE =
        "5ae49cd35f99a539231cfd695b0c7a65e3dc667ab4e7f127edc013b491afff3a"
    private const val BOBSIGNEDPREKEYPUBLIC =
        "690b9bb5fb078ee0237ff89e5824690545ad60321ee1c27b5196e78e71fec808b12b8e5babf32c99e9cb1003f3f825a3ca88" +
        "c94e5de867557fe83e21d64bd7e9"
    private const val BOBSIGNEDPREKEYSIGNATURE =
        "7dad03329a2f77fe948ada78cb53eb6df630c8e4aee46c9075e985fb5c0da42742f1f11dfcf99c9a63f9c0c90252b8482e64" +
        "aacd0bc978ad555b2c8384cfa203"
    private const val BOBSIGNEDPREKEYPRIVATE =
        "50fcea84afd938cecf6f66b6df3a9c62dcdd04bbcc2ad52d3c4b8371c3cfd896"
    private const val BOBONETIMEPREKEYPUBLIC =
        "7d4c6f14ef05cb60f0515dff9a3db64f39eb5a56def255a92abc886f430fd51e6b6f5e5b966058ffa925f9793eaf35299a51" +
        "9f2d817f62cd6ebe809ee696854b"
    private const val BOBONETIMEPREKEYPRIVATE =
        "b70b9a7cdcff5e65893e22c82a23c886742375133e2fd76a8c6563cc3f0413b1"
    private const val ALICEPENDINGV3 =
        "0300000080bd21a84f7f745338683c3b8346bba67d0b21e827d70cbeba92ca5dfdb9755d08acd37e2b5a0a2b0ec18ca3f876" +
        "f42b228a74eb8d1d540949effcfe4db1a1fdd5dc57e7db07b0367497b69a56d3392498c2a1de52625f8aca48147b5613f01e" +
        "5a26c3c112a59affb9425c4bf7b7f6b0058ecccc341e793292c44e6b1b9b3b07680100000040bd21a84f7f745338683c3b83" +
        "46bba67d0b21e827d70cbeba92ca5dfdb9755d08acd37e2b5a0a2b0ec18ca3f876f42b228a74eb8d1d540949effcfe4db1a1" +
        "fdd5000000409f761472feca343cfdfe7285ef31dfc96bd0b8c25d0ee49ce9a6e5115b06963fb3028f823d959fb7b87fe75d" +
        "b7315424389b6dae3e10d30f777cf97fb0c2051000000001010000006401207af3467bbf87d8b327133b59ee756927194adc" +
        "ebfdbac3cba1c98fb216f4b200000000d4a1fd2b994dcc8efe8a5fc26b8b765463357f4fb4ef5236af4cfa5d090a84656401" +
        "690b9bb5fb078ee0237ff89e5824690545ad60321ee1c27b5196e78e71fec808b12b8e5babf32c99e9cb1003f3f825a3ca88" +
        "c94e5de867557fe83e21d64bd7e947a568e616d620361ba091810b3d0e4a01bc4400adf8bb7ecee7ed1c855ca7ae0117c842" +
        "3decc2ef596334506d5453c835139cb82a75bdca2f1160db4c23022b12000000000100000000000000000000000000000019" +
        "4b5365637572654d6573736167652d526174636865742d7631000007d0"
    private const val BOBACCEPTEDV3 =
        "0300000080bd21a84f7f745338683c3b8346bba67d0b21e827d70cbeba92ca5dfdb9755d08acd37e2b5a0a2b0ec18ca3f876" +
        "f42b228a74eb8d1d540949effcfe4db1a1fdd5dc57e7db07b0367497b69a56d3392498c2a1de52625f8aca48147b5613f01e" +
        "5a26c3c112a59affb9425c4bf7b7f6b0058ecccc341e793292c44e6b1b9b3b07680001207af3467bbf87d8b327133b59ee75" +
        "6927194adcebfdbac3cba1c98fb216f4b20100000001000000f47fcbf602d1937be8ffd81af37ba452474172252a553a3a6f" +
        "0bb7fb5a86926b7001047e61fefd898848020042e0b335e8ebd11fb1b09202e5b4451ad664c6a9ce29d0291b4db4bdef9538" +
        "1696a3bcb9be24cc04139daa7745fbdc980e5b739f4c599794cb6a7f00b5fc250251329ac3863afb023f81606bff5f54e2de" +
        "4b9ba45d6201fb796968a12f87f64c177b317ac0762633b9a95eb963cc32e49f4d37854ff8be0117c8423decc2ef59633450" +
        "6d5453c835139cb82a75bdca2f1160db4c23022b1200000000000000010000000000000000000000194b5365637572654d65" +
        "73736167652d526174636865742d7631000007d0"
    private const val ALICEESTABLISHEDV1 =
        "0100000080bd21a84f7f745338683c3b8346bba67d0b21e827d70cbeba92ca5dfdb9755d08acd37e2b5a0a2b0ec18ca3f876" +
        "f42b228a74eb8d1d540949effcfe4db1a1fdd5dc57e7db07b0367497b69a56d3392498c2a1de52625f8aca48147b5613f01e" +
        "5a26c3c112a59affb9425c4bf7b7f6b0058ecccc341e793292c44e6b1b9b3b076800000000f486760c1c12c95b8446af8486" +
        "64c0daff90434da55dcd90ae977c7ce86ed3189501d49121d97c551ad314cd852d82bd5af9284a8d6167e0b43be8a1332818" +
        "3e826563ef3d900946c2a21b238b493e076552fe210172bff9f2c2679a450685f0eb8e3e1aac48e5415eca6f6bf71a2e7d4b" +
        "c4e132fcea80a41f0372cb7e3a55f0c2bc0165c8476f3a3c17e65014a5bbdec3956ed58ee89f4c943acf9ebfd524f37ad4ef" +
        "01fdc20bfdd1a154b44d86c0a37967d3d876dd44ab1065d339452c9b9a76c371090000000000000001000000010000000000" +
        "0000194b5365637572654d6573736167652d526174636865742d7631000007d0"
    private const val BOBESTABLISHEDV1 =
        "0100000080bd21a84f7f745338683c3b8346bba67d0b21e827d70cbeba92ca5dfdb9755d08acd37e2b5a0a2b0ec18ca3f876" +
        "f42b228a74eb8d1d540949effcfe4db1a1fdd5dc57e7db07b0367497b69a56d3392498c2a1de52625f8aca48147b5613f01e" +
        "5a26c3c112a59affb9425c4bf7b7f6b0058ecccc341e793292c44e6b1b9b3b076800000000f47fcbf602d1937be8ffd81af3" +
        "7ba452474172252a553a3a6f0bb7fb5a86926b7001047e61fefd898848020042e0b335e8ebd11fb1b09202e5b4451ad664c6" +
        "a9ce29d0291b4db4bdef95381696a3bcb9be24cc04139daa7745fbdc980e5b739f4c599794cb6a7f00b5fc250251329ac386" +
        "3afb023f81606bff5f54e2de4b9ba45d6201fdc20bfdd1a154b44d86c0a37967d3d876dd44ab1065d339452c9b9a76c37109" +
        "0117c8423decc2ef596334506d5453c835139cb82a75bdca2f1160db4c23022b120000000100000001000000000000000000" +
        "0000194b5365637572654d6573736167652d526174636865742d7631000007d0"
}
