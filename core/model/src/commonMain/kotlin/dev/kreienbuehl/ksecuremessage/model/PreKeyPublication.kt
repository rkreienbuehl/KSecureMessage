package dev.kreienbuehl.ksecuremessage.model

import kotlinx.serialization.Serializable

/**
 * Public prekey material a device uploads to the server: its identity key,
 * its current signed prekey and a batch of one-time prekeys.
 *
 * Unlike a [PreKeyBundle], which is what a fetcher gets (at most one
 * one-time prekey), a publication carries the device's stable keys and one-time
 * prekey inventory separately. Public data only: private keys, session state
 * and plaintext never go into a publication.
 */
@Serializable
data class PreKeyPublication(
    val address: DeviceAddress,
    val identityKey: ByteArray,
    val signedPreKey: PublicSignedPreKey,
    val oneTimePreKeys: List<PublicOneTimePreKey>,
)
