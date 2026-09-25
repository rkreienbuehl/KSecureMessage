# KSecureMessage ciphertext wire format

This document specifies how a KSecureMessage `CiphertextMessage` is encoded
into `EncryptedEnvelope.payload`. It is the KSecureMessage format, built on
Kodium's X3DH and Double Ratchet. It is **not** wire compatible with Signal or
libsignal.

Implementation: `core/protocol/.../protocol/CiphertextMessageCodec.kt`.

## Layering

Since milestone 8 the plaintext is a reliability frame (logical message ID
plus application body, or an acknowledgement), specified in
[message-reliability.md](message-reliability.md#reliability-frame-securepayload-v1).
It is encrypted, so this format does not change.

```text
plaintext
  -> ProtocolEngine (X3DH + Double Ratchet)
  -> CiphertextMessage (RatchetMessage | PreKeyMessage)
  -> CiphertextMessageCodec          <- this document
  -> EncryptedEnvelope.payload
  -> transport
```

The codec only frames data. It performs no cryptography and carries the
ratchet bytes unchanged. A future sealed-sender layer would wrap the encoded
bytes in an outer envelope; the inner format stays the same.

`EncryptedEnvelope.protocolVersion` (currently `1`) versions the envelope
metadata (routing fields). The wire version below versions the payload bytes.

## Conventions

- All integers are unsigned 32-bit, big-endian (network byte order), written
  `u32`. `u8` is one byte.
- Prekey IDs are `u32` values with the high bit clear: `0 .. 2^31-1`
  (`0x00000000 .. 0x7FFFFFFF`). Values `0x80000000 .. 0xFFFFFFFF` are invalid.
- Public keys are exactly 64 bytes: a 32-byte X25519 key followed by a 32-byte
  Ed25519 key. They have no length prefix.
- Ratchet bytes are Kodium's serialized ratchet message (header plus
  authenticated ciphertext). They are opaque to this format and prefixed with
  a `u32` length.
- There are no optional trailing fields and no padding. A message is exactly
  the bytes listed below.

## Header

| Offset | Size | Field        | Value                                   |
|-------:|-----:|--------------|-----------------------------------------|
| 0      | 1    | wire version | `0x01`                                  |
| 1      | 1    | message type | `0x01` RatchetMessage, `0x02` PreKeyMessage |

All other version and type values are reserved and rejected.

## RatchetMessage (type `0x01`)

A message on an established session.

| Offset | Size | Field         |
|-------:|-----:|---------------|
| 0      | 1    | version `0x01` |
| 1      | 1    | type `0x01`   |
| 2      | 4    | ratchet length `L` (`u32`, `1 ..= 262144`) |
| 6      | L    | ratchet bytes |

## PreKeyMessage (type `0x02`)

A ratchet message plus the X3DH data the recipient needs to create its side
of the session. The initiator sends these until it has decrypted a reply.

| Field                | Size | Notes |
|----------------------|-----:|-------|
| version              | 1    | `0x01` |
| type                 | 1    | `0x02` |
| signed prekey ID     | 4    | `u32`, high bit clear |
| one-time prekey flag | 1    | `0x00` absent, `0x01` present; other values invalid |
| one-time prekey ID   | 4    | `u32`, high bit clear; **only if flag is `0x01`** |
| identity key         | 64   | initiator's identity public key |
| ephemeral key        | 64   | initiator's ephemeral (base) public key |
| ratchet length `L`   | 4    | `u32`, `1 ..= 262144` |
| ratchet bytes        | L    | the first ratchet message |

The ratchet length starts at offset 135 without and 139 with a one-time
prekey ID.

## Size limits

| Limit                      | Value            |
|----------------------------|------------------|
| max ratchet bytes          | 262144 (256 KiB) |
| largest header (PreKeyMessage with one-time prekey) | 143 bytes |
| max encoded message        | 262287 bytes     |

Empty ratchet bytes (`L = 0`) are invalid.

## Decoding rules

Treat input as untrusted. A decoder must reject, and never partially accept:

1. input longer than the max encoded size (`MessageTooLarge`);
2. input shorter than 2 bytes (`MalformedMessage`);
3. a version other than `0x01` (`UnsupportedWireVersion`);
4. a type other than `0x01` / `0x02` (`UnknownMessageType`);
5. a ratchet length above 262144, including any value with the high bit set
   (`MessageTooLarge`), checked before reading the bytes;
6. truncated fields, a length larger than the remaining input, `L = 0`, a
   prekey ID with the high bit set, a flag other than `0x00`/`0x01`, or any
   trailing bytes (`MalformedMessage`).

All errors are `ProtocolException` subclasses. Their messages never contain
payload or key bytes.

Encoding is deterministic: the same message always produces the same bytes.

## Examples

RatchetMessage with ratchet bytes `DE AD BE EF`:

```text
01 01 00 00 00 04 DE AD BE EF
```

PreKeyMessage, signed prekey ID 7, one-time prekey ID 42, identity key
64 × `11`, ephemeral key 64 × `22`, ratchet bytes `CA FE`:

```text
01 02                 version, type
00 00 00 07           signed prekey ID
01                    one-time prekey present
00 00 00 2A           one-time prekey ID
11 × 64               identity key
22 × 64               ephemeral key
00 00 00 02           ratchet length
CA FE                 ratchet bytes
```

PreKeyMessage, signed prekey ID `0x01020304`, no one-time prekey, same keys,
ratchet bytes `AB CD EF`:

```text
01 02 01 02 03 04 00  version, type, signed prekey ID, flag absent
11 × 64               identity key
22 × 64               ephemeral key
00 00 00 03 AB CD EF  ratchet length, ratchet bytes
```

These vectors are pinned in `CiphertextMessageCodecTest`.

## Compatibility

- Version 1 is frozen. The test vectors must keep decoding and encoding to the
  same bytes.
- Any change to the layout, field set or limits that old decoders would
  misread needs a new wire version. Decoders reject versions they do not know.
- The X3DH and ratchet info strings (`KSecureMessage-X3DH-v1`,
  `KSecureMessage-Ratchet-v1`, see `ProtocolConstants`) are part of the
  protocol. Changing them breaks every session regardless of wire version.
