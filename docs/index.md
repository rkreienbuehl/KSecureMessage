# KSecureMessage

KSecureMessage is a Kotlin Multiplatform library for Signal-style end-to-end
encrypted messaging. It builds on the X3DH and Double Ratchet primitives of
[Kodium](https://github.com/LivotovLabs/kodium) and adds what an application
needs around them: session lifecycle, identity trust and safety numbers,
reliable delivery with explicit acknowledgements, encrypted client storage,
device authentication towards the server, and recovery of lost device keys.

## What it is not

- **Not Signal** and not wire-compatible with Signal/libsignal. Wire,
  storage, authentication and recovery formats are KSecureMessage's own.
- **No comprehensive security audit** and no formal verification. The
  findings of a targeted security review, their fixes, the independent
  re-review results and the accepted residual risks are documented; see the
  [security model](security-review.md).
- **No metadata protection**: there is no sealed sender, the server sees who
  sends to whom and when.
- **Not exactly-once**: delivery is at least once; the application commits
  each received message ([application delivery](application-delivery.md)).
- **No background work**: the library has no scheduler, timer or implicit
  maintenance; the application calls everything explicitly
  ([application lifecycle](application-lifecycle.md)).

## Maturity

Pre-1.0 (`0.x`). The public API can still change between minor versions;
it is tracked by a checked-in API baseline. Wire, storage and protocol formats
are frozen by test vectors and change only through explicit new format
versions ([releasing](releasing.md)). Current version: `0.1.0`, the first
public release ([changelog](changelog.md)).

## Platforms

| Platform | Status |
|---|---|
| JVM, Android, macOS arm64, iOS simulator arm64, Linux x64, JS on Node.js | supported, tests executed |
| iOS arm64 (device), iOS x64, macOS x64, Windows x64 (mingwX64), JS in a browser | compile-only |
| Wasm (wasmJs) on Node.js and in a browser | compile-only, **runtime blocked** upstream |

Details, the test tasks behind each row and the Wasm blocker:
[supported platforms](supported-platforms.md).

## What to read first

1. [Getting started](getting-started.md): coordinates and the minimal
   send/receive/commit path.
2. [Application lifecycle](application-lifecycle.md): every call an
   application makes, and when.
3. [Security model](security-review.md): threat model and known limitations.
4. [Operating the server](operating-the-server.md): running the reference
   server.
5. [API reference](api-reference.md): generated from the sources.

Found a vulnerability? Report it privately, see
[security reporting](security-reporting.md).
