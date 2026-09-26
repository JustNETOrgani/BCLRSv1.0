# BCLRSpaper

A Java implementation of a BN254-compatible ring-signature cryptographic workflow, centered around the `secureChanelFree` API and a JPBC-based pairing setup. The project demonstrates user registration, blinded partial private-key extraction, stateless key derivation, ring signing, verification, and linkability checks.

## What this project implements

- KGC setup and pairing initialization through `CryptoContext`
- User public-value generation and designated parameter extraction in `KeyManagementService`
- Long-term private-key recovery and a stateless per-period ephemeral key derivation in `PeriodKeyService` for key renewal (future) and key access (past/previous key).
- Ring-signature generation and verification in `RingSignatureService`
- Hashing utilities shared across the scheme in `HashingService`
- A runnable demonstration in `bclrspaper.testRingSignature`

The code is structured as a service-oriented cryptographic workflow rather than a single monolithic class, and the public entry point for the flow is `secureChanelFree`.

## Project layout

- `bclrspaper/` – core Java implementation
  - `secureChanelFree.java` – main workflow API
  - `CryptoContext.java` – pairing, generators, and master keys
  - `KeyManagementService.java` – user registration/key extraction logic
  - `PeriodKeyService.java` – forward-security / period key derivation
  - `RingSignatureService.java` – ring signing and verification
  - `HashingService.java` – shared hashing logic
  - `CryptoBenchmark.java` – benchmarking utilities
  - `testRingSignature.java` – end-to-end demo
- `CryptoParameters/` – JPBC parameter file
- `jars/` – project dependencies
- `Smart_Contract/` – Solidity contract and helper scripts

## Requirements

- Java JDK
- JPBC dependency jars already included under `jars/`
- The project expects the pairing parameter file to be available at `CryptoParameters/params.properties`

## Build

From the project root, compile all Java sources and place the classes in the `out` directory:

```powershell
javac -cp "jars/*" -d out $(Get-ChildItem -Recurse -Filter *.java | ForEach-Object { $_.FullName })
```

## Run the demo workflow

Run the built demonstration that exercises setup, key extraction, ring signing, verification, forward-security key derivation, and linkability checks:

```powershell
java -cp "out;jars/*" bclrspaper.testRingSignature
```

## Typical workflow in the demo

The `testRingSignature` class performs the following:

1. Calls `secureChanelFree.setup()`
2. Generates user public values for a user ID and time period
3. Extracts designated user parameters and recovers the long-term secret key
4. Derives a period key for a given `$T_D$`
5. Creates a ring signature over a message and event string
6. Verifies the signature successfully
7. Demonstrates tamper detection, future/past key access, and linkability behavior

## Notes

- The implementation uses the BN254-compatible JPBC pairing configuration and Ethereum-style generator conventions.
- The ring-signature flow is intentionally designed around a stateless period-key derivation model: keys can be regenerated for different periods without carrying sensitive state between them.
- The `CryptoBenchmark` class is available for timing and cryptographic micro-benchmarks, but the main demonstration entry point remains `bclrspaper.testRingSignature`.
