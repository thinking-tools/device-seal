# 🦭 device-seal

Device-bound, user-verified key custody and local encrypted storage for local-first apps — **no backend**.

[![License: MIT](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

A secret is encrypted on the device and can be read back only after the user verifies on their WebAuthn
authenticator (passkey). Nothing — not the secret, not the key, not the salt — ever leaves the machine.
Quantum-resistant symmetric core: AES-256-GCM + HKDF-SHA-512 (CNSA 2.0 symmetric/hash primitives, NIST PQC
Category 5).

## Implementations

| Implementation               | Platform                       | Quality                                                                                                                                                                                                                               | Review           | Install                                                                                                           |
| ---------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------- |
| [TypeScript](./typescript)   | Browser (WebAuthn PRF)         | [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=thinking-tools-at-codeberg_device-seal-ts&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=thinking-tools-at-codeberg_device-seal-ts) | ⚠️ Internal only | [![NPM Version](https://img.shields.io/npm/v/device-seal?color=green)](https://www.npmjs.com/package/device-seal) |
| [Tauri / Rust](./tauri-rust) | Desktop (Secure Enclave / TPM) | —                                                                                                                                                                                                                                     | —                | —                                                                                                                 |
| [Android](./android)         | Mobile (Android Keystore)      | —                                                                                                                                                                                                                                     | —                | —                                                                                                                 |

See **[`typescript/README.md`](./typescript/README.md)** for the full API, quick start, and security model,
and **[`BREAKING.md`](./BREAKING.md)** for breaking changes between releases.

## Security

This is a security-sensitive library, and it has **not yet had an independent audit or review** — use it at
your own risk. The cryptographic design and its threat model are documented in
**[`typescript/README.md`](./typescript/README.md#security-model--limitations)**.

Found a vulnerability? Please **do not** open a public issue. Report it privately by email to
**reports@thinking.tools** and follow the disclosure process in **[`SECURITY.md`](./SECURITY.md)**, which also
lists supported versions and what to expect after you report.

## Contributing

Contributions are warmly welcomed and deeply appreciated — bug reports, fixes, docs, and new platform
implementations alike.

Before committing to any work, please **[open an issue](https://codeberg.org/thinking_tools/device-seal/issues)**
and let's talk it through first. This is a security-sensitive, zero-backend library where the cryptographic
design is load-bearing, so a short conversation up front saves everyone effort — it lets us agree on the
approach, avoid duplicate or conflicting work, and make sure a change fits the threat model before you invest
your time. Please don't open a large pull request out of the blue; start a discussion, and we'll go from there.

Small, obvious fixes (typos, broken links, clear bugs) are fine to send directly. For anything larger, the
issue comes first — but every thoughtful contribution is genuinely valued.

## License

MIT © thinking.tools — <https://codeberg.org/thinking_tools/device-seal>
