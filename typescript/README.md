# device-seal (Browser and more)

🦭 Device-bound, user-verified key custody and local encrypted storage for local-fist apps — no backend.

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=thinking-tools-at-codeberg_device-seal-ts&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=thinking-tools-at-codeberg_device-seal-ts)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=thinking-tools-at-codeberg_device-seal-ts&metric=coverage)](https://sonarcloud.io/summary/new_code?id=thinking-tools-at-codeberg_device-seal-ts)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=thinking-tools-at-codeberg_device-seal-ts&metric=bugs)](https://sonarcloud.io/summary/new_code?id=thinking-tools-at-codeberg_device-seal-ts)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=thinking-tools-at-codeberg_device-seal-ts&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=thinking-tools-at-codeberg_device-seal-ts)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=thinking-tools-at-codeberg_device-seal-ts&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=thinking-tools-at-codeberg_device-seal-ts)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=thinking-tools-at-codeberg_device-seal-ts&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=thinking-tools-at-codeberg_device-seal-ts)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=thinking-tools-at-codeberg_device-seal-ts&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=thinking-tools-at-codeberg_device-seal-ts)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=thinking-tools-at-codeberg_device-seal-ts&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=thinking-tools-at-codeberg_device-seal-ts)

[![Codeberg stars](https://img.shields.io/gitea/stars/thinking_tools/device-seal?gitea_url=https%3A%2F%2Fcodeberg.org&style=social)](https://codeberg.org/thinking_tools/device-seal)
[![NPM Downloads](https://img.shields.io/npm/dm/device-seal)](https://www.npmjs.com/package/device-seal)
[![NPM Version](https://img.shields.io/npm/v/device-seal?color=green)](https://www.npmjs.com/package/device-seal)
[![Bundle size](https://img.shields.io/bundlejs/size/device-seal?color=green)](https://www.npmjs.com/package/device-seal)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://codeberg.org/thinking_tools/device-seal/src/branch/main/LICENSE)

[![Last commit](https://img.shields.io/gitea/last-commit/thinking_tools/device-seal?gitea_url=https%3A%2F%2Fcodeberg.org&branch=main&color=green)](https://codeberg.org/thinking_tools/device-seal/commits/branch/main)
[![Open issues](https://img.shields.io/gitea/issues/open/thinking_tools/device-seal?gitea_url=https%3A%2F%2Fcodeberg.org)](https://codeberg.org/thinking_tools/device-seal/issues)
[![Format, test & SonarCloud](https://codeberg.org/thinking_tools/device-seal/actions/workflows/sonarcloud.yml/badge.svg?branch=main)](https://codeberg.org/thinking_tools/device-seal/actions?workflow=sonarcloud.yml)

[[codeberg](https://codeberg.org/thinking_tools/device-seal/)]
[[issues](https://codeberg.org/thinking_tools/device-seal/issues)]
[[npm](https://www.npmjs.com/package/device-seal)]
[[github|mirror](https://github.com/thinking-tools/device-seal)]

⚠️ NO independent audit or review yet! Use on your own risk!

- 🔐 **Device-bound & user-verified.** Each secret is sealed behind a WebAuthn passkey (PRF extension); every
  read demands a fresh on-device user-verification ceremony, and the encryption key is re-derived per call and never stored.
- 🚫 **Build for Local-first. Zero backend.** No server, no account, no key material in transit — the secret, the key, and the salt never leave the device.
- ⚛️ **Quantum-resistant symmetric core.** AES-256-GCM + HKDF-SHA-512 — CNSA 2.0 symmetric/hash primitives, NIST PQC Category 5.
- 🔑 **Optional passphrase second factor.** Stretched with PBKDF2-SHA-512 (700k iterations) and bound into both the authenticator's PRF input and the key derivation — so each guess needs a live ceremony and a stolen vault can't be brute-forced offline; required again on every unlock, and never stored.
- 🧩 **Per-app, per-entry isolation.** A length-framed application namespace plus a per-entry salt bind every key and ciphertext to one app, version, and entry, so secrets can never cross between them.
- 🌐 **Origin-bound.** Entries are tied to the creating hostname (the WebAuthn rpId); a copied IndexedDB store cannot be unlocked from any other origin.
- 📦 **Zero runtime dependencies** — pure ESM, side-effect-free, **tree-shakeable**, and safe to import in Node/SSR (nothing touches `window`/`location` until a ceremony runs).
- 🚀 **Tiny CDN bundle** — a single minified ESM of ~3 KB gzipped, served from jsDelivr/unpkg.
- 🎯 **Fully typed.** Written in TypeScript; ships type declarations (`.d.ts`).

A secret is encrypted on the device and can be read back only after the user verifies on their WebAuthn
authenticator (passkey). Nothing — not the secret, not the key, not the salt — ever leaves the machine.
There is no server to call, no account to create, and no key material in transit.

> **Status:** the **browser** implementation (WebAuthn PRF) is what ships today. Desktop (Secure
> Enclave / TPM) and JVM ports are planned and share this cryptographic design, not this code. All
> examples below are for the browser package.

## Requirements

- A **secure context** — HTTPS, or `http://localhost` during development. WebAuthn and `crypto.subtle`
  are unavailable otherwise.
- An authenticator that supports WebAuthn with the **PRF extension** (`hmac-secret`) and **user
  verification**. No attachment filter is set, so the user may use whatever they have — a built-in
  authenticator (Touch ID, Windows Hello, Android biometrics), a roaming security key (USB/NFC, e.g. a
  YubiKey), or their phone via the cross-device flow. (Discoverable/resident keys are *not* required — the
  credential id is stored locally and replayed on unlock, so resident storage is only requested as a
  preference.) PRF/`hmac-secret` is the real requirement; most current platform authenticators and modern
  FIDO2 security keys on recent browsers qualify. If the authenticator does not return a PRF secret,
  `createCredential`/`accessCredential` throw rather than store something unreadable. You can probe the
  browser's PRF capability up front with [`isDeviceSupported()`](#isdevicesupported) — but it reports only
  what the *client* supports, not which authenticator the user will pick, so the ceremony is the final word.
- ESM. The package is `"type": "module"` and has no runtime dependencies.

## Install

```sh
npm install device-seal
```

Or load it straight from a CDN — the package ships a single minified ESM bundle (`device-seal.min.js`),
which `jsdelivr`/`unpkg` serve from the bare package URL:

```html
<script type="module">
  import { createCredential } from 'https://cdn.jsdelivr.net/npm/device-seal';
</script>
```

## Quick start

```ts
import { createCredential, listCredentials, accessCredential } from 'device-seal';

// 1. Create a passkey and seal a secret behind it. Prompts the user to create a passkey
//    (user verification required). Only ciphertext + metadata is persisted; the key and plaintext never are.
const { entry } = await createCredential({
  username: 'alice@example.com',
  secret: 'my-api-token', // string | Uint8Array | omit to generate 32 random bytes
  label: 'Production API token',
});

const id = entry.identifier; // a UUID — persist this to retrieve the secret later

// 2. List what's stored. Metadata only: no decryption, no user prompt.
const all = await listCredentials({ username: 'alice@example.com' });

// 3. Unseal it. Prompts the user to verify on their authenticator, then returns the plaintext.
const { secret } = await accessCredential({ identifier: id });
const token = new TextDecoder().decode(secret); // -> 'my-api-token'
```

Let the library generate and seal a fresh random key instead of supplying one:

```ts
// Omit `secret` -> a fresh random 32-byte Uint8Array is generated, sealed, and returned to you.
const { entry, secret } = await createCredential({
  username: 'alice@example.com',
});
// `secret` is the 32 raw bytes, already encrypted at rest. Keep your own copy if you need a backup
// (see "No recovery" below) — after this call the only way back to it is a user-verified unlock.
```

Require a **passphrase** as a second factor — it is stretched with PBKDF2-SHA-512 and bound into both the
authenticator's PRF input and the key derivation, so the entry can then be opened only with the
authenticator **and** the passphrase, and because a wrong passphrase changes the PRF input, a stolen vault
cannot be brute-forced offline:

```ts
const { entry } = await createCredential({
  username: 'alice@example.com',
  secret: 'my-api-token',
  passphrase: 'correct horse battery staple', // empty string === no passphrase
});

// Later — unlocking needs the same passphrase alongside the authenticator ceremony:
const { secret } = await accessCredential({
  identifier: entry.identifier,
  passphrase: 'correct horse battery staple',
});
```

## API

The core `async` functions below, plus `createVault` — a small factory that pre-binds shared config — and
`isDeviceSupported()`, a capability probe you can call before any of them. Each core function accepts an
optional `databaseName` (default `passkeyVault`) to namespace its own IndexedDB store, and an advanced
`databaseVersion` — omit it unless you are deliberately driving an IndexedDB upgrade (versions are
monotonic, so a fixed value throws after any bump).

### `isDeviceSupported()`

A capability probe for gating your UI: resolves `true` when this client can protect secrets with the
WebAuthn PRF extension, `false` when it definitely cannot — no `PublicKeyCredential` (it is secure-context
only, so absent over plain HTTP and in non-browser runtimes) / no `navigator.credentials`, or the browser
explicitly reports PRF unsupported. It runs no ceremony, shows no prompt, and stores nothing.

```ts
isDeviceSupported(): Promise<boolean>
```

Capabilities are **client-level, not per-authenticator**: a `true` result means the *browser* supports PRF,
not that the specific passkey provider the user picks does. A password manager that stores passkeys without
`hmac-secret` (e.g. Bitwarden on Android) passes this check yet still fails the ceremony — so always handle
a `createCredential` rejection too. Treat it as "hide the feature when it's hopeless," not "guarantee
success." Unknown capabilities (older clients without `getClientCapabilities()`) resolve `true`, so
PRF-capable authenticators are never pre-emptively locked out.

### `createCredential(options)`

Registers a new device-bound passkey and stores a secret encrypted under it. Prompts the user to create
a passkey (user verification required), derives a non-extractable AES-GCM key from the authenticator's
PRF output and a per-entry salt, and persists only ciphertext.

```ts
createCredential(options: {
  username: string;                // required
  secret?: string | Uint8Array;    // string is UTF-8 encoded; Uint8Array is copied;
                                   //   omitted -> fresh random 32 bytes
  label?: string;                  // human-friendly label; defaults to `username`
  passphrase?: string;             // optional 2nd factor (PBKDF2); required again on every access.
                                   //   empty string === omitted
  applicationName?: string;        // crypto namespace; defaults to an environment-derived identity
                                   //   (web-app-manifest id -> page hostname -> 'app')
  applicationVersion?: number;     // crypto namespace version (default 1)
  databaseName?: string;           // default 'passkeyVault'
  databaseVersion?: number;        // advanced; omit to use the database's current version
}): Promise<{ entry: CredentialMetadata; secret: Uint8Array }>
```

Returns the entry's public metadata and the protected secret bytes (so you can use the secret
immediately without a second verification). `applicationName`/`applicationVersion` form the crypto
namespace woven into key derivation and authenticated data; they are recorded with the entry and reused
automatically on access, so secrets from one app/version can never be unlocked as another. When you omit
`applicationName` it defaults to a stable, environment-derived identity — a web-app-manifest id if one is
present, otherwise the page hostname, otherwise `"app"` — chosen to stay constant across app updates.

A `passphrase`, if given, is stretched with PBKDF2-SHA-512 and bound into both the authenticator's PRF
input and the key derivation, so the entry then requires **both** the authenticator and that passphrase to
open; testing a guess needs a live ceremony, so a stolen vault cannot be brute-forced offline. Only a
`passphrased: true` flag is recorded — never the passphrase itself; an empty string is treated as no
passphrase.

> Origin binding is automatic: entries are bound to the page's hostname (`location.hostname`, the WebAuthn
> rpId) and cannot be unlocked from a different hostname. There is no server endpoint — a credential is
> identified by its `identifier` and grouped by `username`.

### `listCredentials(filter?)`

Lists stored credential metadata. No decryption, no user prompt.

```ts
listCredentials(filter?: {
  username?: string;               // narrow by username
  databaseName?: string;           // default 'passkeyVault'
  databaseVersion?: number;        // advanced
}): Promise<CredentialMetadata[]>
```

### `accessCredential(options)`

Decrypts and returns a stored secret, prompting the user to verify on their authenticator. This is the
only read path that returns plaintext. The application namespace recorded at creation is reused
automatically — you do not supply it again.

```ts
accessCredential(options: {
  identifier: string;              // required — the `identifier` from createCredential's entry
  passphrase?: string;             // required iff the entry was created with one (`passphrased: true`)
  databaseName?: string;           // default 'passkeyVault'
  databaseVersion?: number;        // advanced
}): Promise<{ entry: CredentialMetadata; secret: Uint8Array }>
```

Throws if no entry matches the identifier, if the entry needs a passphrase and none (or an empty one) was
supplied, or if the user cancels verification. The passphrase check runs before any authenticator prompt.

### `removeCredential(options)`

Permanently deletes one stored credential and best-effort asks the platform credential manager to drop the
now-orphaned passkey. No user verification: deletion exposes no plaintext, and any same-origin caller could
clear IndexedDB anyway, so a ceremony would only add a footgun (a lost authenticator could never clean up
its own entry). Irreversible — the encrypted secret cannot be recovered afterwards.

```ts
removeCredential(options: {
  identifier: string;              // required — the entry to delete
  databaseName?: string;           // default 'passkeyVault'
  databaseVersion?: number;        // advanced
}): Promise<boolean>               // true if an entry was deleted, false if none matched (idempotent no-op)
```

### `wipeVault(options?)`

Deletes **every** stored credential in a database and best-effort asks the credential manager to drop each
now-orphaned passkey. Like `removeCredential`, it needs no user verification and is irreversible.

```ts
wipeVault(options?: {
  databaseName?: string;           // default 'passkeyVault'
  databaseVersion?: number;        // advanced
}): Promise<number>                // count of entries removed
```

### `createVault(config?)`

A small synchronous factory that pre-binds shared config — `databaseName`, `databaseVersion`,
`applicationName`, `applicationVersion` — so you don't repeat it on every call. It returns
`{ create, access, list, remove, wipe }`, thin wrappers over the five functions above; per-call options are
merged over the bound config (call options win).

```ts
const vault = createVault({ applicationName: 'my-app', databaseName: 'myVault' });

const { entry } = await vault.create({ username: 'alice@example.com', secret: 'my-api-token' });
const all = await vault.list({ username: 'alice@example.com' });
const { secret } = await vault.access({ identifier: entry.identifier });
await vault.remove({ identifier: entry.identifier }); // delete one entry
await vault.wipe(); // or delete every entry in the bound database
```

### Types

```ts
interface CredentialMetadata {
  identifier: string; // UUID; the handle you pass to accessCredential
  username: string;
  label: string;
  createdAt: string; // ISO 8601
  passphrased: boolean; // true if a passphrase is required to unlock this entry
}
```

`CredentialMetadata` is the hard boundary returned to callers: every cryptographic field (salts, nonce,
ciphertext, and even the application namespace) is deliberately stripped, so listing or returning an
entry can never leak key material.

## How it works

Every secret is sealed under a single AES-256-GCM key that is re-derived on demand and **never stored**:

1. **Unlock secret** — 32 bytes produced by the authenticator's WebAuthn PRF extension, but only during
   a user-verified ceremony. The PRF is evaluated over a SHA-512 hash of the per-entry salt — and, when a
   passphrase is set, of the salt length-framed with the PBKDF2-SHA-512-stretched passphrase — so a wrong
   passphrase yields a different secret and each guess needs a fresh ceremony (no offline brute-force). It
   is the one input that requires the physical authenticator and a present human, and it is never persisted.
2. **Encryption key** — `HKDF-SHA-512` over the unlock secret (and, when a passphrase is set, the same
   PBKDF2-stretched passphrase material length-framed in alongside it), salted with a per-entry random salt
   and bound (via the HKDF `info`) to the application namespace and the credential id, so keys never cross
   between entries or apps. Non-extractable; exists only for the duration of one call.
3. **Ciphertext** — the key encrypts the secret with AES-256-GCM under a fresh 12-byte nonce, with the
   application namespace and entry identifier as additional authenticated data (so a stored blob cannot
   be moved to another entry or namespace without failing the GCM tag).

Only opaque, non-secret material reaches IndexedDB — the salt, the public credential id, the nonce, the
ciphertext, and plaintext metadata (username, label, timestamp, and the `passphrased` flag). The derived
key and the plaintext secret never do. Reading reverses the chain: a fresh verification yields the unlock
secret, which re-derives the same key, which decrypts. No key material is cached between calls, so every
read costs exactly one fresh user verification.

AES-256-GCM and HKDF-SHA-512 are the CNSA 2.0 symmetric/hash primitives (NIST PQC Category 5), and
data-at-rest confidentiality rests entirely on them. The passkey's signing keypair (ES256/RS256, etc.)
only authenticates the user and never touches the encryption path, so a break of that classical keypair
does not expose stored secrets.

## Security model & limitations

- **Device-bound and origin-bound.** Entries are bound to the authenticator and to the hostname they
  were created on (the WebAuthn rpId is `location.hostname`). The same IndexedDB data cannot be unlocked
  from a different hostname — the rpId no longer matches.
- **No backend, no sync.** Nothing is uploaded; there is nothing to breach server-side and nothing to
  synchronize across devices.
- **No recovery — by design.** Losing the device or authenticator, or clearing the site's browser
  storage, makes entries permanently unrecoverable. There is no escrow and no reset. If you need
  durability, keep your own backup of the secret (`createCredential` returns it to you once).
- **Per-read verification.** Every `accessCredential` triggers a fresh user-verification ceremony; keys
  are never held in memory across calls.
- **Best-effort persistence.** The module requests persistent storage, but private/incognito sessions
  and storage-pressure eviction can still discard IndexedDB data.

### Errors

The functions reject (throw) rather than fail silently when: a required option (`username`, or
`identifier`) is missing; the context is not secure or WebAuthn is unavailable; the authenticator does not
return a PRF secret; the user cancels a create/verify ceremony; `accessCredential` is given an identifier
with no stored entry; or a passphrase-protected entry is accessed without its passphrase.

## Resources

- FIPS 197 Advanced Encryption Standard (AES) algorithm https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
- FIPS 180-4 Secure Hash Standard (SHS) https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

## License

MIT © thinking.tools — <https://codeberg.org/thinking_tools/device-seal>
