# 🦭 device-seal — Android (Keystore / TPM)

Device-bound, user-verified key custody and local encrypted storage for Android — **no backend**.

A secret is encrypted on the device and can be read back only after the user verifies on the device's secure
hardware (a **StrongBox** secure element when present, otherwise the **TEE** — Android's "TPM"). Nothing —
not the secret, not the key, not the salt — ever leaves the device. Quantum-resistant symmetric core:
**AES-256-GCM + HKDF-SHA-512** (CNSA 2.0 symmetric/hash primitives, NIST PQC Category 5), identical to the
[browser implementation](../typescript).

> **⚠️ Status: compiles & assembles; not yet device-tested or audited.** This is a faithful port of the
> browser package's cryptographic design. It **builds** — `./gradlew assembleRelease` produces an AAR (Gradle
> 8.9 / AGP 8.7.0 / Kotlin 2.0.21, compileSdk 35), and the pure-crypto core **runs** and passes its checks on
> the JVM. It has **not** yet been run through a real on-device ceremony (BiometricPrompt + Keystore HMAC in
> StrongBox/TEE), validated on real StrongBox-vs-TEE hardware, or **security-audited**. Treat it as a
> reviewable, compilable starting point, not shippable code. See
> [Build status & what's unverified](#build-status--whats-unverified).

## How it maps to the browser implementation

The browser uses a WebAuthn passkey and its PRF extension as the device-bound, user-verified root. Android has
no WebAuthn-PRF-by-default, so the same role is played by a **hardware-bound, user-authentication-gated HMAC
key in the Android Keystore**. The HMAC primitive is the same one WebAuthn PRF uses internally (CTAP2
`hmac-secret` is HMAC-SHA-256), so the rest of the envelope is reproduced byte-for-byte.

| Browser primitive | Android equivalent |
| --- | --- |
| WebAuthn passkey + PRF (`hmac-secret`, HMAC-SHA-256) | Per-entry **HMAC-SHA-256 key in the Android Keystore**, non-exportable (StrongBox → TEE) |
| User verification (`userVerification: 'required'`, every ceremony) | `setUserAuthenticationRequired(true)`, verified by **BiometricPrompt** on every create/access |
| Origin binding (`rpId = location.hostname`) | Keystore keys are bound to the app (UID + signing identity) and the device, automatically |
| PRF output (32 bytes) | `Mac.doFinal(SHA-512(prfEvalInput))` → 32 bytes |
| HKDF-SHA-512 → non-extractable AES-GCM key | Software HKDF-SHA-512 (RFC 5869) over the hardware HMAC output; AES key bytes transient + zeroized |
| AES-256-GCM, length-framed AAD/info | Identical (`AES/GCM/NoPadding`, 128-bit tag) |
| PBKDF2-SHA-512, 700k | `PBKDF2withHmacSHA512`, identical parameters |
| IndexedDB | Built-in **SQLite** (`SQLiteOpenHelper`) — zero extra dependency, mirrors the built-in store |
| `signalUnknownCredential` (best-effort orphan cleanup) | `KeyStore.deleteEntry(alias)` — a **reliable** hard delete |

**Why HMAC-SHA-256 and not SHA-512 for the unlock secret:** it is exactly WebAuthn PRF's primitive, yields the
same 32 bytes, and is the one HMAC variant a StrongBox is **guaranteed** to support (key sizes 8–64 bytes). The
derivation/encryption layer keeps SHA-512 / AES-256, so the advertised quantum-resistant symmetric core is
unchanged.

## Cryptographic envelope

Identical in structure to `typescript/src/_crypto.ts` + `_helpers.ts` + `_vault.ts`:

```
unlock secret  = HMAC-SHA-256(hardwareKey, SHA-512(prfEvalInput))            # the "PRF", computed in hardware
prfEvalInput   = salt            | framedBytes(salt, passphraseMaterial)     # passphrase folded in here
secretKey      = HKDF-SHA-512(ikm, salt, info = framed(appContext, credId))  # 32-byte AES-256 key
ikm            = unlockSecret    | framedBytes(unlockSecret, passphraseMaterial)
ciphertext     = AES-256-GCM(secret, iv = 12B random, aad = framed(appContext, identifier))
passphraseMat  = PBKDF2-SHA-512(passphrase, salt, 700_000, 256 bits)         # optional second factor
```

`framedBytes(...)` is injective concatenation: each part is length-prefixed with a big-endian uint32, so a
caller-controlled `applicationContext` (which may contain `/`) can never collide with a different
`(context, id)` pair. The passphrase, when set, is folded into **both** the hardware HMAC input and the HKDF
ikm — so testing a guess requires a live, user-verified ceremony, and a stolen vault cannot be brute-forced
offline.

## Quick start

```kotlin
import androidx.appcompat.app.AppCompatActivity   // AppCompatActivity is a FragmentActivity
import kotlinx.coroutines.launch
import tools.thinking.deviceseal.*

class VaultActivity : AppCompatActivity() {

    // One handle per (database, app namespace). Default mode = biometric-only, strongest binding.
    private val vault by lazy { DeviceSeal(this) }

    fun saveToken(username: String, token: String) {
        if (!DeviceSeal.isDeviceSupported(this)) { /* hide the feature */ return }
        lifecycleScope.launch {
            val result = vault.createCredential(
                activity = this@VaultActivity,
                username = username,
                secret = Secret.Text(token),
                prompt = PromptCopy(title = "Save $username", subtitle = "Verify to protect this secret"),
            )
            // result.secret is returned ONCE — back it up if you need recovery (there is none otherwise).
            // result.entry.keyBacking is STRONGBOX or TEE.
            result.secret.fill(0)   // wipe when done
        }
    }

    fun readToken(identifier: String) {
        lifecycleScope.launch {
            try {
                val result = vault.accessCredential(this@VaultActivity, identifier)
                val token = String(result.secret, Charsets.UTF_8)
                result.secret.fill(0)
                // ... use token ...
            } catch (e: DeviceSealException.UserCancelled) {
                // user dismissed the prompt
            } catch (e: DeviceSealException.DecryptionFailed) {
                // wrong passphrase, wrong device, or tampered data — indistinguishable by design
            }
        }
    }
}
```

## Public API

`DeviceSeal(context, databaseName = "passkeyVault", applicationName = context.packageName, applicationVersion = 1, allowDeviceCredential = false)`

| Member | Description |
| --- | --- |
| `suspend createCredential(activity, username, secret?, label?, passphrase?, prompt?)` → `CredentialResult` | Generates a per-entry hardware key, verifies the user, encrypts and stores the secret. Returns the plaintext **once**. |
| `suspend accessCredential(activity, identifier, passphrase?, prompt?)` → `CredentialResult` | Verifies the user and returns the decrypted secret. The only read path that returns plaintext. |
| `suspend listCredentials(username?)` → `List<CredentialMetadata>` | Metadata only — no decryption, no prompt. |
| `suspend removeCredential(identifier)` → `Boolean` | Deletes the row and the hardware key. No prompt. Irreversible. |
| `suspend wipeVault()` → `Int` | Deletes every row and hardware key in the database. No prompt. Irreversible. |
| `close()` | Releases the database connection. |
| `companion isDeviceSupported(context, allowDeviceCredential = false)` → `Boolean` | Whether the device can verify the user for the chosen mode. |

`CredentialMetadata` = `identifier` / `username` / `label` / `createdAt` / `passphrased` / **`keyBacking`** (the
Android-only achieved hardware level). Suspend functions are coroutine equivalents of the browser's Promises;
`createCredential`/`accessCredential` require a `FragmentActivity` because BiometricPrompt is lifecycle-bound.

## Verification modes (a hard Android constraint)

A `BiometricPrompt.CryptoObject` — which binds an authentication to one specific crypto operation — **cannot**
be combined with `DEVICE_CREDENTIAL` (PIN/pattern/password) as an allowed authenticator. So `DeviceSeal`
exposes `allowDeviceCredential`, fixed into each entry's key at creation and replayed automatically on access:

- **`false` (default — strongest):** per-use auth + `CryptoObject(Mac)`. The HMAC is cryptographically bound to
  one Class-3 biometric authentication; there is no window in which the key is usable without it. **Requires an
  enrolled biometric** (fingerprint/face).
- **`true`:** time-bound auth + no `CryptoObject`. Biometric **or** device credential (PIN) unlocks — matching
  the browser's availability — but the key is merely usable for a short window (5 s) after a successful auth.
  A weaker, non-per-operation binding. Choose this only when you must support PIN-only users.

## StrongBox policy

Key generation **prefers StrongBox and falls back to the TEE**: it requests `setIsStrongBoxBacked(true)`, and
because `KeyGenerator.generateKey()` throws `StrongBoxUnavailableException` when no StrongBox is present, the
library catches that and regenerates on the TEE — it never silently downgrades to software. The level actually
achieved is recorded per entry and surfaced as `CredentialMetadata.keyBacking` (`STRONGBOX` / `TEE`). To
*mandate* StrongBox, gate on `keyBacking == STRONGBOX` after creation (and delete + refuse otherwise), or
adapt `generateUnlockKey` to rethrow.

## Security model & limitations

- **Origin binding = app + device.** Keystore keys are scoped to the app's UID and signing identity and cannot
  leave the device — another app can't use them, and the encrypted store is useless if copied elsewhere. This
  is the analog of the browser's hostname (`rpId`) binding.
- **No recovery, by design.** Losing the device, removing the secure lock screen, or clearing app data makes
  entries permanently unrecoverable. `createCredential` returns the secret once so you can keep your own backup.
- **Metadata is cleartext.** `username`, `label`, `createdAt` are stored unencrypted (like the browser's
  IndexedDB) — a stolen copy reveals which accounts exist (a privacy leak, not a secret one).
- **AAD authenticates only `applicationContext` + `identifier`.** Mutable metadata is not covered by the GCM
  tag, so tampering with it is not detected on decrypt; it can at most deny service, never bypass.
- **Biometric re-enrollment does not invalidate keys** (`setInvalidatedByBiometricEnrollment(false)`), matching
  the browser where the PRF survives adding a fingerprint. Flip it to `true` for stronger anti-coercion at the
  cost of total vault loss when a new biometric is enrolled — a footgun absent in the browser, hence not the
  default.
- **Zeroization is best-effort.** Transient key material (HMAC output, HKDF ikm, passphrase material, AES key
  bytes) is wiped after use, but the JVM copies inputs internally (`SecretKeySpec`), a moving GC may leave
  copies, and `String` secrets/passphrases cannot be wiped at the source.
- **Time-bound mode caveat.** When `allowDeviceCredential = true`, the unlock is not bound to the specific HMAC
  operation; there is a brief window after auth in which the key is usable.

## Requirements

- **minSdk 30** (Android 11) — for `setUserAuthenticationParameters(int, int)` and crypto-bound device
  credential. **compileSdk 35**.
- Dependencies: `androidx.biometric` (≥ 1.1.0 for `setAllowedAuthenticators`), `androidx.fragment`,
  `kotlinx-coroutines-android`. SQLite and the Keystore are built into the platform.
- The host screen must be a `FragmentActivity` (e.g. `AppCompatActivity`).

## Build & test

```bash
# from android/  (a Gradle 8.9 wrapper is committed; an Android SDK at $ANDROID_HOME + a JDK 17+ are required)
./gradlew assembleRelease      # compiles all sources and builds build/outputs/aar/device-seal-android-release.aar
./gradlew compileReleaseKotlin # compile/type-check only (faster)
```

On-device / emulator test matrix (manual, until instrumented tests exist):

1. `isDeviceSupported` true on a device with a biometric (mode A) / a lock screen (mode B), false otherwise.
2. `createCredential` → `listCredentials` → `accessCredential` round-trips the same bytes.
3. Wrong `passphrase` → `DecryptionFailed`; dismissing the prompt → `UserCancelled`.
4. Mode A on a biometric-enrolled device; mode B via PIN on a device without biometrics.
5. A StrongBox device reports `keyBacking == STRONGBOX`; a TEE-only device reports `TEE`.
6. `removeCredential` / `wipeVault` clear both the rows and the Keystore keys.

## Build status & what's unverified

This port was written from the browser source and the Android API references; the APIs it relies on were
checked against authoritative docs (StrongBox supports HMAC-SHA-256; `StrongBoxUnavailableException` is thrown
on unsupported devices; `setDigests` is implied for HMAC keys; `CryptoObject` is incompatible with
`DEVICE_CREDENTIAL`).

**Verified by building and running:**

- **It compiles and assembles.** `./gradlew assembleRelease` builds all four Kotlin sources against real
  Android (compileSdk 35) + androidx.biometric/fragment/core + kotlinx-coroutines and emits
  `device-seal-android-release.aar` (Gradle 8.9, AGP 8.7.0, Kotlin 2.0.21). A clean compile means every
  Android/androidx API signature used here resolved and type-checked against the real libraries — the main
  API-correctness risk for a from-docs port.
- **The crypto core runs.** The real `Crypto.kt` (`framedBytes`, `sha512`, HKDF-SHA-512, AES-256-GCM, PBKDF2,
  `zeroize`) was compiled and executed on the JVM (no Android needed) and passes 11 checks — including
  agreement with an independent HKDF-SHA-512 reference over 200 random vectors (the looping HKDF was
  separately confirmed against the **RFC 5869** test vector), the full encrypt→decrypt envelope round-trip,
  GCM rejection of mismatched AAD (entry/namespace binding), and the wrong-passphrase-fails-to-decrypt
  property.

**Not yet verified** (these genuinely require a device/emulator — they call into secure hardware and show UI):

- a real on-device ceremony — `BiometricPrompt`, and the HMAC actually computed by the Keystore key in
  StrongBox/TEE (both auth modes);
- behaviour on real StrongBox vs TEE-only hardware (`keyBacking`), and key invalidation on a security change;
- a security audit.

Instrumented (`androidTest`) tests on an emulator with an enrolled biometric, plus JVM unit tests wired into
the Gradle module for `Crypto.kt`, are the sensible next step.

## License

MIT © thinking.tools — <https://codeberg.org/thinking_tools/device-seal>
