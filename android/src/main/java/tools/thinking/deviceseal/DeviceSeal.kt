package tools.thinking.deviceseal

import android.content.Context
import androidx.fragment.app.FragmentActivity
import java.time.Instant
import java.util.UUID
import javax.crypto.AEADBadTagException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// ============================================================================================
// device-seal — Android (Keystore / TPM) implementation.
//
// Port of the browser `device-seal` package. A secret is encrypted on the device and can be read back only
// after the user verifies on the device's hardware authenticator; nothing — not the secret, not the key, not
// the salt — ever leaves the device. The cryptographic envelope is identical to the browser build:
//
//   unlock secret  = HMAC-SHA-256 over SHA-512(prfEvalInput), computed by a per-entry, user-auth-gated,
//                    non-exportable key in the Android Keystore (StrongBox secure element → TEE).   [HardwareKey]
//   secret key     = HKDF-SHA-512(ikm, salt, info = framed(applicationContext, credentialIdentifier))  [Crypto]
//   ciphertext     = AES-256-GCM(secret), 96-bit nonce, AAD = framed(applicationContext, identifier)    [Crypto]
//   passphrase     = PBKDF2-SHA-512(700k) folded into BOTH the PRF eval input and the HKDF ikm           [Crypto]
//
// What differs from the browser, and why:
//   - The ambient `crypto`/`indexedDB`/`navigator.credentials` globals don't exist on Android, so this is a
//     class (a "vault handle") constructed with a Context — equivalent to the browser's `createVault(config)`.
//   - create/access are `suspend` and take a [FragmentActivity], because the user-verification ceremony runs
//     through BiometricPrompt (callback + main-thread + lifecycle bound). The browser's Promise-based API
//     maps onto Kotlin coroutines.
//   - WebAuthn's hostname (rpId) origin binding becomes the Keystore's automatic app + device binding.
//   - A hard platform constraint (CryptoObject is incompatible with device-credential auth) forces a choice
//     of verification mode; see `allowDeviceCredential` and [HardwareKey]'s two-mode note.
// ============================================================================================

/** Which secure hardware actually protects an entry's key. No browser analog. */
enum class KeyBacking {
    /** A discrete tamper-resistant secure element (preferred). */
    STRONGBOX,

    /** The CPU's Trusted Execution Environment (fallback when no StrongBox is present). */
    TEE,
}

/**
 * Public, non-secret metadata for a stored entry — the only shape ever returned to callers. Deliberately
 * carries no cryptographic field (salt, nonce, ciphertext, or application context), so listing or returning
 * an entry can never leak key material. Mirrors `CredentialMetadata` in the browser build, plus the
 * Android-only [keyBacking].
 */
data class CredentialMetadata(
    /** Stable unique id (a UUID) assigned at creation; pass it to [DeviceSeal.accessCredential]/[DeviceSeal.removeCredential]. */
    val identifier: String,
    /** Account username supplied at creation. */
    val username: String,
    /** Human-friendly label; defaults to the username when none was given. */
    val label: String,
    /** ISO-8601 timestamp of when the entry was created. */
    val createdAt: String,
    /** Whether unlocking this entry also requires the passphrase set at creation. */
    val passphrased: Boolean,
    /** Android-only: which secure hardware protects this entry's key (the level actually achieved, not requested). */
    val keyBacking: KeyBacking,
)

/**
 * Returned by [DeviceSeal.createCredential] and [DeviceSeal.accessCredential]. The plaintext [secret] is a
 * fresh, caller-owned [ByteArray]; createCredential returns it once so callers can keep their own backup
 * (there is no recovery), and accessCredential returns the decrypted secret. The caller is responsible for
 * wiping it ([ByteArray.fill]) once done.
 */
data class CredentialResult(val entry: CredentialMetadata, val secret: ByteArray)

/**
 * The secret to protect, mirroring the browser's `string | Uint8Array | undefined`: [Text] is UTF-8 encoded,
 * [Bytes] is copied (so later mutation of the caller's array cannot change what was encrypted), and a `null`
 * secret generates a fresh random 32-byte value.
 */
sealed class Secret {
    data class Text(val value: String) : Secret()
    class Bytes(val value: ByteArray) : Secret()
}

/** Copy shown in the BiometricPrompt during a create/access ceremony. */
data class PromptCopy(
    val title: String = "Verify it's you",
    val subtitle: String? = null,
    val description: String? = null,
    /** Shown only in biometric-only mode (`allowDeviceCredential = false`), where a negative button is required. */
    val negativeButtonText: String = "Cancel",
)

/** Every failure this library raises. Sealed so callers can branch exhaustively. */
sealed class DeviceSealException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** The device cannot verify the user for the selected mode (no enrolled biometric, and — in default mode — no device credential). */
    class Unsupported : DeviceSealException(
        "This device cannot verify the user for the selected mode: enrol a biometric (or allow device credential) to use device-seal",
    )

    /** The user dismissed or cancelled the verification prompt. */
    class UserCancelled : DeviceSealException("Verification was cancelled")

    /** A terminal BiometricPrompt error (lockout, hardware error, etc.). [code] is the BiometricPrompt error code, if any. */
    class AuthenticationFailed(message: String, val code: Int?) : DeviceSealException(message)

    /** The entry is passphrase-protected and no passphrase (or an empty one) was supplied. */
    class PassphraseRequired : DeviceSealException("This credential requires a passphrase")

    /** No stored entry matched the given identifier. */
    class NotFound(identifier: String) : DeviceSealException("No stored credential with identifier '$identifier'")

    /** The entry's hardware key is gone from the Keystore (e.g. app data partially cleared). Unrecoverable. */
    class HardwareKeyMissing(alias: String) : DeviceSealException("Hardware key '$alias' is missing; the entry cannot be unlocked")

    /** The hardware key was invalidated (lock screen removed, or biometrics re-enrolled when invalidation is on). Unrecoverable. */
    class HardwareKeyInvalidated(alias: String, cause: Throwable) :
        DeviceSealException("Hardware key '$alias' was permanently invalidated by a security change", cause)

    /** GCM rejected: wrong passphrase, wrong device/credential, or tampered ciphertext. Indistinguishable by design. */
    class DecryptionFailed(cause: Throwable?) :
        DeviceSealException("Decryption failed: wrong passphrase, wrong device, or the stored data was altered", cause)
}

/**
 * A device-bound, user-verified secret vault backed by the Android Keystore — the Android equivalent of the
 * browser's `createVault(config)` handle. Construct one per (database, application namespace) and reuse it.
 *
 * @param context any [Context]; only its application context is retained.
 * @param databaseName the SQLite database the entries live in (default `passkeyVault`, matching the browser).
 * @param applicationName crypto namespace woven (length-framed) into key derivation and authenticated data,
 *   recorded with each entry and reused automatically on access. Defaults to this app's package name (the
 *   stable, update-surviving identity the browser approximates from the web-manifest id / hostname).
 * @param applicationVersion crypto namespace version (default `1`); bumping it deliberately rotates (orphans)
 *   older secrets, exactly as in the browser build.
 * @param allowDeviceCredential verification mode for credentials created by this handle. `false` (default,
 *   strongest) binds the unlock to one Class-3 biometric via a CryptoObject and requires an enrolled
 *   biometric. `true` also accepts the device PIN/pattern/password but, because CryptoObject and device
 *   credential are mutually exclusive on Android, uses a weaker time-bound binding. The mode is recorded per
 *   entry and replayed on access, so a single handle can read entries it created regardless of later changes.
 */
class DeviceSeal(
    context: Context,
    private val databaseName: String = DEFAULT_DATABASE_NAME,
    applicationName: String = context.applicationContext.packageName,
    applicationVersion: Int = DEFAULT_APPLICATION_VERSION,
    private val allowDeviceCredential: Boolean = false,
) {
    private val appContext: Context = context.applicationContext
    private val applicationContext: String = "$applicationName/v$applicationVersion/"
    private val store: VaultStore by lazy { VaultStore(appContext, databaseName) }

    /**
     * Registers a new device-bound hardware key and stores a secret encrypted under it. Generates a per-entry
     * HMAC key in the Keystore (StrongBox preferred, TEE fallback), prompts the user to verify, derives an
     * AES-256-GCM key from the hardware HMAC output and a per-entry salt, and persists only ciphertext.
     * Equivalent to the browser's `createCredential`.
     *
     * @param activity the host activity to show the verification prompt on (must be a [FragmentActivity];
     *   AppCompatActivity qualifies).
     * @param username account username (required, non-blank).
     * @param secret the secret to protect (see [Secret]); `null` generates a fresh random 32-byte secret.
     * @param label human-friendly label; defaults to [username].
     * @param passphrase optional second factor folded (via PBKDF2) into both the hardware HMAC eval input and
     *   the key derivation, so each guess requires a live ceremony and a stolen vault cannot be brute-forced
     *   offline. A non-empty value must be supplied again on every access; `null`/empty means no passphrase.
     * @param prompt copy for the verification dialog.
     * @return the entry's public metadata (including the achieved [KeyBacking]) and the protected secret bytes
     *   (returned once — keep a backup).
     * @throws DeviceSealException.Unsupported if the device cannot verify the user for this handle's mode.
     * @throws DeviceSealException.UserCancelled if the user dismisses the prompt.
     */
    suspend fun createCredential(
        activity: FragmentActivity,
        username: String,
        secret: Secret? = null,
        label: String? = null,
        passphrase: String? = null,
        prompt: PromptCopy = PromptCopy(),
    ): CredentialResult {
        require(username.isNotBlank()) { "Username is required" }
        if (!isDeviceSupported(appContext, allowDeviceCredential)) throw DeviceSealException.Unsupported()

        val secretBytes = normalizeSecret(secret)
        val salt = Crypto.randomBytes(SALT_BYTES)
        val identifier = UUID.randomUUID().toString()
        // The analog of the WebAuthn credential rawId: random bytes that name this entry's hardware key.
        val credentialIdentifier = Crypto.randomBytes(CREDENTIAL_ID_BYTES)
        val additionalData = Crypto.additionalDataFor(applicationContext, identifier)

        val passphraseEnabled = !passphrase.isNullOrEmpty()
        // Derived before the ceremony: the passphrase is folded into the PRF eval input, so a stolen vault
        // can't be tested offline. PBKDF2 is CPU-heavy → off the main thread.
        val passphraseMaterial = if (passphraseEnabled) {
            withContext(Dispatchers.Default) { Crypto.derivePassphraseMaterial(passphrase!!, salt) }
        } else null
        val prfEvalInput = if (passphraseMaterial == null) salt else Crypto.framedBytes(salt, passphraseMaterial)

        var unlockSecret: ByteArray? = null
        var aesKeyBytes: ByteArray? = null
        try {
            val keyBacking = withContext(Dispatchers.IO) {
                HardwareKey.generateUnlockKey(credentialIdentifier, allowDeviceCredential)
            }
            try {
                unlockSecret = HardwareKey.evaluateUnlockSecret(
                    activity, credentialIdentifier, prfEvalInput, prompt, allowDeviceCredential,
                )
                aesKeyBytes = deriveAesKey(unlockSecret!!, passphraseMaterial, salt, credentialIdentifier)
                val sealed = Crypto.aesGcmEncrypt(aesKeyBytes!!, secretBytes, additionalData)

                val entry = StoredEntry(
                    identifier = identifier,
                    username = username,
                    label = label ?: username,
                    createdAt = Instant.now().toString(),
                    applicationContext = applicationContext,
                    credentialIdentifier = credentialIdentifier,
                    salt = salt,
                    initializationVector = sealed.initializationVector,
                    ciphertext = sealed.ciphertext,
                    passphrased = passphraseEnabled,
                    keyBacking = keyBacking,
                    deviceCredentialAllowed = allowDeviceCredential,
                )
                withContext(Dispatchers.IO) { store.save(entry) }
                return CredentialResult(toPublicMetadata(entry), secretBytes)
            } catch (e: Throwable) {
                // We generated a hardware key we could not use (cancelled ceremony, or a later failure).
                // Unlike the browser's best-effort signal, deletion here is reliable: drop the orphan so
                // retries don't pile up dead keys, then surface the original failure.
                withContext(Dispatchers.IO) { HardwareKey.deleteUnlockKey(credentialIdentifier) }
                throw e
            }
        } finally {
            // Wipe raw key material now the AES key is derived (best-effort; see Crypto.zeroize). Never wipe
            // `salt` (persisted) or `secretBytes` (returned). prfEvalInput aliases `salt` without a passphrase.
            Crypto.zeroize(unlockSecret, aesKeyBytes, passphraseMaterial)
            if (passphraseMaterial != null) Crypto.zeroize(prfEvalInput)
        }
    }

    /**
     * Lists stored credential metadata without decrypting anything or prompting the user. Equivalent to the
     * browser's `listCredentials`.
     *
     * @param username optional filter; omit to list every entry in the database.
     */
    suspend fun listCredentials(username: String? = null): List<CredentialMetadata> =
        withContext(Dispatchers.IO) {
            store.loadAll()
                .filter { username == null || it.username == username }
                .map(::toPublicMetadata)
        }

    /**
     * Decrypts and returns a stored secret, prompting the user to verify on their device. The application
     * namespace and verification mode recorded at creation are reused automatically. Equivalent to the
     * browser's `accessCredential`.
     *
     * @param activity the host activity to show the verification prompt on (must be a [FragmentActivity]).
     * @param identifier the [CredentialMetadata.identifier] of the entry to unlock.
     * @param passphrase required if the entry was created with one (see [CredentialMetadata.passphrased]);
     *   omitting it (or passing empty) for a protected entry throws before any prompt.
     * @param prompt copy for the verification dialog.
     * @throws DeviceSealException.NotFound if no entry matches.
     * @throws DeviceSealException.PassphraseRequired if a passphrase is needed but absent.
     * @throws DeviceSealException.DecryptionFailed on a wrong passphrase, wrong device, or tampered data.
     */
    suspend fun accessCredential(
        activity: FragmentActivity,
        identifier: String,
        passphrase: String? = null,
        prompt: PromptCopy = PromptCopy(),
    ): CredentialResult {
        require(identifier.isNotBlank()) { "identifier is required" }
        val entry = withContext(Dispatchers.IO) { store.load(identifier) }
            ?: throw DeviceSealException.NotFound(identifier)

        val passphraseRequired = entry.passphrased
        val passphraseProvided = !passphrase.isNullOrEmpty()
        if (passphraseRequired && !passphraseProvided) throw DeviceSealException.PassphraseRequired()

        // Entries always store their context; fall back to the legacy default only if somehow blank.
        val entryContext = entry.applicationContext.ifBlank { DEFAULT_APPLICATION_CONTEXT }
        val additionalData = Crypto.additionalDataFor(entryContext, entry.identifier)

        // Rebuild the SAME PRF eval input used at creation. A wrong passphrase yields a different eval input,
        // hence a different hardware HMAC output, hence a different key — so GCM rejects (online-only guessing:
        // every attempt still needs a live, user-verified ceremony).
        val passphraseMaterial = if (passphraseRequired && passphrase != null) {
            withContext(Dispatchers.Default) { Crypto.derivePassphraseMaterial(passphrase, entry.salt) }
        } else null
        val prfEvalInput = if (passphraseMaterial == null) entry.salt else Crypto.framedBytes(entry.salt, passphraseMaterial)

        var unlockSecret: ByteArray? = null
        var aesKeyBytes: ByteArray? = null
        try {
            // Replay the verification mode this entry's key was created with (not necessarily this handle's).
            unlockSecret = HardwareKey.evaluateUnlockSecret(
                activity, entry.credentialIdentifier, prfEvalInput, prompt, entry.deviceCredentialAllowed,
            )
            aesKeyBytes = deriveAesKey(unlockSecret!!, passphraseMaterial, entry.salt, entry.credentialIdentifier, entryContext)
            val secretBytes = try {
                Crypto.aesGcmDecrypt(aesKeyBytes!!, entry.initializationVector, entry.ciphertext, additionalData)
            } catch (e: AEADBadTagException) {
                throw DeviceSealException.DecryptionFailed(e)
            }
            return CredentialResult(toPublicMetadata(entry), secretBytes)
        } finally {
            Crypto.zeroize(unlockSecret, aesKeyBytes, passphraseMaterial)
            if (passphraseMaterial != null) Crypto.zeroize(prfEvalInput)
        }
    }

    /**
     * Permanently deletes a stored credential and its hardware key. No user verification is required:
     * deletion exposes no plaintext, and a lost/unusable authenticator must still be able to clean up its own
     * entry. Irreversible. Equivalent to the browser's `removeCredential`.
     *
     * @return `true` if an entry was deleted, `false` if none matched (idempotent no-op).
     */
    suspend fun removeCredential(identifier: String): Boolean {
        require(identifier.isNotBlank()) { "identifier is required" }
        return withContext(Dispatchers.IO) {
            val entry = store.load(identifier) ?: return@withContext false
            store.delete(identifier)
            // Local ciphertext gone; now drop the hardware key so no orphaned key lingers (a reliable hard
            // delete, unlike the browser's best-effort credential-manager hint).
            HardwareKey.deleteUnlockKey(entry.credentialIdentifier)
            true
        }
    }

    /**
     * Deletes every stored credential in this database and each entry's hardware key. Like [removeCredential],
     * requires no user verification and is irreversible. Equivalent to `wipeVault`.
     *
     * @return the number of entries removed.
     */
    suspend fun wipeVault(): Int = withContext(Dispatchers.IO) {
        val entries = store.loadAll()
        if (entries.isEmpty()) return@withContext 0
        store.clear()
        for (entry in entries) HardwareKey.deleteUnlockKey(entry.credentialIdentifier)
        entries.size
    }

    /** Releases the underlying database connection. */
    fun close() = store.close()

    // === Internal helpers ===

    /**
     * HKDF-SHA-512 over the hardware HMAC output, with the passphrase material folded into the ikm (defense in
     * depth) exactly as the browser's `deriveSecretKey`. The intermediate ikm (allocated only when a
     * passphrase is set) is wiped immediately; the caller still wipes `unlockSecret` and `passphraseMaterial`.
     */
    private fun deriveAesKey(
        unlockSecret: ByteArray,
        passphraseMaterial: ByteArray?,
        salt: ByteArray,
        credentialIdentifier: ByteArray,
        context: String = applicationContext,
    ): ByteArray {
        val ikm = if (passphraseMaterial == null) unlockSecret else Crypto.framedBytes(unlockSecret, passphraseMaterial)
        try {
            return Crypto.hkdfSha512(ikm, salt, Crypto.keyInfoFor(context, credentialIdentifier))
        } finally {
            if (ikm !== unlockSecret) Crypto.zeroize(ikm)
        }
    }

    private fun normalizeSecret(secret: Secret?): ByteArray = when (secret) {
        null -> Crypto.randomBytes(DEFAULT_SECRET_BYTES)
        is Secret.Text -> secret.value.toByteArray(Charsets.UTF_8)
        is Secret.Bytes -> secret.value.copyOf()
    }

    // The single boundary returned to callers: every cryptographic field (salt, nonce, ciphertext, and the
    // application context) is dropped, so listing or returning an entry can never leak key material.
    private fun toPublicMetadata(entry: StoredEntry): CredentialMetadata = CredentialMetadata(
        identifier = entry.identifier,
        username = entry.username,
        label = entry.label,
        createdAt = entry.createdAt,
        passphrased = entry.passphrased,
        keyBacking = entry.keyBacking,
    )

    companion object {
        private const val DEFAULT_DATABASE_NAME = "passkeyVault"
        private const val DEFAULT_APPLICATION_VERSION = 1
        // Fallback namespace for any entry that somehow lacks a stored context (legacy parity).
        private const val DEFAULT_APPLICATION_CONTEXT = "passkey-vault/v1/"
        private const val SALT_BYTES = 32
        private const val CREDENTIAL_ID_BYTES = 16
        private const val DEFAULT_SECRET_BYTES = 32

        /**
         * Reports whether this device can protect secrets — i.e. can verify the user for the given mode —
         * without running a ceremony, prompting, or persisting anything. Intended for UIs that want to hide or
         * disable the feature before calling [createCredential]. Mirrors the browser's `isDeviceSupported`.
         *
         * @param allowDeviceCredential must match the value passed to the [DeviceSeal] constructor you intend
         *   to use: `false` checks for a Class-3 biometric; `true` also accepts a device credential.
         */
        fun isDeviceSupported(context: Context, allowDeviceCredential: Boolean = false): Boolean =
            HardwareKey.isUserVerificationAvailable(context, allowDeviceCredential)
    }
}
