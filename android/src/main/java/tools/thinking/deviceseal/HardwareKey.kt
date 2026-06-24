package tools.thinking.deviceseal

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * The hardware authenticator — the Android counterpart of the WebAuthn passkey + PRF extension the browser
 * build relies on. This is where "utilize the device TPM" actually happens.
 *
 * Each vault entry owns a dedicated **HMAC-SHA-256 key generated inside the Android Keystore**, preferring a
 * discrete **StrongBox** secure element and falling back to the **TEE** only when StrongBox is unavailable
 * (the achieved level is recorded as [KeyBacking]). The key is non-exportable — its bytes never leave secure
 * hardware — and is marked `setUserAuthenticationRequired(true)`, so every use must be authorized by a fresh
 * verification. That key is the precise analog of a passkey:
 *
 *   - WebAuthn PRF is HMAC-SHA-256 (`hmac-secret`) evaluated inside the authenticator; here it is HMAC-SHA-256
 *     evaluated inside the Keystore. Same primitive, same 32-byte output, so the rest of the envelope
 *     (HKDF-SHA-512 → AES-256-GCM) is byte-for-byte the TypeScript design. SHA-256 is also the one HMAC
 *     variant a StrongBox is guaranteed to implement (key sizes 8–64 bytes), which is why the unlock secret
 *     uses it while the derivation layer keeps SHA-512.
 *   - WebAuthn binds a credential to an origin (rpId = hostname); the Keystore binds a key to this app's UID
 *     and signing identity and to this device. Another app cannot use the key, and the key cannot be lifted
 *     off the device — the same "can only be unlocked where it was created" guarantee.
 *   - WebAuthn requires user verification on every ceremony; the auth-required key enforces the same.
 *
 * ## Two verification modes (a hard Android constraint, not a preference)
 *
 * A [BiometricPrompt.CryptoObject] — which binds an authentication to one specific crypto operation — CANNOT
 * be combined with `DEVICE_CREDENTIAL` (PIN/pattern/password) as an allowed authenticator. So the caller picks
 * one of two bindings via `allowDeviceCredential`:
 *
 *   - **false (default, strongest):** per-use auth (`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`)
 *     with a `CryptoObject(Mac)`. The HMAC is cryptographically bound to that exact Class-3 biometric auth;
 *     there is no window in which the key is usable without it. Requires an enrolled biometric.
 *   - **true:** time-bound auth (`setUserAuthenticationParameters(window, AUTH_BIOMETRIC_STRONG |
 *     AUTH_DEVICE_CREDENTIAL)`) with NO `CryptoObject`. Biometric or device credential (PIN) unlocks, matching
 *     the browser's availability, but the key is merely usable for a short window after a successful auth — a
 *     weaker, non-per-operation binding.
 *
 * The mode is fixed into the Keystore key at creation, so [DeviceSeal] persists it per entry and replays the
 * SAME mode on access.
 */
internal object HardwareKey {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val MAC_ALGORITHM = "HmacSHA256"
    private const val HMAC_KEY_BITS = 256
    private const val ALIAS_PREFIX = "device-seal/"

    // Mode-B time-bound validity window (seconds): how long after a successful auth the key stays usable. Kept
    // short to minimise the window, since this mode cannot bind the auth to the specific HMAC operation. The
    // HMAC runs immediately after the prompt returns, so this is slack, not a usable idle period.
    private const val AUTH_WINDOW_SECONDS = 5

    private val keyStore: KeyStore by lazy { KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) } }

    /**
     * Reports whether this device can verify the user for the chosen mode — the analog of the browser's PRF
     * capability pre-flight. Mode A needs a Class-3 biometric; Mode B accepts a biometric or device credential.
     * Returns true only on an explicit `BIOMETRIC_SUCCESS`: there is no offline-software fallback by design.
     */
    fun isUserVerificationAvailable(context: Context, allowDeviceCredential: Boolean): Boolean =
        BiometricManager.from(context).canAuthenticate(authenticatorsFor(allowDeviceCredential)) ==
            BiometricManager.BIOMETRIC_SUCCESS

    /** Informational: whether a discrete StrongBox secure element is present (preferred, never required). */
    fun hasStrongBox(context: Context): Boolean =
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    /**
     * Generates this entry's hardware credential and returns the backing actually achieved. Tries StrongBox
     * first; `generateKey()` throws [StrongBoxUnavailableException] when the device has no StrongBox (or the
     * algorithm/key size is unsupported there), so we catch it and regenerate on the TEE — never silently
     * downgrading to software. Generation needs no user verification (mirroring passkey creation); the first
     * *use* in createCredential does.
     */
    fun generateUnlockKey(credentialIdentifier: ByteArray, allowDeviceCredential: Boolean): KeyBacking {
        val alias = aliasFor(credentialIdentifier)
        return try {
            buildKey(alias, allowDeviceCredential, strongBox = true)
            KeyBacking.STRONGBOX
        } catch (_: StrongBoxUnavailableException) {
            buildKey(alias, allowDeviceCredential, strongBox = false)
            KeyBacking.TEE
        }
    }

    private fun buildKey(alias: String, allowDeviceCredential: Boolean, strongBox: Boolean) {
        val authTypes = if (allowDeviceCredential) {
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
        } else {
            KeyProperties.AUTH_BIOMETRIC_STRONG
        }
        // Mode A binds per-operation via a CryptoObject, so the key needs no validity window (timeout 0 =
        // auth-per-use). Mode B cannot use a CryptoObject (device credential forbids it), so it binds by a
        // short time window instead.
        val authTimeoutSeconds = if (allowDeviceCredential) AUTH_WINDOW_SECONDS else 0

        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            // No setDigests(): for KEY_ALGORITHM_HMAC_SHA256 the digest is fixed by the algorithm. Setting one
            // is redundant and a mismatched digest throws.
            .setKeySize(HMAC_KEY_BITS)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(authTimeoutSeconds, authTypes)
            // Survive biometric re-enrollment, matching the browser build where the PRF survives adding a
            // fingerprint. Flipping this to true is legitimate hardening (a new enrollment then permanently
            // destroys the vault) but is a footgun absent in the browser, so the faithful default is false.
            .setInvalidatedByBiometricEnrollment(false)
        if (strongBox) builder.setIsStrongBoxBacked(true)

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
        generator.init(builder.build())
        generator.generateKey()
    }

    /**
     * Runs a user-verification ceremony and returns this credential's unlock secret — the one input that
     * requires the physical device and a present, verified human, and is never stored. The HMAC is computed
     * inside secure hardware; only its 32-byte output crosses back into app memory (where the caller wipes it
     * after derivation). Equivalent to the browser's `evaluatePasskeySecret`.
     *
     * `allowDeviceCredential` must match how this entry's key was created (see the two modes above);
     * [DeviceSeal] passes the value it persisted for the entry. BiometricPrompt must be driven from the main
     * thread and a [FragmentActivity], so the ceremony is marshalled onto [Dispatchers.Main]; the HMAC is
     * negligible work.
     */
    suspend fun evaluateUnlockSecret(
        activity: FragmentActivity,
        credentialIdentifier: ByteArray,
        prfEvalInput: ByteArray,
        prompt: PromptCopy,
        allowDeviceCredential: Boolean,
    ): ByteArray = withContext(Dispatchers.Main.immediate) {
        val alias = aliasFor(credentialIdentifier)
        val key = keyStore.getKey(alias, null) as? SecretKey
            ?: throw DeviceSealException.HardwareKeyMissing(alias)
        val mac = Mac.getInstance(MAC_ALGORITHM)
        // sha512 over the eval input mirrors the browser (which evaluates its PRF over SHA-512(prfEvalInput))
        // and also normalises arbitrary-length input down to a fixed 64 bytes before the HMAC.
        val digestInput = Crypto.sha512(prfEvalInput)
        val promptInfo = promptInfo(prompt, allowDeviceCredential)

        if (allowDeviceCredential) {
            // Mode B: authenticate WITHOUT a CryptoObject (device credential forbids one), then use the key
            // within its short validity window.
            authenticate(activity, promptInfo, cryptoObject = null)
            initMac(mac, key, alias)
            try {
                mac.doFinal(digestInput)
            } catch (e: UserNotAuthenticatedException) {
                // The validity window elapsed between the prompt and the HMAC (rare; the call is immediate).
                throw DeviceSealException.AuthenticationFailed("Authentication expired before the key could be used", code = null)
            }
        } else {
            // Mode A: bind the exact HMAC operation to this authentication via a CryptoObject.
            initMac(mac, key, alias)
            val authenticated = authenticate(activity, promptInfo, BiometricPrompt.CryptoObject(mac))
            val authenticatedMac = authenticated.cryptoObject?.mac
                ?: throw DeviceSealException.AuthenticationFailed("Authentication returned no crypto object", code = null)
            authenticatedMac.doFinal(digestInput)
        }
    }

    /**
     * Hard-deletes this entry's hardware key. On the web `signalUnknownCredential` is only a best-effort hint
     * the platform may ignore; here the app fully owns its Keystore aliases, so removal is reliable and
     * complete. Safe to call for an absent alias.
     */
    fun deleteUnlockKey(credentialIdentifier: ByteArray) {
        val alias = aliasFor(credentialIdentifier)
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    // init() does no gated work; for Mode A the doFinal() is what the CryptoObject-bound auth authorizes.
    private fun initMac(mac: Mac, key: SecretKey, alias: String) {
        try {
            mac.init(key)
        } catch (e: KeyPermanentlyInvalidatedException) {
            // The secure lock screen was removed (or biometrics re-enrolled when invalidation is on),
            // destroying the key — the entry is now permanently unrecoverable, by the no-recovery design.
            throw DeviceSealException.HardwareKeyInvalidated(alias, e)
        }
    }

    private fun authenticatorsFor(allowDeviceCredential: Boolean): Int =
        if (allowDeviceCredential) {
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        }

    private fun promptInfo(prompt: PromptCopy, allowDeviceCredential: Boolean): BiometricPrompt.PromptInfo {
        val builder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(prompt.title)
            .setAllowedAuthenticators(authenticatorsFor(allowDeviceCredential))
        prompt.subtitle?.let(builder::setSubtitle)
        prompt.description?.let(builder::setDescription)
        // A negative button is REQUIRED when device credential is NOT allowed, and FORBIDDEN when it is (the
        // system then supplies the PIN/password fallback affordance) — BiometricPrompt throws on the wrong one.
        if (!allowDeviceCredential) builder.setNegativeButtonText(prompt.negativeButtonText)
        return builder.build()
    }

    // Bridges BiometricPrompt's callback API into a cancellable coroutine. A single non-matching attempt
    // (onAuthenticationFailed) leaves the prompt up and is intentionally not surfaced; only a terminal error or
    // success resumes. Cancelling the coroutine dismisses the prompt.
    private suspend fun authenticate(
        activity: FragmentActivity,
        promptInfo: BiometricPrompt.PromptInfo,
        cryptoObject: BiometricPrompt.CryptoObject?,
    ): BiometricPrompt.AuthenticationResult = suspendCancellableCoroutine { continuation ->
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (continuation.isActive) continuation.resume(result)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (!continuation.isActive) return
                val isCancellation = errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                    errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                    errorCode == BiometricPrompt.ERROR_CANCELED
                continuation.resumeWithException(
                    if (isCancellation) DeviceSealException.UserCancelled()
                    else DeviceSealException.AuthenticationFailed(errString.toString(), errorCode),
                )
            }
        }
        val biometricPrompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
        continuation.invokeOnCancellation { runCatching { biometricPrompt.cancelAuthentication() } }
        if (cryptoObject != null) biometricPrompt.authenticate(promptInfo, cryptoObject)
        else biometricPrompt.authenticate(promptInfo)
    }

    private fun aliasFor(credentialIdentifier: ByteArray): String =
        ALIAS_PREFIX + Base64.encodeToString(credentialIdentifier, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
}
