import type { Bytes } from './_types.js';
import { textEncoder, framedBytes, asBytes, zeroize } from './_helpers.js';

// WebAuthn binds every credential to one hostname, so entries created here can only be unlocked here:
// opening the stored data from a different hostname will not decrypt, because the rpId no longer matches.
// This must be the raw location.hostname (WebAuthn rejects any rpId that isn't a registrable suffix of
// the origin), so it is deliberately NOT the _app-identity value — that may be a bundle id or "app", and
// it must stay the hostname even on localhost. Read lazily, at ceremony time rather than module load, so
// importing the package never touches `location`: that keeps the module graph side-effect-free (honestly
// tree-shakable, import-safe in Node/SSR/bundlers). It only runs after ensurePasskeySupport().
const relyingPartyIdentifier = (): string => location.hostname;
const PUBKEY_CRED_PARAMS = [
  { type: 'public-key', alg: -50 }, // ML-DSA-87
  { type: 'public-key', alg: -49 }, // ML-DSA-65
  { type: 'public-key', alg: -48 }, // ML-DSA-44
  { type: 'public-key', alg: -8 }, // EdDSA/Ed25519
  { type: 'public-key', alg: -7 }, // ES256  (universal default)
  { type: 'public-key', alg: -257 }, // RS256  (legacy: TPM/Windows Hello)
] satisfies PublicKeyCredentialParameters[];

// Stretches the optional passphrase into 32 fixed bytes that are length-framed into the PRF eval input
// (not the HKDF key). PBKDF2 is not the primary barrier here — the authenticator-in-the-loop is — but it
// adds per-guess cost as defense in depth should an authenticator's PRF secret ever be extracted.
export const derivePassphraseMaterial = async (passphrase: string, salt: Bytes): Promise<Bytes> => {
  const PBKDF2_ITERATIONS = 700_000;
  const passphraseBytes = textEncoder.encode(passphrase);
  try {
    const baseKey = await crypto.subtle.importKey('raw', passphraseBytes, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-512', salt, iterations: PBKDF2_ITERATIONS },
      baseKey,
      256,
    );
    return new Uint8Array(bits);
  } finally {
    // Wipe our UTF-8 copy of the passphrase; PBKDF2 has absorbed it into baseKey. The original `passphrase`
    // string is immutable and cannot be wiped (it lingers until GC) — this only clears the bytes we control.
    zeroize(passphraseBytes);
  }
};

export const generateRandomBytes = (length: number): Bytes => crypto.getRandomValues(new Uint8Array(length));

// SHA-512 over the given bytes, returned as bytes. Thin wrapper over crypto.subtle.digest so callers get a
// non-shared Uint8Array<ArrayBuffer> (Bytes) rather than a raw ArrayBuffer.
export const sha512 = async (data: Bytes): Promise<Bytes> =>
  new Uint8Array(await crypto.subtle.digest('SHA-512', data));

// Encrypts the secret under the derived key, with a fresh 12-byte AES-GCM nonce; additionalData ties the
// ciphertext to this entry.
export const encrypt = async (
  key: CryptoKey,
  plaintextBytes: Bytes,
  additionalData: Bytes,
): Promise<{ initializationVector: Bytes; ciphertext: Bytes }> => {
  const initializationVector = generateRandomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: initializationVector, additionalData },
    key,
    plaintextBytes,
  );
  return { initializationVector, ciphertext: new Uint8Array(ciphertext) };
};

// Reverses encrypt. A wrong key, a tampered blob, or mismatched additionalData all fail the GCM tag here
// and reject, so nothing usable comes back without a live, user-verified passkey.
export const decrypt = (
  key: CryptoKey,
  initializationVector: Bytes,
  ciphertext: Bytes,
  additionalData: Bytes,
): Promise<Bytes> =>
  crypto.subtle
    .decrypt({ name: 'AES-GCM', iv: initializationVector, additionalData }, key, ciphertext)
    .then(plaintext => new Uint8Array(plaintext));

// === Key derivation

// HKDF blends the unlock secret (the only human-gated input) with a per-entry salt and an info label
// pinning the key to this application context and this credential, so keys never cross between entries or
// apps. The result is non-extractable and used only to encrypt/decrypt — it is the single key over the
// plaintext and never leaves WebCrypto.
//
// The passphrase (when set) is bound in TWO places: primarily into the authenticator's PRF eval input
// upstream (so testing a guess requires a live ceremony and a stolen vault cannot be brute-forced
// offline), and additionally — via `passphraseMaterial` here — into this HKDF ikm as defense in depth, so
// the key still needs the passphrase even if a PRF output ever leaked. The PRF-input binding is what makes
// guessing online-only; the HKDF binding alone would not (a captured PRF output could be brute-forced
// locally).
//
// `salt` is a public, per-entry random value used here as the HKDF salt; it is also the base of the PRF
// eval input (alone when there is no passphrase, length-framed with the passphrase material when there is).
// Reusing one public random value across those unrelated keyed functions weakens neither, and the PRF
// output is already uniformly random, so HKDF gains nothing from an independent salt.
export const deriveSecretKey = async (
  passkeySecret: BufferSource,
  passphraseMaterial: Bytes | undefined,
  salt: Bytes,
  credentialIdentifier: Bytes,
  applicationContext: string,
): Promise<CryptoKey> => {
  const inputKeyMaterial =
    passphraseMaterial === undefined ? asBytes(passkeySecret) : framedBytes(asBytes(passkeySecret), passphraseMaterial);

  try {
    const baseKey = await crypto.subtle.importKey('raw', inputKeyMaterial, 'HKDF', false, ['deriveKey']);
    // The info uses the same length-framing as the authenticated data, pinned to the credential id, so
    // every credential derives its own key and namespaces never collide.
    const info = framedBytes(textEncoder.encode(applicationContext), credentialIdentifier);
    return await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-512', salt, info },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  } finally {
    // inputKeyMaterial is our only raw copy of the combined key material (a copy of passkeySecret, plus the
    // passphrase material when set); the non-extractable baseKey now holds it, so wipe ours best-effort
    // whether derivation succeeded or threw. The caller still wipes passkeySecret/passphraseMaterial.
    zeroize(inputKeyMaterial);
  }
};

const ensurePasskeySupport = (): void => {
  if (!globalThis.PublicKeyCredential || !navigator.credentials) {
    throw new Error('WebAuthn is not available in this browser');
  }
};

// Pre-flight PRF check, run before create() persists a credential. getClientCapabilities() reports whether
// the CLIENT (browser) implements the PRF extension; abort only when it is explicitly false. An absent map
// or missing key means "unknown" (older clients predate this API) and falls through to the post-create
// check in registerPasskey — blocking on unknown would lock out authenticators that do support PRF. This
// stops the common "browser can't do PRF at all" case from creating a credential we could never unlock (a
// discoverable one becomes an orphaned passkey the relying party cannot delete). It cannot catch a
// PRF-capable client paired with a non-PRF authenticator: capabilities are client-level, not per-device.
const ensurePrfClientSupport = async (): Promise<void> => {
  const capabilities = await globalThis.PublicKeyCredential.getClientCapabilities?.();
  if (capabilities?.['extension:prf'] === false) {
    throw new Error('This browser does not support the WebAuthn PRF extension required to protect secrets');
  }
};

/**
 * Reports whether this client can protect secrets with the WebAuthn PRF extension, without running a
 * ceremony, prompting the user, or persisting anything. Intended for UIs that want to hide or disable the
 * feature before calling {@link createCredential}.
 *
 * Returns `false` when WebAuthn is unavailable — no `PublicKeyCredential` (it is `[SecureContext]`-gated, so
 * absent over plain HTTP and in non-browser runtimes) or no `navigator.credentials` — or when the client
 * explicitly reports the PRF extension unsupported. Returns `true` when the client supports PRF, or when
 * support is unknown (older clients predate `getClientCapabilities()`), mirroring the registration
 * pre-flight's "block only on an explicit no" policy so PRF-capable authenticators are never pre-emptively
 * locked out.
 *
 * IMPORTANT: capabilities are client-level, not per-authenticator. A `true` result means the *browser* can
 * do PRF; it cannot guarantee the authenticator the user ultimately selects supports it — a password
 * manager that stores passkeys without `hmac-secret` (e.g. Bitwarden on Android) passes this check yet
 * still fails the ceremony. Only {@link createCredential} knows for certain, and it throws if the chosen
 * authenticator lacks PRF. Use this to gate the UI; always still handle a `createCredential` rejection.
 *
 * @returns `true` if the client plausibly supports PRF-protected secrets, `false` if it definitely does not.
 */
export const isDeviceSupported = async (): Promise<boolean> => {
  if (!globalThis.PublicKeyCredential || !globalThis.navigator?.credentials) {
    return false;
  }
  const capabilities = await globalThis.PublicKeyCredential.getClientCapabilities?.();
  return capabilities?.['extension:prf'] !== false;
};

// base64url-encodes a credential id for the WebAuthn signal API, which takes a Base64URLString, not bytes.
const toBase64Url = (bytes: Bytes): string => {
  let binary = '';
  for (const byte of bytes) binary += String.fromCodePoint(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
};

// Best-effort cleanup for a credential we no longer want stored — a failed registration, or an explicit
// removeCredential/wipeVault. signalUnknownCredential() asks the
// platform credential manager to drop a credential the relying party no longer recognizes — it is a hint
// (the manager decides) and is not yet universally supported, so a missing method or any rejection is
// swallowed. This shrinks, but cannot guarantee removal of, the orphan a non-PRF authenticator can leave
// behind: capabilities are client-level, so the pre-flight above cannot prevent that one credential.
export const bestEffortRemoveCredential = async (credentialIdentifier: Bytes): Promise<void> => {
  // Guard for non-browser/SSR and clients without the signal API: with no `PublicKeyCredential` (Node/SSR)
  // or one lacking signalUnknownCredential, there is no credential manager to hint, so quietly skip. This
  // also lets removeCredential/wipeVault purge local data when WebAuthn is unavailable.
  if (typeof globalThis.PublicKeyCredential?.signalUnknownCredential !== 'function') return;
  try {
    await globalThis.PublicKeyCredential.signalUnknownCredential({
      rpId: relyingPartyIdentifier(),
      credentialId: toBase64Url(credentialIdentifier),
    });
  } catch {
    // hint-only; if the manager declines or the API rejects there is nothing more we can do
  }
};

// === Passkey ceremonies

// Creates the passkey and obtains the unlock secret. Resident key + required user verification mean the
// credential is discoverable by id later and always demands a present, verified human.
export const registerPasskey = async (
  appName: string,
  username: string,
  prfEvalInput: Bytes,
): Promise<{ credentialIdentifier: Bytes; passkeySecret: BufferSource }> => {
  ensurePasskeySupport();
  await ensurePrfClientSupport();
  const credential = (await navigator.credentials.create({
    publicKey: {
      rp: { id: relyingPartyIdentifier(), name: appName },
      user: {
        id: generateRandomBytes(16),
        name: username,
        displayName: username,
      },
      challenge: generateRandomBytes(32),
      timeout: 1000 * 120,
      // These signing algorithms only gate user verification; they never enter the encryption path, so
      // their classical (non-quantum-resistant) nature does not weaken the stored secret's confidentiality.
      pubKeyCredParams: PUBKEY_CRED_PARAMS,
      authenticatorSelection: {
        // no authenticatorAttachment → user may pick built-in biometric, a security key, or their phone
        residentKey: 'preferred',
        userVerification: 'required',
      },
      extensions: { prf: { eval: { first: prfEvalInput } } },
    },
  })) as PublicKeyCredential | null;
  if (!credential) {
    throw new Error('Passkey creation was cancelled');
  }
  const credentialIdentifier = new Uint8Array(credential.rawId);
  try {
    // Some authenticators return the PRF secret right here at creation; others reveal it only on a later
    // get() assertion. Prefer the direct result, and fall back to a verification ceremony when absent.
    const prf = credential.getClientExtensionResults().prf;
    const secretFromCreation = prf?.results?.first;
    // create() ignores an unsupported extension rather than failing, so the credential is already
    // persisted here. With no secret from creation, a follow-up assertion is worth attempting only when the
    // authenticator affirmatively reports PRF support (`enabled === true`) — the load-bearing
    // dual-evaluation path for authenticators that defer the secret to get(). Every other shape means a
    // doomed get(): `enabled === false` is an explicit "no", and a missing `enabled` (`undefined`, or no
    // prf output at all) is a credential manager that ignored the prf extension — e.g. a passkey provider
    // without hmac-secret support, like Bitwarden on Android — so support was never confirmed and the
    // assertion cannot produce a secret. Fail now instead of firing a second, doomed user-verification
    // prompt. The client-level pre-flight cannot prevent reaching here — only the authenticator knows.
    if (secretFromCreation === undefined && prf?.enabled !== true) {
      throw new Error('This authenticator does not support the WebAuthn PRF extension required to protect secrets');
    }
    const passkeySecret = secretFromCreation ?? (await evaluatePasskeySecret(credentialIdentifier, prfEvalInput));
    return { credentialIdentifier, passkeySecret };
  } catch (error) {
    // We persisted a credential we cannot use (no PRF secret, or the user cancelled the fallback
    // assertion), and WebAuthn has no relying-party-side delete. Best-effort: ask the credential manager
    // to drop this orphan so retries do not pile up dead passkeys, then surface the original failure.
    await bestEffortRemoveCredential(credentialIdentifier);
    throw error;
  }
};

// Runs a user-verification ceremony and returns the authenticator's PRF secret for this credential and
// eval input — the one input that requires the physical authenticator and a present human, and is never
// stored. The eval input is the per-entry salt, optionally length-framed with the passphrase material so
// the secret is bound to the passphrase and cannot be reproduced for another guess without a fresh ceremony.
export const evaluatePasskeySecret = async (
  credentialIdentifier: Bytes,
  prfEvalInput: Bytes,
): Promise<BufferSource> => {
  ensurePasskeySupport();
  const assertion = (await navigator.credentials.get({
    signal: AbortSignal.timeout(120_000),
    publicKey: {
      rpId: relyingPartyIdentifier(),
      challenge: generateRandomBytes(32),

      allowCredentials: [{ type: 'public-key', id: credentialIdentifier }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: prfEvalInput } } },
    },
  })) as PublicKeyCredential | null;
  if (!assertion) {
    throw new Error('Passkey verification was cancelled');
  }
  const passkeySecret = assertion.getClientExtensionResults().prf?.results?.first;
  if (!passkeySecret) {
    throw new Error('This authenticator did not return a pseudo-random-function secret');
  }
  return passkeySecret;
};

// Normalizes the caller's secret into owned bytes: a string is UTF-8 encoded, a Uint8Array is copied
// (so later mutation of their array cannot change what we encrypted), and undefined generates a fresh
// random 32-byte secret for callers who just want a generated key.
export const normalizeSecret = (secret: string | Uint8Array | undefined): Bytes => {
  if (secret === undefined) return generateRandomBytes(32);
  if (typeof secret === 'string') return textEncoder.encode(secret);
  return new Uint8Array(secret);
};
