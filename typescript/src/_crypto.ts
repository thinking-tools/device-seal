import type { Bytes } from './_types.js';
import { textEncoder, framedBytes, asBytes } from './_helpers.js';

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

export const derivePassphraseMaterial = async (passphrase: string, salt: Bytes): Promise<Bytes> => {
  const PBKDF2_ITERATIONS = 700_000;
  const baseKey = await crypto.subtle.importKey('raw', textEncoder.encode(passphrase), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-512', salt, iterations: PBKDF2_ITERATIONS },
    baseKey,
    256,
  );
  return new Uint8Array(bits);
};

export const generateRandomBytes = (length: number): Bytes => crypto.getRandomValues(new Uint8Array(length));

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
// `salt` is a public, per-entry random value; it doubles as the authenticator's PRF eval input (see the
// ceremonies below). Reusing one public random value across those two unrelated keyed functions weakens
// neither, and the PRF output is already uniformly random, so HKDF gains nothing from an independent salt.
export const deriveSecretKey = async (
  passkeySecret: BufferSource,
  passphraseMaterial: Bytes | undefined,
  salt: Bytes,
  credentialIdentifier: Bytes,
  applicationContext: string,
): Promise<CryptoKey> => {
  const inputKeyMaterial =
    passphraseMaterial === undefined ? asBytes(passkeySecret) : framedBytes(asBytes(passkeySecret), passphraseMaterial);

  const baseKey = await crypto.subtle.importKey('raw', inputKeyMaterial, 'HKDF', false, ['deriveKey']);
  // The info uses the same length-framing as the authenticated data, pinned to the credential id, so
  // every credential derives its own key and namespaces never collide.
  const info = framedBytes(textEncoder.encode(applicationContext), credentialIdentifier);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-512', salt, info },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
};

const ensurePasskeySupport = (): void => {
  if (!window.PublicKeyCredential || !navigator.credentials) {
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
  const capabilities = await window.PublicKeyCredential.getClientCapabilities?.();
  if (capabilities?.['extension:prf'] === false) {
    throw new Error('This browser does not support the WebAuthn PRF extension required to protect secrets');
  }
};

// base64url-encodes a credential id for the WebAuthn signal API, which takes a Base64URLString, not bytes.
const toBase64Url = (bytes: Bytes): string => {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
};

// Best-effort cleanup for a credential we no longer want stored — a failed registration, or an explicit
// removeCredential/wipeVault. signalUnknownCredential() asks the
// platform credential manager to drop a credential the relying party no longer recognizes — it is a hint
// (the manager decides) and is not yet universally supported, so a missing method or any rejection is
// swallowed. This shrinks, but cannot guarantee removal of, the orphan a non-PRF authenticator can leave
// behind: capabilities are client-level, so the pre-flight above cannot prevent that one credential.
export const bestEffortRemoveCredential = async (credentialIdentifier: Bytes): Promise<void> => {
  // Guard for non-browser/SSR (no `window`) and clients without the signal API; either way there is no
  // credential manager to hint, so quietly skip. This also lets removeCredential/wipeVault purge local
  // data when WebAuthn is unavailable.
  if (typeof window === 'undefined' || typeof window.PublicKeyCredential?.signalUnknownCredential !== 'function')
    return;
  try {
    await window.PublicKeyCredential.signalUnknownCredential({
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
  salt: Bytes,
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
        residentKey: 'preferred',
        userVerification: 'required',
      },
      extensions: { prf: { eval: { first: salt } } },
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
    // persisted here. If the authenticator explicitly reports PRF disabled, a follow-up assertion cannot
    // yield a secret either, so fail now instead of firing a second, doomed user-verification prompt. The
    // client-level pre-flight cannot prevent reaching here — only the authenticator knows it lacks PRF.
    if (secretFromCreation === undefined && prf?.enabled === false) {
      throw new Error('This authenticator does not support the WebAuthn PRF extension required to protect secrets');
    }
    const passkeySecret = secretFromCreation ?? (await evaluatePasskeySecret(credentialIdentifier, salt));
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
// salt — the one input that requires the physical authenticator and a present human, and is never stored.
export const evaluatePasskeySecret = async (credentialIdentifier: Bytes, salt: Bytes): Promise<BufferSource> => {
  ensurePasskeySupport();
  const assertion = (await navigator.credentials.get({
    signal: AbortSignal.timeout(120_000),
    publicKey: {
      rpId: relyingPartyIdentifier(),
      challenge: generateRandomBytes(32),

      allowCredentials: [{ type: 'public-key', id: credentialIdentifier }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: salt } } },
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
