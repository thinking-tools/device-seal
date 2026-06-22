import type {
  StoredEntry,
  StoredEntryRow,
  CredentialMetadata,
  CreateCredentialOptions,
  AccessCredentialOptions,
  ListCredentialsFilter,
  RemoveCredentialOptions,
  WipeVaultOptions,
  CredentialResult,
  VaultConfig,
} from './_types.js';
import {
  resolveStorageLocation,
  requestPersistentStorage,
  saveEntry,
  loadEntry,
  loadAllEntries,
  deleteEntry,
  clearEntries,
} from './_storage.js';
import {
  sha512,
  normalizeSecret,
  encrypt,
  decrypt,
  generateRandomBytes,
  registerPasskey,
  deriveSecretKey,
  evaluatePasskeySecret,
  derivePassphraseMaterial,
  bestEffortRemoveCredential,
} from './_crypto.js';
import { additionalDataFor, framedBytes, zeroize } from './_helpers.js';
import { resolveAppIdentitySync } from './_app-identity.js';

const DEFAULT_APPLICATION_NAME = 'passkey-vault';
const DEFAULT_APPLICATION_VERSION = 1;
// An application context is a namespace label (e.g. "passkey-vault/v1/") woven (length-framed) into both
// the key derivation and the authenticated data, so secrets from one app/version can never be unlocked as
// another. createCredential derives the live default from the environment (see below); this fixed constant
// is only the fallback accessCredential uses for legacy rows written before applicationContext was stored.
const DEFAULT_APPLICATION_CONTEXT = `${DEFAULT_APPLICATION_NAME}/v${DEFAULT_APPLICATION_VERSION}/`;

// === Public API

// The single boundary returned to callers: every cryptographic field (salt, nonce, ciphertext, and even
// the application context) is deliberately dropped, so listing or returning an entry can never leak key
// material. Never widen this to include a stored secret-bearing field.
const toPublicMetadata = (entry: StoredEntryRow): CredentialMetadata => ({
  identifier: entry.identifier,
  username: entry.username,
  label: entry.label,
  createdAt: entry.createdAt,
  passphrased: entry.passphrased,
});

/**
 * Registers a new device-bound passkey and stores a secret encrypted under it.
 * Prompts the user to create a passkey (user verification required), derives a non-extractable AES-GCM
 * key from the authenticator's PRF output and a per-entry salt, and persists only ciphertext.
 *
 * @param options.username Account username (required).
 * @param options.secret Secret to protect; a string is UTF-8 encoded, a Uint8Array is copied,
 *   and `undefined` generates a fresh random 32-byte secret.
 * @param options.label Human-friendly label; defaults to the username.
 * @param options.passphrase Optional second factor folded (via PBKDF2) into both the authenticator's PRF
 *   eval input and the key derivation, so each guess requires a live ceremony and a stolen vault cannot be
 *   brute-forced offline. When set to a non-empty string, the same passphrase is required on every access.
 *   An empty string is treated as no passphrase, so the entry is stored without passphrase protection
 *   (`passphrased: false`).
 * @param options.databaseName IndexedDB database to store the entry in (default `passkeyVault`).
 * @param options.databaseVersion Advanced: explicit IndexedDB version to open with. Omit to use the
 *   database's current version (created at version 1 on first use); only set this to drive an upgrade.
 * @param options.applicationName Crypto namespace bound into key derivation and authenticated data;
 *   recorded with the entry and reused automatically on access. Defaults to a stable, environment-derived
 *   identity (inline web-manifest id → real hostname → "app"); pass it explicitly to pin the namespace.
 * @param options.applicationVersion Crypto namespace version (default `1`).
 * @returns The public metadata of the stored entry and the protected secret bytes.
 */
export const createCredential = async (options: CreateCredentialOptions): Promise<CredentialResult> => {
  const { username, secret, label, passphrase } = options;
  if (!username) {
    throw new Error('Username is required');
  }
  const storageLocation = resolveStorageLocation(options);
  // No explicit applicationName → derive a stable, environment-based identity (inline manifest id → real
  // hostname → "app"; sync, no network) so secrets are namespaced per app and survive app updates. The
  // version segment is explicit: bumping applicationVersion deliberately rotates (orphans) older secrets.
  const applicationName = options.applicationName ?? resolveAppIdentitySync().id;
  const applicationVersion = options.applicationVersion ?? DEFAULT_APPLICATION_VERSION;
  const applicationContext = `${applicationName}/v${applicationVersion}/`;

  const secretBytes = normalizeSecret(secret);
  const salt = generateRandomBytes(32);
  const identifier = crypto.randomUUID();
  const additionalData = additionalDataFor(applicationContext, identifier);

  // Only the salt, nonce, and ciphertext are ever written to disk; the derived key is never stored and
  // never extractable. The passphrase (when set) is folded into the PRF eval input (and, in deriveSecretKey,
  // the HKDF ikm), so it must be derived before the ceremony, and a stolen vault cannot be brute-forced
  // offline (testing a guess needs a live authenticator ceremony).
  const passphraseEnabled = passphrase !== undefined && passphrase.length > 0;
  const passphraseMaterial = passphraseEnabled ? await derivePassphraseMaterial(passphrase, salt) : undefined;
  const prfEvalInput = passphraseMaterial === undefined ? salt : framedBytes(salt, passphraseMaterial);
  // Hold the raw PRF unlock secret in an outer binding so it can be wiped in the finally below, on success
  // or on a thrown/cancelled ceremony.
  let passkeySecret: BufferSource | undefined;
  try {
    const registration = await registerPasskey(applicationContext, username, await sha512(prfEvalInput));
    passkeySecret = registration.passkeySecret;
    const { credentialIdentifier } = registration;
    const key = await deriveSecretKey(
      passkeySecret,
      passphraseMaterial,
      salt,
      credentialIdentifier,
      applicationContext,
    );
    const { initializationVector, ciphertext } = await encrypt(key, secretBytes, additionalData);

    const entry: StoredEntry = {
      identifier,
      username,
      label: label ?? username,
      createdAt: new Date().toISOString(),
      applicationContext,
      credentialIdentifier,
      salt,
      initializationVector,
      ciphertext,
      passphrased: passphraseEnabled,
    };

    await requestPersistentStorage();
    await saveEntry(storageLocation, entry);

    return { entry: toPublicMetadata(entry), secret: secretBytes };
  } finally {
    // Best-effort wipe of raw key material now that the AES key is derived (see zeroize for limits). Never
    // wipe `salt` (persisted) or `secretBytes` (returned). prfEvalInput aliases `salt` when there is no
    // passphrase, so only the passphrased branch allocates buffers we own and may wipe.
    if (passkeySecret !== undefined) zeroize(passkeySecret);
    if (passphraseMaterial !== undefined) {
      zeroize(passphraseMaterial);
      zeroize(prfEvalInput);
    }
  }
};

/**
 * Lists stored credential metadata without decrypting anything or prompting the user.
 *
 * @param filter Optional `username` to narrow the results, plus
 *   `databaseName` (default `passkeyVault`) and advanced `databaseVersion` to select the store.
 * @returns Public metadata for every matching entry.
 */
export const listCredentials = async (filter: ListCredentialsFilter = {}): Promise<CredentialMetadata[]> => {
  const { username } = filter;
  const entries = await loadAllEntries(resolveStorageLocation(filter));
  return entries.filter(entry => username === undefined || entry.username === username).map(toPublicMetadata);
};

/**
 * Decrypts and returns a stored secret, prompting the user to verify on their authenticator.
 * The application namespace recorded at creation time is reused automatically and does not need
 * to be supplied again.
 *
 * @param options.identifier The `identifier` of the entry to unlock (required).
 * @param options.passphrase Required if the entry was created with one (check `passphrased` from
 *   listCredentials). Omitting it (or passing an empty string) for a protected entry throws before any
 *   authenticator prompt.
 * @param options.databaseName IndexedDB database the entry lives in (default `passkeyVault`).
 * @param options.databaseVersion Advanced: explicit IndexedDB version to open with; omit to use the
 *   database's current version.
 * @returns The entry's public metadata and the decrypted secret bytes.
 * @throws If no entry matches, or if the user cancels verification.
 */
export const accessCredential = async (options: AccessCredentialOptions): Promise<CredentialResult> => {
  const { identifier, passphrase } = options;
  if (!identifier) {
    throw new Error('identifier is required');
  }
  const entry = await loadEntry(resolveStorageLocation(options), identifier);
  if (!entry) {
    throw new Error('No stored credential with that identifier');
  }
  const passphraseRequired = entry.passphrased ?? false;
  const passphraseProvided = passphrase !== undefined && passphrase.length > 0;
  if (passphraseRequired && !passphraseProvided) {
    throw new Error('This credential requires a passphrase');
  }
  // Entries written before applicationContext was recorded fall back to the default namespace.
  const applicationContext = entry.applicationContext ?? DEFAULT_APPLICATION_CONTEXT;
  // Reverse the chain: a fresh verification yields the unlock secret, which re-derives the same key,
  // which decrypts the secret. The matching additionalData must be supplied or GCM rejects.
  const additionalData = additionalDataFor(applicationContext, entry.identifier);
  // Rebuild the same PRF eval input used at creation: the salt alone, or length-framed with the passphrase
  // material when the entry is passphrase-protected. A wrong passphrase yields a different eval input and
  // therefore a different PRF secret, so the key never re-derives and GCM rejects.
  const passphraseMaterial =
    passphraseRequired && passphrase !== undefined ? await derivePassphraseMaterial(passphrase, entry.salt) : undefined;
  const prfEvalInput = passphraseMaterial === undefined ? entry.salt : framedBytes(entry.salt, passphraseMaterial);
  // Hold the raw PRF unlock secret in an outer binding so it can be wiped in the finally below.
  let passkeySecret: BufferSource | undefined;
  try {
    passkeySecret = await evaluatePasskeySecret(entry.credentialIdentifier, await sha512(prfEvalInput));
    const key = await deriveSecretKey(
      passkeySecret,
      passphraseMaterial,
      entry.salt,
      entry.credentialIdentifier,
      applicationContext,
    );
    const secretBytes = await decrypt(key, entry.initializationVector, entry.ciphertext, additionalData);
    return { entry: toPublicMetadata(entry), secret: secretBytes };
  } finally {
    // Best-effort wipe of raw key material (see zeroize). Never wipe `entry.salt` (still part of the loaded
    // row) or `secretBytes` (returned). prfEvalInput aliases entry.salt without a passphrase, so only the
    // passphrased branch allocates buffers we own and may wipe.
    if (passkeySecret !== undefined) zeroize(passkeySecret);
    if (passphraseMaterial !== undefined) {
      zeroize(passphraseMaterial);
      zeroize(prfEvalInput);
    }
  }
};

/**
 * Permanently deletes a stored credential and best-effort asks the platform credential manager to drop
 * the now-orphaned passkey. No user verification is required: deletion exposes no plaintext, and any
 * same-origin caller could clear IndexedDB directly, so a ceremony would add a footgun (a lost or
 * unusable authenticator could never clean up its own entry) without adding security. This is
 * irreversible — the encrypted secret cannot be recovered afterwards.
 *
 * @param options.identifier The `identifier` of the entry to delete (required).
 * @param options.databaseName IndexedDB database the entry lives in (default `passkeyVault`).
 * @param options.databaseVersion Advanced: explicit IndexedDB version to open with; omit to use the
 *   database's current version.
 * @returns `true` if an entry was deleted, `false` if no entry matched (idempotent no-op).
 */
export const removeCredential = async (options: RemoveCredentialOptions): Promise<boolean> => {
  const { identifier } = options;
  if (!identifier) {
    throw new Error('identifier is required');
  }
  const storageLocation = resolveStorageLocation(options);
  const entry = await loadEntry(storageLocation, identifier);
  if (!entry) {
    return false;
  }
  await deleteEntry(storageLocation, identifier);
  // The local ciphertext is gone; now best-effort tell the authenticator to forget the orphaned passkey.
  await bestEffortRemoveCredential(entry.credentialIdentifier);
  return true;
};

/**
 * Deletes every stored credential in a database and best-effort asks the platform credential manager to
 * drop each now-orphaned passkey. Like removeCredential this requires no user verification and is
 * irreversible.
 *
 * @param options.databaseName IndexedDB database to empty (default `passkeyVault`).
 * @param options.databaseVersion Advanced: explicit IndexedDB version to open with; omit to use the
 *   database's current version.
 * @returns The number of entries removed.
 */
export const wipeVault = async (options: WipeVaultOptions = {}): Promise<number> => {
  const storageLocation = resolveStorageLocation(options);
  // Read the credential ids before clearing so each orphaned passkey can be signalled afterwards.
  const entries = await loadAllEntries(storageLocation);
  if (entries.length === 0) {
    return 0;
  }
  await clearEntries(storageLocation);
  await Promise.all(entries.map(entry => bestEffortRemoveCredential(entry.credentialIdentifier)));
  return entries.length;
};

/**
 * Creates a vault handle with shared configuration (database and application namespace) pre-bound, so the
 * common options don't have to be repeated on every call. The returned methods are thin wrappers over the
 * standalone functions; per-call options are merged over the bound config and may override it.
 *
 * @param config Shared options ({@link VaultConfig}) applied to every operation; all fields optional.
 * @returns An object exposing `create`, `access`, `list`, `remove`, and `wipe`, mirroring the standalone
 *   {@link createCredential}, {@link accessCredential}, {@link listCredentials}, {@link removeCredential},
 *   and {@link wipeVault} functions with the config pre-applied.
 */
export const createVault = (config: VaultConfig = {}) => ({
  create: (o: Omit<CreateCredentialOptions, keyof VaultConfig>) => createCredential({ ...config, ...o }),
  access: (o: Omit<AccessCredentialOptions, keyof VaultConfig>) => accessCredential({ ...config, ...o }),
  list: (f: Omit<ListCredentialsFilter, keyof VaultConfig> = {}) => listCredentials({ ...config, ...f }),
  remove: (o: Omit<RemoveCredentialOptions, keyof VaultConfig>) => removeCredential({ ...config, ...o }),
  wipe: (o: Omit<WipeVaultOptions, keyof VaultConfig> = {}) => wipeVault({ ...config, ...o }),
});
