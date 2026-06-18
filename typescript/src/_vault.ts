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
import { additionalDataFor } from './_helpers.js';
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
 * @param options.passphrase Optional second factor folded into the key via PBKDF2; when set to a
 *   non-empty string, the same passphrase is required on every access. An empty string is treated as
 *   no passphrase, so the entry is stored without passphrase protection (`passphrased: false`).
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
  // never extractable.
  const { credentialIdentifier, passkeySecret } = await registerPasskey(applicationContext, username, salt);
  const passphraseEnabled = passphrase !== undefined && passphrase.length > 0;
  const passphraseMaterial = passphraseEnabled ? await derivePassphraseMaterial(passphrase, salt) : undefined;
  const key = await deriveSecretKey(passkeySecret, passphraseMaterial, salt, credentialIdentifier, applicationContext);
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
  const passkeySecret = await evaluatePasskeySecret(entry.credentialIdentifier, entry.salt);

  const passphraseMaterial =
    passphraseRequired && passphrase !== undefined ? await derivePassphraseMaterial(passphrase, entry.salt) : undefined;
  const key = await deriveSecretKey(
    passkeySecret,
    passphraseMaterial,
    entry.salt,
    entry.credentialIdentifier,
    applicationContext,
  );
  const secretBytes = await decrypt(key, entry.initializationVector, entry.ciphertext, additionalData);
  return { entry: toPublicMetadata(entry), secret: secretBytes };
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

export const createVault = (config: VaultConfig = {}) => ({
  create: (o: Omit<CreateCredentialOptions, keyof VaultConfig>) => createCredential({ ...config, ...o }),
  access: (o: Omit<AccessCredentialOptions, keyof VaultConfig>) => accessCredential({ ...config, ...o }),
  list: (f: Omit<ListCredentialsFilter, keyof VaultConfig> = {}) => listCredentials({ ...config, ...f }),
  remove: (o: Omit<RemoveCredentialOptions, keyof VaultConfig>) => removeCredential({ ...config, ...o }),
  wipe: (o: Omit<WipeVaultOptions, keyof VaultConfig> = {}) => wipeVault({ ...config, ...o }),
});
