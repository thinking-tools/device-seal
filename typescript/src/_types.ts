/**
 * Shared configuration pre-bound to a vault handle by {@link createVault}, so the common options don't have
 * to be repeated on every call. Every field is optional and is merged into each operation's options, which
 * may still override it.
 */
export type VaultConfig = Partial<{
  /** IndexedDB database the entries live in (default `passkeyVault`). */
  databaseName: string;
  /** Advanced: explicit IndexedDB version to open with; omit to use the database's current version. */
  databaseVersion: number;
  /** Crypto namespace bound into key derivation; defaults to a stable, environment-derived identity. */
  applicationName: string;
  /** Crypto namespace version (default `1`); bumping it deliberately rotates (orphans) older secrets. */
  applicationVersion: number;
}>;

/** Byte buffer guaranteed to be backed by a non-shared ArrayBuffer, as WebCrypto/WebAuthn require. */
export type Bytes = Uint8Array<ArrayBuffer>;

/** Which IndexedDB database the entries live in; configurable so apps can namespace their own store. */
export interface StorageLocation {
  databaseName: string;
  // Omitted (undefined) opens the database at its current version; IndexedDB versions only ever
  // increase, so a fixed default would throw once any caller upgraded the store.
  databaseVersion: number | undefined;
}

// One persisted record. The first fields are public metadata; applicationContext is non-secret but
// internal (never returned to callers); everything from credentialIdentifier downward is an opaque salt,
// nonce, and ciphertext — inert without a live, user-verified passkey.
export interface StoredEntry {
  identifier: string;
  username: string;
  label: string;
  createdAt: string;
  applicationContext: string;
  credentialIdentifier: Bytes;
  salt: Bytes;
  initializationVector: Bytes;
  ciphertext: Bytes;
  passphrased: boolean;
}

// Shape of a row read back from IndexedDB: persisted blobs are outside the type system and may predate
// fields added later, so applicationContext is optional on read (createCredential always writes it).
export type StoredEntryRow = Omit<StoredEntry, 'applicationContext'> & {
  applicationContext?: string;
};

/**
 * Public, non-secret metadata for a stored entry — the only shape ever returned to callers. Deliberately
 * carries no cryptographic field (salt, nonce, ciphertext, or application context), so listing or returning
 * an entry can never leak key material.
 */
export interface CredentialMetadata {
  /** Stable unique id (a UUID) assigned at creation; pass it to accessCredential/removeCredential. */
  identifier: string;
  /** Account username supplied at creation. */
  username: string;
  /** Human-friendly label; defaults to the username when none was given. */
  label: string;
  /** ISO-8601 timestamp of when the entry was created. */
  createdAt: string;
  /** Whether unlocking this entry also requires the passphrase set at creation. */
  passphrased: boolean;
}

/** Options for {@link createCredential}. */
export interface CreateCredentialOptions {
  /** Account username (required). */
  username: string;
  /**
   * Secret to protect: a string is UTF-8 encoded, a Uint8Array is copied, and `undefined` generates a fresh
   * random 32-byte secret.
   */
  secret?: string | Uint8Array;
  /** Human-friendly label; defaults to the username. */
  label?: string;
  /**
   * Optional second factor folded (via PBKDF2) into both the authenticator's PRF eval input and the key
   * derivation, so each guess requires a live ceremony and a stolen vault cannot be brute-forced offline.
   * When set to a non-empty string, the same passphrase is required on every access; an empty string is
   * treated as no passphrase.
   */
  passphrase?: string;
  /** IndexedDB database to store the entry in (default `passkeyVault`). */
  databaseName?: string;
  /** Advanced: explicit IndexedDB version to open with; omit to use the database's current version. */
  databaseVersion?: number;
  /**
   * Crypto namespace bound into key derivation and authenticated data; recorded with the entry and reused
   * automatically on access. Defaults to a stable, environment-derived identity; pass it to pin the namespace.
   */
  applicationName?: string;
  /** Crypto namespace version (default `1`). */
  applicationVersion?: number;
}

/** Optional filter for {@link listCredentials}. */
export interface ListCredentialsFilter {
  /** Narrow the results to entries with this username; omit to list all. */
  username?: string;
  /** IndexedDB database to read from (default `passkeyVault`). */
  databaseName?: string;
  /** Advanced: explicit IndexedDB version to open with; omit to use the database's current version. */
  databaseVersion?: number;
}

/** Options for {@link accessCredential}. */
export interface AccessCredentialOptions {
  /** The `identifier` of the entry to unlock (required). */
  identifier: string;
  /**
   * Required if the entry was created with one (see `passphrased` on {@link CredentialMetadata}). Omitting it
   * (or passing an empty string) for a protected entry throws before any authenticator prompt.
   */
  passphrase?: string;
  /** IndexedDB database the entry lives in (default `passkeyVault`). */
  databaseName?: string;
  /** Advanced: explicit IndexedDB version to open with; omit to use the database's current version. */
  databaseVersion?: number;
}

/** Options for {@link removeCredential}. */
export interface RemoveCredentialOptions {
  /** The `identifier` of the entry to delete (required). */
  identifier: string;
  /** IndexedDB database the entry lives in (default `passkeyVault`). */
  databaseName?: string;
  /** Advanced: explicit IndexedDB version to open with; omit to use the database's current version. */
  databaseVersion?: number;
}

/** Options for {@link wipeVault}. */
export interface WipeVaultOptions {
  /** IndexedDB database to empty (default `passkeyVault`). */
  databaseName?: string;
  /** Advanced: explicit IndexedDB version to open with; omit to use the database's current version. */
  databaseVersion?: number;
}

/** Returned by {@link createCredential} and {@link accessCredential}. */
export interface CredentialResult {
  /** Public, non-secret metadata for the entry. */
  entry: CredentialMetadata;
  /**
   * The plaintext secret bytes, backed by a non-shared ArrayBuffer. createCredential returns them once so
   * callers can keep their own backup (there is no recovery); accessCredential returns the decrypted secret.
   */
  secret: Uint8Array<ArrayBuffer>;
}
