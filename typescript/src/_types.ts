export type VaultConfig = Partial<{
  databaseName: string;
  databaseVersion: number;
  applicationName: string;
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

export interface CredentialMetadata {
  identifier: string;
  username: string;
  label: string;
  createdAt: string;
  passphrased: boolean;
}

export interface CreateCredentialOptions {
  username: string;
  secret?: string | Uint8Array;
  label?: string;
  passphrase?: string;
  databaseName?: string;
  databaseVersion?: number;
  applicationName?: string;
  applicationVersion?: number;
}

export interface ListCredentialsFilter {
  username?: string;
  databaseName?: string;
  databaseVersion?: number;
}

export interface AccessCredentialOptions {
  identifier: string;
  passphrase?: string;
  databaseName?: string;
  databaseVersion?: number;
}

export interface RemoveCredentialOptions {
  identifier: string;
  databaseName?: string;
  databaseVersion?: number;
}

export interface WipeVaultOptions {
  databaseName?: string;
  databaseVersion?: number;
}

export interface CredentialResult {
  entry: CredentialMetadata;
  secret: Uint8Array<ArrayBuffer>;
}
