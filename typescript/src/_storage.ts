import type { StorageLocation, StoredEntry, StoredEntryRow } from './_types.js';
const DEFAULT_DATABASE_NAME = 'passkeyVault';
const STORE_NAME = 'entries';
// Bridges a single IndexedDB request's success/error events into a promise.
const promisifyRequest = <T>(request: IDBRequest<T>): Promise<T> =>
  new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

// Applies the default database name; the version is passed through unchanged (see StorageLocation).
export const resolveStorageLocation = (options: {
  databaseName?: string;
  databaseVersion?: number;
}): StorageLocation => ({
  databaseName: options.databaseName ?? DEFAULT_DATABASE_NAME,
  databaseVersion: options.databaseVersion,
});

// === IndexedDB persistence (thin promise wrappers over its event-based API)
//
// IndexedDB has no access control beyond same-origin, so this store cannot be made "unstealable"; the
// design instead makes a stolen copy useless. Each record holds only public values (salt,
// credentialIdentifier) and AES-256-GCM ciphertext that is inert without a live, hardware-bound,
// user-verified passkey (plus the optional passphrase) — no key material is ever written here, and
// another origin can neither read the store (it is origin-scoped) nor run the unlock ceremony (the
// passkey is bound to the creating hostname).
//
// Residual exposure, by design: metadata (username, label, createdAt) is stored in
// cleartext, so a stolen copy reveals which accounts exist — a privacy leak, not a secret one. Tampering
// can at most deny service: ciphertext cannot be forged, and since the derived key binds whether a
// passphrase was mixed in, flipping `passphrased` yields the wrong key, never a bypass.

// Best-effort request that the browser not evict our data under storage pressure; a false result
// (declined, or API absent) is harmless, so it is never treated as an error.
export const requestPersistentStorage = (): Promise<boolean> => {
  if (navigator.storage && typeof navigator.storage.persist === 'function') {
    return navigator.storage.persist();
  }
  return Promise.resolve(false);
};

// Opens (and, on first use, builds) the object store. onupgradeneeded is the only place IndexedDB lets
// you create stores/indexes; the contains() guard makes first-time creation safe, and any future schema
// change would add its migration outside that guard.
const openDatabase = (storageLocation: StorageLocation): Promise<IDBDatabase> =>
  new Promise((resolve, reject) => {
    const request =
      storageLocation.databaseVersion === undefined
        ? indexedDB.open(storageLocation.databaseName)
        : indexedDB.open(storageLocation.databaseName, storageLocation.databaseVersion);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(STORE_NAME)) {
        // keyPath 'identifier' only — no secondary indexes. listCredentials reads getAll() and filters in
        // JS, so the indexes this store used to declare were dead weight and were dropped.
        database.createObjectStore(STORE_NAME, { keyPath: 'identifier' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    request.onblocked = () => {
      // The open may still succeed once the blocking connection closes; close that late result so the
      // already-rejected promise does not leave an orphaned connection open.
      request.onsuccess = () => request.result.close();
      reject(new Error('Database upgrade blocked by another open connection'));
    };
  });

// Runs one store operation inside a fresh transaction and guarantees the connection is closed on every
// exit path. The transaction (not the request) is the source of truth: its oncomplete event signals a
// committed transaction and onabort a rollback, so the promise resolves only once the transaction has
// committed. (Default durability: this reports a logical commit, not a guaranteed flush to disk.)
const runTransaction = <T>(
  storageLocation: StorageLocation,
  mode: IDBTransactionMode,
  executeRequest: (store: IDBObjectStore) => Promise<T>,
): Promise<T> =>
  openDatabase(storageLocation).then(
    database =>
      new Promise<T>((resolve, reject) => {
        try {
          const transaction = database.transaction(STORE_NAME, mode);
          const requestResult = executeRequest(transaction.objectStore(STORE_NAME));
          // A failed request aborts the transaction (rejecting via onabort below); observe the inner
          // promise's rejection too so it never surfaces as an unhandled rejection.
          void requestResult.catch(() => {});
          transaction.oncomplete = () => {
            database.close();
            resolve(requestResult);
          };
          transaction.onerror = () => {
            database.close();
            reject(transaction.error);
          };
          transaction.onabort = () => {
            database.close();
            reject(transaction.error ?? new Error('Transaction aborted'));
          };
        } catch (error) {
          // transaction()/executeRequest can throw synchronously (e.g. NotFoundError, DataError);
          // close the connection so a setup failure cannot leak it.
          database.close();
          reject(error);
        }
      }),
  );

export const saveEntry = (storageLocation: StorageLocation, entry: StoredEntry): Promise<IDBValidKey> =>
  runTransaction(storageLocation, 'readwrite', store => promisifyRequest(store.put(entry)));

export const loadEntry = (storageLocation: StorageLocation, identifier: string): Promise<StoredEntryRow | undefined> =>
  runTransaction(storageLocation, 'readonly', store =>
    promisifyRequest(store.get(identifier) as IDBRequest<StoredEntryRow | undefined>),
  );

export const loadAllEntries = (storageLocation: StorageLocation): Promise<StoredEntryRow[]> =>
  runTransaction(storageLocation, 'readonly', store =>
    promisifyRequest(store.getAll() as IDBRequest<StoredEntryRow[]>),
  );
