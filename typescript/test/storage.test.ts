import { describe, it, expect, vi } from 'vitest';
import {
  resolveStorageLocation,
  requestPersistentStorage,
  saveEntry,
  loadEntry,
  loadAllEntries,
  deleteEntry,
  clearEntries,
} from '../src/_storage.js';
import type { StoredEntry, StorageLocation } from '../src/_types.js';

const LOC: StorageLocation = { databaseName: 'testdb', databaseVersion: undefined };

const makeEntry = (identifier: string, username = 'alice'): StoredEntry => ({
  identifier,
  username,
  label: identifier,
  createdAt: '2026-01-01T00:00:00.000Z',
  applicationContext: 'app/v1/',
  credentialIdentifier: new Uint8Array([1, 2, 3]),
  salt: new Uint8Array(32),
  initializationVector: new Uint8Array(12),
  ciphertext: new Uint8Array([9, 9, 9]),
  passphrased: false,
});

describe('resolveStorageLocation', () => {
  it('applies the default database name and passes the version through', () => {
    expect(resolveStorageLocation({})).toEqual({ databaseName: 'passkeyVault', databaseVersion: undefined });
    expect(resolveStorageLocation({ databaseName: 'x', databaseVersion: 3 })).toEqual({
      databaseName: 'x',
      databaseVersion: 3,
    });
  });
});

describe('requestPersistentStorage', () => {
  it('delegates to navigator.storage.persist when available', async () => {
    vi.stubGlobal('navigator', { storage: { persist: vi.fn(async () => true) } });
    expect(await requestPersistentStorage()).toBe(true);
  });

  it('returns false when the Storage API is absent', async () => {
    vi.stubGlobal('navigator', {});
    expect(await requestPersistentStorage()).toBe(false);
  });
});

describe('saveEntry / loadEntry / loadAllEntries', () => {
  it('persists an entry and reads it back unchanged', async () => {
    await saveEntry(LOC, makeEntry('id-1'));
    const row = await loadEntry(LOC, 'id-1');
    expect(row?.identifier).toBe('id-1');
    expect(row?.ciphertext).toEqual(new Uint8Array([9, 9, 9]));
  });

  it('returns undefined for an unknown identifier', async () => {
    await saveEntry(LOC, makeEntry('id-1'));
    expect(await loadEntry(LOC, 'missing')).toBeUndefined();
  });

  it('lists every stored row', async () => {
    await saveEntry(LOC, makeEntry('a'));
    await saveEntry(LOC, makeEntry('b'));
    const ids = (await loadAllEntries(LOC)).map(r => r.identifier).sort();
    expect(ids).toEqual(['a', 'b']);
  });

  it('upserts on the identifier keyPath (put, not add)', async () => {
    await saveEntry(LOC, makeEntry('dup', 'first'));
    await saveEntry(LOC, makeEntry('dup', 'second'));
    expect((await loadAllEntries(LOC)).length).toBe(1);
    expect((await loadEntry(LOC, 'dup'))?.username).toBe('second');
  });
});

describe('openDatabase schema lifecycle', () => {
  it('creates the store on first open and reuses it across an explicit version upgrade', async () => {
    // First save opens at the implicit current version -> onupgradeneeded creates the store.
    await saveEntry(LOC, makeEntry('v1-row'));
    // Opening at an explicit higher version triggers onupgradeneeded again; the contains() guard skips
    // re-creating the existing store, and the prior row survives.
    await saveEntry({ databaseName: 'testdb', databaseVersion: 2 }, makeEntry('v2-row'));
    expect((await loadAllEntries({ databaseName: 'testdb', databaseVersion: 2 })).length).toBe(2);
  });

  it('rejects when a version upgrade is blocked by another open connection', async () => {
    const dbName = 'blocktest';
    const held = await new Promise<IDBDatabase>((resolve, reject) => {
      const req = indexedDB.open(dbName);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    // `held` stays open with no versionchange handler, so a higher-version open cannot proceed.
    await expect(saveEntry({ databaseName: dbName, databaseVersion: 2 }, makeEntry('x'))).rejects.toThrow(/blocked/);
    held.close();
  });
});

describe('runTransaction failure handling', () => {
  it('rejects (and closes) when the request throws synchronously', async () => {
    // An object with no `identifier` violates the keyPath, so store.put throws DataError synchronously,
    // exercising the try/catch around transaction setup.
    await expect(saveEntry(LOC, {} as unknown as StoredEntry)).rejects.toThrow();
  });
});

describe('deleteEntry / clearEntries', () => {
  it('deletes a single row and is a no-op for a missing identifier', async () => {
    await saveEntry(LOC, makeEntry('a'));
    await saveEntry(LOC, makeEntry('b'));
    await deleteEntry(LOC, 'a');
    expect(await loadEntry(LOC, 'a')).toBeUndefined();
    expect((await loadAllEntries(LOC)).map(r => r.identifier)).toEqual(['b']);
    await deleteEntry(LOC, 'missing'); // delete of an absent key resolves without throwing
    expect((await loadAllEntries(LOC)).length).toBe(1);
  });

  it('clears the entire store', async () => {
    await saveEntry(LOC, makeEntry('a'));
    await saveEntry(LOC, makeEntry('b'));
    await clearEntries(LOC);
    expect(await loadAllEntries(LOC)).toEqual([]);
  });
});
