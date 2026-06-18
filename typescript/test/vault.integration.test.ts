import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  createCredential,
  accessCredential,
  listCredentials,
  removeCredential,
  wipeVault,
  createVault,
} from '../src/_vault.js';
import { loadEntry, saveEntry } from '../src/_storage.js';
import { installAuthenticator, toB64Url } from './_fakes.js';
import type { StorageLocation, StoredEntry, StoredEntryRow } from '../src/_types.js';

const DEFAULT_LOC: StorageLocation = { databaseName: 'passkeyVault', databaseVersion: undefined };
const decode = (b: Uint8Array) => new TextDecoder().decode(b);
const u8 = (max = 128) => fc.uint8Array({ maxLength: max }).map(u => new Uint8Array(u));

describe('createCredential', () => {
  it('seals a string secret and returns metadata + the plaintext bytes', async () => {
    installAuthenticator();
    const { entry, secret } = await createCredential({ username: 'alice@example.com', secret: 'tok', label: 'Prod' });
    expect(entry).toMatchObject({ username: 'alice@example.com', label: 'Prod', passphrased: false });
    expect(typeof entry.identifier).toBe('string');
    expect(decode(secret)).toBe('tok');
  });

  it('defaults the label to the username', async () => {
    installAuthenticator();
    expect((await createCredential({ username: 'bob', secret: 'x' })).entry.label).toBe('bob');
  });

  it('requires a username and never reaches the authenticator without one', async () => {
    const h = installAuthenticator();
    await expect(createCredential({ username: '', secret: 'x' })).rejects.toThrow(/Username is required/);
    expect(h.createSpy).not.toHaveBeenCalled();
  });

  it('generates a fresh random 32-byte secret when none is given', async () => {
    installAuthenticator();
    expect((await createCredential({ username: 'a' })).secret.length).toBe(32);
  });

  it('copies a Uint8Array secret so later caller mutation cannot change what was sealed', async () => {
    installAuthenticator();
    const input = new Uint8Array([1, 2, 3, 4]);
    const { entry } = await createCredential({ username: 'a', secret: input });
    input[0] = 99;
    expect((await accessCredential({ identifier: entry.identifier })).secret).toEqual(new Uint8Array([1, 2, 3, 4]));
  });

  it('persists only opaque material — never the plaintext secret', async () => {
    installAuthenticator();
    const { entry } = await createCredential({ username: 'priv', secret: 'PLAINTEXT-SECRET' });
    const row = (await loadEntry(DEFAULT_LOC, entry.identifier)) as StoredEntryRow;
    for (const f of ['salt', 'initializationVector', 'ciphertext', 'credentialIdentifier', 'applicationContext']) {
      expect(row).toHaveProperty(f);
    }
    expect(row).not.toHaveProperty('secret');
    expect(decode(new Uint8Array(row.ciphertext))).not.toContain('PLAINTEXT-SECRET');
  });

  it('the returned metadata leaks no cryptographic field', async () => {
    installAuthenticator();
    const { entry } = await createCredential({ username: 'm', secret: 'x' });
    expect(Object.keys(entry).sort()).toEqual(['createdAt', 'identifier', 'label', 'passphrased', 'username']);
  });
});

describe('create -> access round-trip', () => {
  it('returns byte-identical plaintext for arbitrary secrets', async () => {
    installAuthenticator();
    await fc.assert(
      fc.asyncProperty(u8(), async secretBytes => {
        const { entry, secret } = await createCredential({ username: 'rt', secret: secretBytes });
        expect(secret).toEqual(secretBytes);
        expect((await accessCredential({ identifier: entry.identifier })).secret).toEqual(secretBytes);
      }),
      { numRuns: 20 },
    );
  });

  it('reuses the application namespace recorded at creation (custom appName/version)', async () => {
    installAuthenticator();
    const { entry } = await createCredential({
      username: 'x',
      secret: 'y',
      applicationName: 'myapp',
      applicationVersion: 2,
    });
    expect(decode((await accessCredential({ identifier: entry.identifier })).secret)).toBe('y');
  });

  it('falls back to the default namespace for a legacy row missing applicationContext', async () => {
    installAuthenticator();
    // Create under the default namespace so the fallback used on read matches what encrypted it.
    const { entry } = await createCredential({
      username: 'legacy',
      secret: 'old',
      applicationName: 'passkey-vault',
      applicationVersion: 1,
    });
    const row = (await loadEntry(DEFAULT_LOC, entry.identifier)) as StoredEntry;
    delete (row as Partial<StoredEntry>).applicationContext;
    await saveEntry(DEFAULT_LOC, row);
    expect(decode((await accessCredential({ identifier: entry.identifier })).secret)).toBe('old');
  });
});

describe('accessCredential — guards and the passphrase factor', () => {
  it('throws for a missing identifier or an unknown entry', async () => {
    installAuthenticator();
    await expect(accessCredential({ identifier: '' })).rejects.toThrow(/identifier is required/);
    await expect(accessCredential({ identifier: 'nope' })).rejects.toThrow(/No stored credential/);
  });

  it('round-trips with a passphrase, and rejects a wrong or missing one (before any prompt)', async () => {
    const h = installAuthenticator();
    const { entry } = await createCredential({ username: 'p', secret: 'sec', passphrase: 'pw' });
    expect(entry.passphrased).toBe(true);

    expect(decode((await accessCredential({ identifier: entry.identifier, passphrase: 'pw' })).secret)).toBe('sec');

    h.getSpy.mockClear();
    await expect(accessCredential({ identifier: entry.identifier })).rejects.toThrow(/requires a passphrase/);
    expect(h.getSpy).not.toHaveBeenCalled(); // the passphrase check runs before the authenticator ceremony

    await expect(accessCredential({ identifier: entry.identifier, passphrase: 'WRONG' })).rejects.toThrow();
  });

  it('treats an empty passphrase as no passphrase', async () => {
    installAuthenticator();
    expect((await createCredential({ username: 'e', secret: 'x', passphrase: '' })).entry.passphrased).toBe(false);
  });
});

describe('listCredentials', () => {
  it('returns [] for an empty store, filters by username, and exposes metadata only', async () => {
    installAuthenticator();
    expect(await listCredentials({})).toEqual([]);
    await createCredential({ username: 'u1', secret: 'a' });
    await createCredential({ username: 'u1', secret: 'b' });
    await createCredential({ username: 'u2', secret: 'c' });
    expect((await listCredentials({})).length).toBe(3);
    expect((await listCredentials({ username: 'u1' })).length).toBe(2);
    const meta = (await listCredentials({ username: 'u2' }))[0]!;
    expect(meta).not.toHaveProperty('ciphertext');
    expect(meta).not.toHaveProperty('salt');
  });
});

describe('removeCredential', () => {
  it('deletes the entry and signals the authenticator to drop the orphaned passkey', async () => {
    const h = installAuthenticator();
    const { entry } = await createCredential({ username: 'r', secret: 'x' });
    expect(await removeCredential({ identifier: entry.identifier })).toBe(true);
    expect(await listCredentials({})).toEqual([]);
    expect(h.signalSpy).toHaveBeenCalledWith({ rpId: 'localhost', credentialId: toB64Url(h.createdIds[0]!) });
  });

  it('returns false for an unknown identifier and signals nothing', async () => {
    const h = installAuthenticator();
    expect(await removeCredential({ identifier: 'nope' })).toBe(false);
    expect(h.signalSpy).not.toHaveBeenCalled();
  });

  it('requires an identifier', async () => {
    await expect(removeCredential({ identifier: '' })).rejects.toThrow(/identifier is required/);
  });

  it('purges local data even when WebAuthn is unavailable', async () => {
    // No authenticator installed -> no window/PublicKeyCredential; deletion must still work and skip the
    // (impossible) authenticator signal. Seed a row directly so no ceremony is needed to create it.
    const row: StoredEntry = {
      identifier: 'manual',
      username: 'u',
      label: 'u',
      createdAt: '2026-01-01T00:00:00.000Z',
      applicationContext: 'app/v1/',
      credentialIdentifier: new Uint8Array([1, 2, 3]),
      salt: new Uint8Array(32),
      initializationVector: new Uint8Array(12),
      ciphertext: new Uint8Array([9]),
      passphrased: false,
    };
    await saveEntry(DEFAULT_LOC, row);
    expect(await removeCredential({ identifier: 'manual' })).toBe(true);
    expect(await loadEntry(DEFAULT_LOC, 'manual')).toBeUndefined();
  });
});

describe('wipeVault', () => {
  it('clears every entry, returns the count, and signals each authenticator credential', async () => {
    const h = installAuthenticator();
    await createCredential({ username: 'a', secret: '1' });
    await createCredential({ username: 'b', secret: '2' });
    expect(await wipeVault({})).toBe(2);
    expect(await listCredentials({})).toEqual([]);
    expect(h.signalSpy).toHaveBeenCalledTimes(2);
  });

  it('returns 0 and signals nothing for an already-empty store', async () => {
    const h = installAuthenticator();
    expect(await wipeVault({})).toBe(0);
    expect(h.signalSpy).not.toHaveBeenCalled();
  });
});

describe('createVault', () => {
  it('binds shared config, lets per-call options override it, and round-trips', async () => {
    installAuthenticator();
    const vault = createVault({ applicationName: 'bound', databaseName: 'vaultdb' });
    const { entry } = await vault.create({ username: 'v', secret: 'vv' });
    expect((await vault.list({})).length).toBe(1);
    expect(decode((await vault.access({ identifier: entry.identifier })).secret)).toBe('vv');
    // a per-call databaseName overrides the bound one, hitting a different (empty) store
    expect(await vault.list({ databaseName: 'otherdb' })).toEqual([]);
  });

  it('exposes remove and wipe bound to the configured database', async () => {
    installAuthenticator();
    const vault = createVault({ databaseName: 'vaultdb2' });
    const { entry } = await vault.create({ username: 'a', secret: 'x' });
    await vault.create({ username: 'b', secret: 'y' });
    expect(await vault.remove({ identifier: entry.identifier })).toBe(true);
    expect((await vault.list({})).length).toBe(1);
    expect(await vault.wipe()).toBe(1);
    expect(await vault.list({})).toEqual([]);
  });
});
