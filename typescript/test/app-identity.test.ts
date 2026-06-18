import { describe, it, expect, vi } from 'vitest';
import { resolveAppIdentity, resolveAppIdentitySync, clearAppIdentityCache } from '../src/_app-identity.js';

const setLocation = (hostname?: string) => vi.stubGlobal('location', hostname === undefined ? undefined : { hostname });
const setManifestHref = (href?: string) =>
  vi.stubGlobal('document', {
    querySelector: (sel: string) => (sel.includes('manifest') && href ? { href } : null),
  });
const dataUrl = (obj: unknown, base64 = false): string => {
  const json = JSON.stringify(obj);
  return base64 ? `data:application/json;base64,${btoa(json)}` : `data:application/json,${encodeURIComponent(json)}`;
};

describe('resolveAppIdentitySync — priority order', () => {
  it('an explicit override wins over everything', () => {
    setLocation('example.com');
    expect(resolveAppIdentitySync({ override: 'pinned' })).toMatchObject({ id: 'pinned', source: 'override' });
  });

  it('falls to an inline data: manifest id when no override', () => {
    setManifestHref(dataUrl({ id: 'com.app', name: 'My App' }));
    expect(resolveAppIdentitySync()).toMatchObject({ id: 'com.app', name: 'My App', source: 'manifest' });
  });

  it('uses a real hostname when there is no override or inline manifest', () => {
    setManifestHref(undefined);
    setLocation('vault.example.com');
    expect(resolveAppIdentitySync()).toMatchObject({ id: 'vault.example.com', source: 'hostname' });
  });

  it('falls back to "app" when nothing identifies the environment', () => {
    setLocation('localhost'); // local host is not identifying
    expect(resolveAppIdentitySync()).toMatchObject({ id: 'app', source: 'fallback' });
  });

  it('honours a custom fallback and trustHostname:false', () => {
    setLocation('real.domain.com');
    expect(resolveAppIdentitySync({ trustHostname: false, fallback: 'mine' })).toMatchObject({
      id: 'mine',
      source: 'fallback',
    });
  });

  it('ignores a non-data: manifest href in the sync path', () => {
    setManifestHref('https://example.com/manifest.webmanifest'); // needs a network read -> skipped here
    setLocation('host.example.com');
    expect(resolveAppIdentitySync()).toMatchObject({ id: 'host.example.com', source: 'hostname' });
  });
});

describe('isRealHost (via the hostname path)', () => {
  const cases: Array<[string, boolean]> = [
    ['example.com', true],
    ['localhost', false],
    ['127.0.0.1', false],
    ['1.2.3.4', false],
    ['pwa', false], // synthetic
    ['nodot', false], // no dot -> not a registrable domain
  ];
  for (const [host, isReal] of cases) {
    it(`${host} -> ${isReal ? 'hostname' : 'fallback'}`, () => {
      setLocation(host);
      expect(resolveAppIdentitySync().source).toBe(isReal ? 'hostname' : 'fallback');
    });
  }

  it('treats denyHosts as non-identifying, case-insensitively', () => {
    setLocation('EXAMPLE.COM');
    expect(resolveAppIdentitySync({ denyHosts: ['example.com'] }).source).toBe('fallback');
  });
});

describe('manifest parsing', () => {
  it('reads a base64 data: manifest', () => {
    setManifestHref(dataUrl({ id: 'b64.app' }, true));
    expect(resolveAppIdentitySync()).toMatchObject({ id: 'b64.app', source: 'manifest' });
  });

  it('falls through a manifest with no usable id', () => {
    setManifestHref(dataUrl({ description: 'x' }));
    setLocation('localhost');
    expect(resolveAppIdentitySync().source).toBe('fallback');
  });

  it('treats id "/" as absent and uses name', () => {
    setManifestHref(dataUrl({ id: '/', name: 'Named' }));
    expect(resolveAppIdentitySync()).toMatchObject({ id: 'Named', source: 'manifest' });
  });

  it('uses short_name when id and name are absent', () => {
    setManifestHref(dataUrl({ short_name: 'Sn' }));
    expect(resolveAppIdentitySync()).toMatchObject({ id: 'Sn', source: 'manifest' });
  });

  const bad = [
    ['no comma', 'data:application/json'],
    ['bad json', 'data:application/json,{oops'],
    ['non-object', dataUrl(5)],
  ];
  for (const [name, href] of bad) {
    it(`ignores a ${name} data URL`, () => {
      setManifestHref(href);
      setLocation('localhost');
      expect(resolveAppIdentitySync().source).toBe('fallback');
    });
  }
});

describe('detectPlatform', () => {
  it('reflects the Capacitor platform when present', () => {
    vi.stubGlobal('Capacitor', { getPlatform: () => 'ios' });
    setLocation('app.example.com');
    expect(resolveAppIdentitySync().platform).toBe('ios');
  });

  it('is "unknown" with no Capacitor bridge', () => {
    setLocation('app.example.com');
    expect(resolveAppIdentitySync().platform).toBe('unknown');
  });
});

describe('resolveAppIdentity (async) — extra sources and memoization', () => {
  it('memoizes after the first resolution and bypasses with fresh:true', async () => {
    const first = await resolveAppIdentity({ override: 'one' });
    expect(first).toMatchObject({ id: 'one' });
    // A second call without fresh returns the memo regardless of new options.
    expect(await resolveAppIdentity({ override: 'two' })).toBe(first);
    expect(await resolveAppIdentity({ override: 'two', fresh: true })).toMatchObject({ id: 'two' });
  });

  it('clearAppIdentityCache resets the memo', async () => {
    await resolveAppIdentity({ override: 'one' });
    clearAppIdentityCache();
    expect(await resolveAppIdentity({ override: 'three' })).toMatchObject({ id: 'three' });
  });

  it('fetches a non-data manifest over the network', async () => {
    setManifestHref('https://example.com/manifest.json');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: true, json: async () => ({ id: 'fetched.app' }) })),
    );
    expect(await resolveAppIdentity({ fresh: true })).toMatchObject({ id: 'fetched.app', source: 'manifest' });
  });

  it('ignores a non-ok manifest fetch', async () => {
    setManifestHref('https://example.com/manifest.json');
    setLocation('localhost');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: false })),
    );
    expect((await resolveAppIdentity({ fresh: true })).source).toBe('fallback');
  });

  it('ignores a failed manifest fetch', async () => {
    setManifestHref('https://example.com/manifest.json');
    setLocation('localhost');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('network');
      }),
    );
    expect((await resolveAppIdentity({ fresh: true })).source).toBe('fallback');
  });

  it('reads an injected Capacitor App plugin', async () => {
    expect(
      await resolveAppIdentity({ fresh: true, capacitorApp: { getInfo: async () => ({ id: 'cap.id', name: 'Cap' }) } }),
    ).toMatchObject({ id: 'cap.id', name: 'Cap', source: 'capacitor' });
  });

  it('reads the native Capacitor bridge from globalThis', async () => {
    vi.stubGlobal('Capacitor', {
      getPlatform: () => 'android',
      isNativePlatform: () => true,
      Plugins: { App: { getInfo: async () => ({ id: 'native.id' }) } },
    });
    expect(await resolveAppIdentity({ fresh: true })).toMatchObject({
      id: 'native.id',
      source: 'capacitor',
      platform: 'android',
    });
  });

  it('falls through when the Capacitor plugin throws', async () => {
    setLocation('localhost');
    expect(
      (
        await resolveAppIdentity({
          fresh: true,
          capacitorApp: {
            getInfo: async () => {
              throw new Error('no plugin');
            },
          },
        })
      ).source,
    ).toBe('fallback');
  });
});
