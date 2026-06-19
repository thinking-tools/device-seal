export type IdentitySource = 'override' | 'manifest' | 'capacitor' | 'hostname' | 'fallback';
export type Platform = 'ios' | 'android' | 'web' | 'unknown';

export interface AppIdentity {
  readonly id: string; // stable machine id — safe key for storage namespacing
  readonly name: string; // human-readable
  readonly source: IdentitySource;
  readonly platform: Platform;
}

interface CapAppInfo {
  id: string;
  name: string;
  build: string;
  version: string;
}

export interface ResolveOptions {
  /** Wins over everything. Pin it with a build constant: `import.meta.env.VITE_APP_ID`. */
  readonly override?: string;
  /** Inject @capacitor/app for explicit deps/tree-shaking; else read window.Capacitor at runtime. */
  readonly capacitorApp?: { getInfo: () => Promise<Partial<CapAppInfo>> };
  /** Use location.hostname when it's a real domain. Default true. */
  readonly trustHostname?: boolean;
  /** Extra hosts to treat as non-identifying. */
  readonly denyHosts?: readonly string[];
  /** Last resort. Default "app". */
  readonly fallback?: string;
  /** Skip the session memo. */
  readonly fresh?: boolean;
}

const LOCAL = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]']);
const SYNTHETIC = new Set(['pwa', 'app', 'capacitor', 'ionic', 'tauri.localhost']);
const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-f]*:[0-9a-f:]*\]?$/i;

const str = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');
const g = (): any => (typeof globalThis === 'undefined' ? undefined : (globalThis as any));
const cap = (): any => g()?.Capacitor;

const detectPlatform = (): Platform => {
  const p = cap()?.getPlatform?.();
  return p === 'ios' || p === 'android' || p === 'web' ? p : 'unknown';
};

const getHostname = (): string => (typeof g()?.location?.hostname === 'string' ? g().location.hostname : '');

const isRealHost = (h: string, deny?: readonly string[]): boolean => {
  const x = h.toLowerCase();
  if (!x || LOCAL.has(x) || SYNTHETIC.has(x)) return false;
  if (deny?.some(d => d.toLowerCase() === x)) return false;
  if (IP_RE.test(x)) return false;
  return x.includes('.');
};

const parseDataUrlJson = (url: string): Record<string, unknown> | undefined => {
  try {
    const i = url.indexOf(',');
    if (i < 0) return undefined;
    const body = url.slice(i + 1);
    const raw = url.slice(0, i).includes(';base64') ? atob(body) : decodeURIComponent(body);
    const j = JSON.parse(raw);
    return j && typeof j === 'object' ? j : undefined;
  } catch {
    return undefined;
  }
};

const manifestHref = (): string | undefined =>
  g()?.document?.querySelector?.('link[rel="manifest"]')?.href ?? undefined;

const readManifest = async (): Promise<Record<string, unknown> | undefined> => {
  const href = manifestHref();
  if (!href) return undefined;
  if (href.startsWith('data:')) return parseDataUrlJson(href); // inline, no network
  try {
    const res = await fetch(href); // same-origin creds; SW-cacheable when offline
    if (!res.ok) return undefined;
    const j = await res.json();
    return j && typeof j === 'object' ? j : undefined;
  } catch {
    return undefined;
  }
};

const fromManifest = (m: Record<string, unknown>, platform: Platform): AppIdentity | undefined => {
  const mid = str(m.id);
  const id = (mid && mid !== '/' ? mid : '') || str(m.name) || str(m.short_name);
  return id ? { id, name: str(m.name) || str(m.short_name) || id, source: 'manifest', platform } : undefined;
};

let memo: AppIdentity | undefined;

export const resolveAppIdentity = async (opts: ResolveOptions = {}): Promise<AppIdentity> => {
  if (memo && !opts.fresh) return memo;
  const platform = detectPlatform();
  const done = (v: AppIdentity): AppIdentity => {
    if (!opts.fresh) memo = v;
    return v;
  };

  const ov = str(opts.override);
  if (ov) return done({ id: ov, name: ov, source: 'override', platform });

  const m = await readManifest();
  if (m) {
    const r = fromManifest(m, platform);
    if (r) return done(r);
  }

  try {
    let info: Partial<CapAppInfo> | undefined;
    if (opts.capacitorApp) info = await opts.capacitorApp.getInfo();
    else if (cap()?.isNativePlatform?.()) {
      const App = cap()?.Plugins?.App;
      if (App?.getInfo) info = await App.getInfo(); // method call keeps correct `this`
    }
    const id = str(info?.id);
    if (id) return done({ id, name: str(info?.name) || id, source: 'capacitor', platform });
  } catch {
    /* plugin absent / called on web — fall through */
  }

  if (opts.trustHostname !== false) {
    const h = getHostname();
    if (isRealHost(h, opts.denyHosts)) return done({ id: h, name: h, source: 'hostname', platform });
  }

  const fb = str(opts.fallback) || 'app';
  return done({ id: fb, name: fb, source: 'fallback', platform });
};

// Sync best-effort for boot-time use (no fetch, no native bridge): override → inline manifest → hostname → fallback
export const resolveAppIdentitySync = (opts: ResolveOptions = {}): AppIdentity => {
  const platform = detectPlatform();
  const ov = str(opts.override);
  if (ov) return { id: ov, name: ov, source: 'override', platform };

  const href = manifestHref();
  const m = href?.startsWith('data:') ? parseDataUrlJson(href) : undefined;
  if (m) {
    const r = fromManifest(m, platform);
    if (r) return r;
  }
  if (opts.trustHostname !== false) {
    const h = getHostname();
    if (isRealHost(h, opts.denyHosts)) return { id: h, name: h, source: 'hostname', platform };
  }
  return { id: str(opts.fallback) || 'app', name: str(opts.fallback) || 'app', source: 'fallback', platform };
};

export const clearAppIdentityCache = (): void => {
  memo = undefined;
};
