import { vi } from 'vitest';

// Structural test double for the WebAuthn surface. The real PublicKeyCredential is a host class that can't
// be constructed, so create()/get() return plain objects shaped like what the code reads — hence the
// localized `any`s here (a deliberate exception to the no-any rule, scoped to this test harness).

/** Deterministic stand-in for the authenticator PRF: sha256(eval.first). Same salt -> same secret (so a
 *  create() secret and a later get() secret for one entry match); distinct salts -> distinct secrets. */
export const prfSecret = async (evalFirst: BufferSource): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', evalFirst));

/** Same base64url transform the production toBase64Url uses, for asserting the signalled credential id. */
export const toB64Url = (bytes: Uint8Array): string => {
  let binary = '';
  for (const byte of bytes) binary += String.fromCodePoint(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
};

export interface FakeOptions {
  /** getClientCapabilities() return value; `null` removes the method entirely; default `{'extension:prf':true}`. */
  clientCapabilities?: Record<string, boolean> | null;
  /** What create() reports: a direct PRF result, enabled-without-result (forces a get()), PRF disabled, or cancel. */
  createResult?: 'prf' | 'enabledNoResult' | 'disabled' | null;
  /** What a follow-up get() reports: a PRF result, an assertion lacking PRF, or cancel. */
  getResult?: 'prf' | 'noPrf' | null;
  hasSignalUnknownCredential?: boolean;
  omitPublicKeyCredential?: boolean;
  omitCredentialsContainer?: boolean;
}

export interface FakeHandles {
  createSpy: ReturnType<typeof vi.fn>;
  getSpy: ReturnType<typeof vi.fn>;
  signalSpy: ReturnType<typeof vi.fn>;
  createdIds: Uint8Array[];
}

/** Installs PublicKeyCredential/navigator/location stubs for one test. afterEach (setup.ts) unstubs them. */
// eslint not used in this repo; `any` is the deliberate test-double exception noted above.
export const installAuthenticator = (opts: FakeOptions = {}): FakeHandles => {
  const {
    clientCapabilities,
    createResult = 'prf',
    getResult = 'prf',
    hasSignalUnknownCredential = true,
    omitPublicKeyCredential = false,
    omitCredentialsContainer = false,
  } = opts;

  const createdIds: Uint8Array[] = [];

  const createSpy = vi.fn(async (options: any): Promise<any> => {
    if (createResult === null) return null;
    const evalFirst = options?.publicKey?.extensions?.prf?.eval?.first as BufferSource;
    const rawId = crypto.getRandomValues(new Uint8Array(16)).buffer;
    createdIds.push(new Uint8Array(rawId));
    const prf =
      createResult === 'prf'
        ? { results: { first: await prfSecret(evalFirst) } }
        : createResult === 'enabledNoResult'
          ? { enabled: true }
          : { enabled: false };
    return { rawId, getClientExtensionResults: () => ({ prf }) };
  });

  const getSpy = vi.fn(async (options: any): Promise<any> => {
    if (getResult === null) return null;
    const evalFirst = options?.publicKey?.extensions?.prf?.eval?.first as BufferSource;
    const prf = getResult === 'prf' ? { results: { first: await prfSecret(evalFirst) } } : {};
    return { getClientExtensionResults: () => ({ prf }) };
  });

  const signalSpy = vi.fn(async () => undefined);
  const caps = clientCapabilities === undefined ? { 'extension:prf': true } : clientCapabilities;

  const PublicKeyCredential: any = {};
  if (clientCapabilities !== null) PublicKeyCredential.getClientCapabilities = async () => caps;
  if (hasSignalUnknownCredential) PublicKeyCredential.signalUnknownCredential = signalSpy;

  const nav: any = {};
  if (!omitCredentialsContainer) nav.credentials = { create: createSpy, get: getSpy };
  nav.storage = { persist: async () => true }; // createCredential best-effort requests persistence

  // Real browsers expose these on globalThis (window === globalThis); the production code reads them there.
  if (!omitPublicKeyCredential) vi.stubGlobal('PublicKeyCredential', PublicKeyCredential);
  vi.stubGlobal('navigator', nav);
  vi.stubGlobal('location', { hostname: 'localhost' });

  return { createSpy, getSpy, signalSpy, createdIds };
};
