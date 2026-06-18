import { describe, it, expect } from 'vitest';
import { registerPasskey, evaluatePasskeySecret } from '../src/_crypto.js';
import { installAuthenticator, prfSecret, toB64Url } from './_fakes.js';
import type { Bytes } from '../src/_types.js';

const SALT: Bytes = new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 1));
const asBytes = (b: BufferSource) => new Uint8Array(b instanceof ArrayBuffer ? b : b.buffer);

describe('registerPasskey — support guards', () => {
  it('throws when WebAuthn is unavailable (no PublicKeyCredential)', async () => {
    installAuthenticator({ omitPublicKeyCredential: true });
    await expect(registerPasskey('app/v1/', 'alice', SALT)).rejects.toThrow(/WebAuthn is not available/);
  });

  it('throws when navigator.credentials is missing', async () => {
    installAuthenticator({ omitCredentialsContainer: true });
    await expect(registerPasskey('app/v1/', 'alice', SALT)).rejects.toThrow(/WebAuthn is not available/);
  });

  it('Layer 1: aborts before create() when the browser reports PRF unsupported', async () => {
    const h = installAuthenticator({ clientCapabilities: { 'extension:prf': false } });
    await expect(registerPasskey('app/v1/', 'alice', SALT)).rejects.toThrow(/browser does not support/);
    expect(h.createSpy).not.toHaveBeenCalled(); // nothing was ever persisted
    expect(h.signalSpy).not.toHaveBeenCalled();
  });

  it('proceeds when capabilities are unknown — method absent', async () => {
    installAuthenticator({ clientCapabilities: null }); // getClientCapabilities not implemented
    await expect(registerPasskey('app/v1/', 'alice', SALT)).resolves.toHaveProperty('passkeySecret');
  });

  it('proceeds when capabilities are unknown — key absent', async () => {
    installAuthenticator({ clientCapabilities: {} }); // older client: no 'extension:prf' key
    await expect(registerPasskey('app/v1/', 'alice', SALT)).resolves.toHaveProperty('passkeySecret');
  });
});

describe('registerPasskey — PRF acquisition paths', () => {
  it('cancelled create() throws and signals nothing (no credential exists yet)', async () => {
    const h = installAuthenticator({ createResult: null });
    await expect(registerPasskey('app/v1/', 'alice', SALT)).rejects.toThrow(/cancelled/);
    expect(h.signalSpy).not.toHaveBeenCalled();
  });

  it('PRF returned at creation: succeeds with no get() and no cleanup', async () => {
    const h = installAuthenticator({ createResult: 'prf' });
    const { credentialIdentifier, passkeySecret } = await registerPasskey('app/v1/', 'alice', SALT);
    expect(credentialIdentifier).toEqual(h.createdIds[0]);
    expect(asBytes(passkeySecret)).toEqual(await prfSecret(SALT));
    expect(h.getSpy).not.toHaveBeenCalled();
    expect(h.signalSpy).not.toHaveBeenCalled();
  });

  it('Layer 2: PRF explicitly disabled -> throws, cleans up once, fires no second prompt', async () => {
    const h = installAuthenticator({ createResult: 'disabled' });
    await expect(registerPasskey('app/v1/', 'alice', SALT)).rejects.toThrow(/authenticator does not support/);
    expect(h.getSpy).not.toHaveBeenCalled(); // no doomed second ceremony
    expect(h.signalSpy).toHaveBeenCalledTimes(1);
    expect(h.signalSpy).toHaveBeenCalledWith({ rpId: 'localhost', credentialId: toB64Url(h.createdIds[0]!) });
  });

  it('fallback: enabled-without-result then get() supplies the secret, no cleanup', async () => {
    const h = installAuthenticator({ createResult: 'enabledNoResult', getResult: 'prf' });
    const { passkeySecret } = await registerPasskey('app/v1/', 'alice', SALT);
    expect(asBytes(passkeySecret)).toEqual(await prfSecret(SALT));
    expect(h.getSpy).toHaveBeenCalledTimes(1);
    expect(h.signalSpy).not.toHaveBeenCalled();
  });

  it('Layer 3: get() yields no PRF -> throws and best-effort cleans up the orphan', async () => {
    const h = installAuthenticator({ createResult: 'enabledNoResult', getResult: 'noPrf' });
    await expect(registerPasskey('app/v1/', 'alice', SALT)).rejects.toThrow(/did not return a pseudo-random/);
    expect(h.signalSpy).toHaveBeenCalledTimes(1);
    expect(h.signalSpy).toHaveBeenCalledWith({ rpId: 'localhost', credentialId: toB64Url(h.createdIds[0]!) });
  });

  it('Layer 3: cleanup is a safe no-op when signalUnknownCredential is absent; original error propagates', async () => {
    const h = installAuthenticator({
      createResult: 'enabledNoResult',
      getResult: 'noPrf',
      hasSignalUnknownCredential: false,
    });
    await expect(registerPasskey('app/v1/', 'alice', SALT)).rejects.toThrow(/did not return a pseudo-random/);
    expect(h.signalSpy).not.toHaveBeenCalled();
  });
});

describe('evaluatePasskeySecret', () => {
  it('returns the authenticator PRF secret for the salt', async () => {
    installAuthenticator({ getResult: 'prf' });
    const secret = await evaluatePasskeySecret(new Uint8Array([1, 2, 3]), SALT);
    expect(asBytes(secret)).toEqual(await prfSecret(SALT));
  });

  it('throws when the assertion is cancelled', async () => {
    installAuthenticator({ getResult: null });
    await expect(evaluatePasskeySecret(new Uint8Array([1, 2, 3]), SALT)).rejects.toThrow(/cancelled/);
  });

  it('throws when the assertion carries no PRF result', async () => {
    installAuthenticator({ getResult: 'noPrf' });
    await expect(evaluatePasskeySecret(new Uint8Array([1, 2, 3]), SALT)).rejects.toThrow(
      /did not return a pseudo-random/,
    );
  });
});
