import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  generateRandomBytes,
  normalizeSecret,
  derivePassphraseMaterial,
  encrypt,
  decrypt,
  deriveSecretKey,
} from '../src/_crypto.js';
import type { Bytes } from '../src/_types.js';

const u8 = (opts?: { maxLength?: number; minLength?: number }) =>
  fc.uint8Array({ minLength: opts?.minLength ?? 0, maxLength: opts?.maxLength ?? 64 }).map(u => new Uint8Array(u));

const bytesOf = (...n: number[]): Bytes => new Uint8Array(n);

// A real (non-extractable) AES-GCM key derived through the production path — encrypt/decrypt tests below
// exercise the actual WebCrypto chain, not a mock.
const deriveTestKey = (over: Partial<{ prf: Bytes; ppm: Bytes; salt: Bytes; cid: Bytes; ctx: string }> = {}) =>
  deriveSecretKey(
    over.prf ?? bytesOf(...Array.from({ length: 32 }, (_, i) => i)),
    over.ppm,
    over.salt ?? bytesOf(...Array.from({ length: 32 }, (_, i) => 255 - i)),
    over.cid ?? bytesOf(1, 2, 3, 4),
    over.ctx ?? 'app/v1/',
  );

describe('generateRandomBytes', () => {
  it('returns exactly the requested length', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 1024 }), n => {
        expect(generateRandomBytes(n).length).toBe(n);
      }),
    );
  });
});

describe('normalizeSecret', () => {
  it('undefined yields a 32-byte secret', () => {
    expect(normalizeSecret(undefined).length).toBe(32);
  });

  it('a string is UTF-8 encoded and decodes back unchanged', () => {
    fc.assert(
      fc.property(fc.string(), s => {
        expect(new TextDecoder().decode(normalizeSecret(s))).toBe(s);
      }),
    );
  });

  it('a Uint8Array is copied, not aliased', () => {
    fc.assert(
      fc.property(u8({ minLength: 1, maxLength: 48 }), src => {
        const out = normalizeSecret(src);
        expect(out).toEqual(src);
        const before = out[0]!;
        src[0] = src[0]! ^ 0xff;
        expect(out[0]).toBe(before); // mutating the caller's array must not change what we sealed
      }),
    );
  });
});

describe('derivePassphraseMaterial', () => {
  // PBKDF2 runs 700k SHA-512 iterations per call (hundreds of ms), so these are a few pinned examples
  // rather than a high-numRuns property — the invariants (length, determinism, sensitivity) need no fuzzing.
  const salt = bytesOf(...Array.from({ length: 16 }, (_, i) => i));
  const salt2 = bytesOf(...Array.from({ length: 16 }, (_, i) => i + 1));

  it('derives 32 bytes', async () => {
    expect((await derivePassphraseMaterial('pw', salt)).length).toBe(32);
  });

  it('is deterministic for the same passphrase + salt', async () => {
    expect(await derivePassphraseMaterial('hunter2', salt)).toEqual(await derivePassphraseMaterial('hunter2', salt));
  });

  it('changes with the passphrase and with the salt', async () => {
    const base = await derivePassphraseMaterial('hunter2', salt);
    expect(await derivePassphraseMaterial('hunter3', salt)).not.toEqual(base);
    expect(await derivePassphraseMaterial('hunter2', salt2)).not.toEqual(base);
  });
});

describe('encrypt / decrypt', () => {
  it('round-trips arbitrary plaintext and additionalData', async () => {
    const key = await deriveTestKey();
    await fc.assert(
      fc.asyncProperty(u8({ maxLength: 256 }), u8({ maxLength: 64 }), async (plaintext, aad) => {
        const { initializationVector, ciphertext } = await encrypt(key, plaintext, aad);
        expect(await decrypt(key, initializationVector, ciphertext, aad)).toEqual(plaintext);
      }),
      { numRuns: 50 },
    );
  });

  it('uses a fresh random 12-byte IV, so the same input encrypts differently each time', async () => {
    const key = await deriveTestKey();
    const a = await encrypt(key, bytesOf(1, 2, 3), bytesOf(9));
    const b = await encrypt(key, bytesOf(1, 2, 3), bytesOf(9));
    expect(a.initializationVector.length).toBe(12);
    expect(a.initializationVector).not.toEqual(b.initializationVector);
    expect(a.ciphertext).not.toEqual(b.ciphertext);
  });

  it('ciphertext is plaintext length plus the 16-byte GCM tag', async () => {
    const key = await deriveTestKey();
    await fc.assert(
      fc.asyncProperty(u8({ maxLength: 128 }), async plaintext => {
        const { ciphertext } = await encrypt(key, plaintext, bytesOf(0));
        expect(ciphertext.length).toBe(plaintext.length + 16);
      }),
      { numRuns: 30 },
    );
  });

  it('rejects when the additionalData differs', async () => {
    const key = await deriveTestKey();
    const { initializationVector, ciphertext } = await encrypt(key, bytesOf(1, 2, 3), bytesOf(7));
    await expect(decrypt(key, initializationVector, ciphertext, bytesOf(8))).rejects.toThrow();
  });

  it('rejects when the key differs', async () => {
    const key = await deriveTestKey();
    const other = await deriveTestKey({ salt: bytesOf(...Array.from({ length: 32 }, () => 7)) });
    const { initializationVector, ciphertext } = await encrypt(key, bytesOf(1, 2, 3), bytesOf(7));
    await expect(decrypt(other, initializationVector, ciphertext, bytesOf(7))).rejects.toThrow();
  });

  it('rejects when any single ciphertext byte is flipped', async () => {
    const key = await deriveTestKey();
    const aad = bytesOf(7);
    const { initializationVector, ciphertext } = await encrypt(key, bytesOf(10, 20, 30, 40), aad);
    await fc.assert(
      fc.asyncProperty(fc.nat(), async i => {
        const tampered = new Uint8Array(ciphertext);
        const idx = i % tampered.length;
        tampered[idx] = tampered[idx]! ^ 0x01;
        await expect(decrypt(key, initializationVector, tampered, aad)).rejects.toThrow();
      }),
      { numRuns: 20 },
    );
  });
});

describe('deriveSecretKey', () => {
  it('produces a non-extractable AES-256-GCM key usable only for encrypt/decrypt', async () => {
    const key = await deriveTestKey();
    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    expect([...key.usages].sort()).toEqual(['decrypt', 'encrypt']);
  });

  it('is reproducible: a key re-derived from identical inputs decrypts the original ciphertext', async () => {
    const inputs = { salt: generateRandomBytes(32), cid: bytesOf(5, 6, 7), ctx: 'reproduce/v1/' };
    const k1 = await deriveTestKey(inputs);
    const k2 = await deriveTestKey(inputs);
    const aad = bytesOf(1);
    const { initializationVector, ciphertext } = await encrypt(k1, bytesOf(42, 43), aad);
    expect(await decrypt(k2, initializationVector, ciphertext, aad)).toEqual(bytesOf(42, 43));
  });

  it('domain-separates: perturbing any input yields a key that cannot decrypt the others ciphertext', async () => {
    const base = {
      prf: bytesOf(...Array.from({ length: 32 }, (_, i) => i)),
      salt: bytesOf(...Array.from({ length: 32 }, (_, i) => 200 - i)),
      cid: bytesOf(1, 2, 3, 4),
      ctx: 'app/v1/',
    };
    const baseKey = await deriveTestKey(base);
    const aad = bytesOf(0xaa);
    const { initializationVector, ciphertext } = await encrypt(baseKey, bytesOf(1, 2, 3, 4), aad);

    const variants: Array<Partial<typeof base> & { ppm?: Bytes }> = [
      { prf: bytesOf(...Array.from({ length: 32 }, (_, i) => i + 1)) }, // different unlock secret
      { salt: bytesOf(...Array.from({ length: 32 }, (_, i) => 201 - i)) }, // different salt
      { cid: bytesOf(9, 9, 9, 9) }, // different credential id
      { ctx: 'app/v2/' }, // different application context
      { ppm: bytesOf(...Array.from({ length: 16 }, () => 1)) }, // a passphrase folded in vs none
    ];
    for (const v of variants) {
      const key = await deriveTestKey({ ...base, ...v });
      await expect(decrypt(key, initializationVector, ciphertext, aad)).rejects.toThrow();
    }
  });

  it('folding a passphrase changes the key versus deriving without one', async () => {
    const salt = generateRandomBytes(32);
    const withPp = await deriveTestKey({ salt, ppm: bytesOf(...Array.from({ length: 16 }, () => 3)) });
    const aad = bytesOf(1);
    const { initializationVector, ciphertext } = await encrypt(withPp, bytesOf(7), aad);
    const withoutPp = await deriveTestKey({ salt });
    await expect(decrypt(withoutPp, initializationVector, ciphertext, aad)).rejects.toThrow();
  });
});
