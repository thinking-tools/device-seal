import type { Bytes } from './_types.js';

export const textEncoder = new TextEncoder();

// === Encoding helpers

// Injective (unambiguous) concatenation: each part is prefixed with its big-endian uint32 length so
// distinct (part, part) tuples can never collapse to the same bytes. Plain concatenation would let a
// caller-controlled applicationContext (which may contain the '/' delimiter) collide with a different
// (context, credentialId) pair, weakening the per-namespace domain separation it exists to provide.
export const framedBytes = (...parts: Bytes[]): Bytes => {
  const total = parts.reduce((sum, part) => sum + 4 + part.length, 0);
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const part of parts) {
    view.setUint32(offset, part.length, false);
    offset += 4;
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

// Additional authenticated data binding a record's ciphertext to its application namespace and immutable
// identifier, so a stored blob cannot be silently moved to another identifier or decrypted under a
// different application context — the AES-GCM tag covers exactly these two inputs. Mutable metadata such
// as label or username is not authenticated here, so the tag does not protect it.
export const additionalDataFor = (applicationContext: string, identifier: string): Bytes =>
  framedBytes(textEncoder.encode(applicationContext), textEncoder.encode(identifier));

export const asBytes = (source: BufferSource): Bytes => {
  const view =
    source instanceof ArrayBuffer
      ? new Uint8Array(source)
      : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
  return new Uint8Array(view);
};

// Best-effort in-place wipe of a sensitive buffer once it is no longer needed (raw PRF unlock secret,
// passphrase material, HKDF ikm). Writes through a view onto the SAME memory — unlike asBytes it does not
// copy — so it must only be given a buffer that is truly done with, never one still in use, the returned
// plaintext, or the persisted salt (prfEvalInput aliases the salt when there is no passphrase).
//
// This is defense in depth, not a guarantee. JS strings are immutable, so a passphrase or string secret
// cannot be wiped at its source (it lingers until GC); a moving garbage collector may leave un-wiped copies
// elsewhere; and WebCrypto copies its inputs internally where we cannot reach. It still shrinks the window
// in which raw key material sits in heap memory.
export const zeroize = (source: BufferSource): void => {
  const view =
    source instanceof ArrayBuffer
      ? new Uint8Array(source)
      : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
  view.fill(0);
};
