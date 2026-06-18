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
