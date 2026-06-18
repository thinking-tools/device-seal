import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { framedBytes, additionalDataFor, asBytes, textEncoder } from '../src/_helpers.js';

// Independent reader for framedBytes' wire format: read a big-endian uint32 length, then that many bytes,
// repeat. If this recovers the exact input parts for every input, the encoding is injective — which is the
// whole reason framedBytes exists (no two distinct part-tuples can collapse to the same bytes).
const decodeFramed = (bytes: Uint8Array): Uint8Array[] => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const parts: Uint8Array[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    const len = view.getUint32(offset, false);
    offset += 4;
    parts.push(bytes.slice(offset, offset + len));
    offset += len;
  }
  return parts;
};

const bytes = (opts?: { maxLength?: number }) =>
  fc.uint8Array({ maxLength: opts?.maxLength ?? 64 }).map(u => new Uint8Array(u));

describe('framedBytes', () => {
  it('is injective: the framed form decodes back to the exact input parts', () => {
    fc.assert(
      fc.property(fc.array(bytes(), { maxLength: 6 }), parts => {
        const decoded = decodeFramed(framedBytes(...parts));
        expect(decoded).toEqual(parts);
      }),
    );
  });

  it('resists the delimiter collision plain concatenation would allow', () => {
    // "a/" + "b" and "a" + "/b" share the byte string "a/b"; framing must keep them distinct.
    const enc = (s: string) => textEncoder.encode(s);
    const left = framedBytes(enc('a/'), enc('b'));
    const right = framedBytes(enc('a'), enc('/b'));
    expect(left).not.toEqual(right);
  });

  it('handles the empty list and zero-length parts', () => {
    expect(framedBytes()).toEqual(new Uint8Array(0));
    // a single empty part is just its 4-byte length prefix of zero
    expect(framedBytes(new Uint8Array(0))).toEqual(new Uint8Array([0, 0, 0, 0]));
  });
});

describe('additionalDataFor', () => {
  it('the slash delimiter cannot move the namespace boundary', () => {
    expect(additionalDataFor('app/', 'id')).not.toEqual(additionalDataFor('app', '/id'));
  });
});

describe('asBytes', () => {
  it('returns an independent copy for a Uint8Array (mutating either side is isolated)', () => {
    fc.assert(
      fc.property(bytes({ maxLength: 32 }), src => {
        fc.pre(src.length > 0);
        const copy = asBytes(src);
        expect(copy).toEqual(src);
        const before = copy[0]!;
        src[0] = src[0]! ^ 0xff;
        expect(copy[0]).toBe(before); // source mutation did not bleed into the copy
      }),
    );
  });

  it('copies an ArrayBuffer without aliasing it', () => {
    const buf = new ArrayBuffer(4);
    new Uint8Array(buf).set([1, 2, 3, 4]);
    const copy = asBytes(buf);
    expect(copy).toEqual(new Uint8Array([1, 2, 3, 4]));
    new Uint8Array(buf)[0] = 99;
    expect(copy[0]).toBe(1);
  });

  it('honours a non-zero byteOffset view and copies only that window', () => {
    const buf = new ArrayBuffer(8);
    new Uint8Array(buf).set([0, 0, 5, 6, 7, 0, 0, 0]);
    const view = new Uint8Array(buf, 2, 3); // [5,6,7]
    const copy = asBytes(view);
    expect(copy).toEqual(new Uint8Array([5, 6, 7]));
    new Uint8Array(buf)[2] = 42;
    expect(copy[0]).toBe(5);
  });

  it('accepts a DataView', () => {
    const buf = new Uint8Array([9, 8, 7]).buffer;
    expect(asBytes(new DataView(buf))).toEqual(new Uint8Array([9, 8, 7]));
  });
});
