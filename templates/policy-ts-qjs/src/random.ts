// QuickJS seeds `Math.random` once, when the policy is built, so every session
// would draw the same numbers; and it has no `crypto`. Both draw here from
// `wasi:random`, the round's own randomness: fresh for every round from the
// enclave's own generator, so it is unpredictable to anyone outside it. A
// module of its own, imported before anything that draws.
import { getRandomBytes } from "wasi:random/random@0.2.12";

declare global {
  var crypto: {
    getRandomValues<T extends ArrayBufferView>(array: T): T;
  };
}

// componentize-qjs 0.4.5 takes a u64 as a `number` (a `bigint` traps), while the
// generated types say `bigint`.
const bytes = (length: number): Uint8Array =>
  getRandomBytes(length as unknown as bigint);

// 53 random bits, the most a double holds exactly: the low 5 bits of the first
// of 7 bytes, then the other 6. Always below 1.
Math.random = () => {
  const b = bytes(7);
  let bits = b[0] & 0x1f;
  for (let i = 1; i < 7; i++) bits = bits * 256 + b[i];
  return bits / 2 ** 53;
};

// What Web Crypto fills: integer typed arrays, not floats or a DataView.
const integerArrays = [
  Int8Array,
  Uint8Array,
  Uint8ClampedArray,
  Int16Array,
  Uint16Array,
  Int32Array,
  Uint32Array,
  BigInt64Array,
  BigUint64Array,
];

globalThis.crypto = {
  getRandomValues(array) {
    if (!integerArrays.some((kind) => array instanceof kind)) {
      throw new TypeError("getRandomValues takes an integer typed array");
    }
    if (array.byteLength > 65536) {
      throw new RangeError("getRandomValues takes at most 65536 bytes");
    }
    new Uint8Array(array.buffer, array.byteOffset, array.byteLength).set(
      bytes(array.byteLength),
    );
    return array;
  },
};
