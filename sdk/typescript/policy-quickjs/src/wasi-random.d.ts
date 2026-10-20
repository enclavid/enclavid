// What `wasi:random` offers, as far as this package's own build needs: in a
// policy, the types come from its world.
declare module "wasi:random/random@0.2.12" {
  export function getRandomBytes(len: bigint): Uint8Array;
}
