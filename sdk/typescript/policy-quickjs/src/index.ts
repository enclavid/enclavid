// What a policy built on QuickJS — the engine `componentize-qjs` embeds —
// needs of the runtime and QuickJS lacks, put in place before anything of
// the policy runs. Imported first, for its effects alone:
//
//   import "@enclavid/policy-quickjs";
//
// - `TextEncoder` and `TextDecoder`, which `@enclavid/policy` keeps the state
//   with: the `fast-text-encoding` polyfill, onto the `global` it looks for
//   and QuickJS does not define (./global.ts);
// - `crypto.getRandomValues`, and a `Math.random` drawn afresh every round,
//   from `wasi:random` (./random.ts). The policy's world imports
//   `wasi:random/random@0.2.12` for it.
//
// The modules run in the order they are imported here.
import "./global.js";
import "fast-text-encoding";
import "./random.js";

declare global {
  var crypto: {
    getRandomValues<T extends ArrayBufferView>(array: T): T;
  };
}
