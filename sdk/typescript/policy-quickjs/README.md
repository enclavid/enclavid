# @enclavid/policy-quickjs

What an [enclavid](https://github.com/enclavid/enclavid) policy built on
QuickJS — the engine `componentize-qjs` embeds — needs of the runtime and
QuickJS lacks, put in place before anything of the policy runs:

- `TextEncoder` and `TextDecoder`, which
  [`@enclavid/policy`](https://www.npmjs.com/package/@enclavid/policy) keeps
  the state with, from the `fast-text-encoding` polyfill;
- `crypto.getRandomValues`, and a `Math.random` drawn afresh every round, from
  `wasi:random`: the round's own randomness, unpredictable to anyone outside
  the enclave. QuickJS seeds its own `Math.random` once, when the policy is
  built, so without this every session would draw the same numbers.

Import it first, for its effects alone:

```ts
import "@enclavid/policy-quickjs";
```

and import `wasi:random` in the policy's world:

```wit
import wasi:random/random@0.2.12;
```

The templates of `npm create enclavid` do both.
