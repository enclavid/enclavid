# An Enclavid policy in TypeScript, built on QuickJS

A policy decides what an applicant is asked and what the session ends with. It
runs inside the enclave, in a sandbox, as a WebAssembly component — this one
built with `componentize-qjs`, which embeds the QuickJS engine.

## Build

Needs Node and the `enclavid` CLI on the path.

```
npm install
npm run build
```

`dist/policy.wasm` is the policy, ready to push:

```
enclavid oci push dist/policy.wasm <registry>/<repository>:<tag>
```

## What is where

- `src/policy.ts` — the policy. Its state is a value of its own type; see
  `definePolicy` and `withStart` in `@enclavid/policy`.
- `src/global.ts` — makes QuickJS's global object reachable as `global`, for
  the TextEncoder polyfill imported next to it.
- `wit/world.wit` — what the policy imports (the host's interfaces and plugins')
  and exports. Their WIT is in `wit/deps/`.
- `i18n.json` — the texts the policy shows, by key and locale.
- `disclosure-fields.json` — the keys of the fields the policy may disclose to
  the consumer, on the applicant's consent.
- `types/` — the TypeScript types of everything in `wit/`, written by
  `npm run types` (the build writes them too). Not edited by hand.

## Using a plugin

Import its interfaces in `wit/world.wit`, put its WIT in `wit/deps/`, and run
`npm run types`. Then import it in `src/policy.ts` by the interface name, for
example `import * as ocr from "acme:ocr/read@0.1.0"`. The consumer pins an
implementation of the plugin's package when it creates a session.

## The runtime

The policy runs on QuickJS. There is no `console`, no `Date.now()`, no random
numbers and no network: what a policy may know comes from its events, its
props and its plugins. `TextEncoder` and `TextDecoder` come from the
`fast-text-encoding` polyfill.
