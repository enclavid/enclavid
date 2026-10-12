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
  and exports, and the props it takes. The WIT it imports is in `wit/deps/`.
- `i18n.json` — the texts the policy shows, by key and locale.
- `disclosure-fields.json` — the keys of the fields the policy may disclose to
  the consumer, on the applicant's consent.
- `types/` — the TypeScript types of everything in `wit/`, written by
  `npm run types` (the build writes them too). Not edited by hand.

## Props

Props are what the consumer sets for each session: a threshold, a mode, a
value to compare the document against. The policy declares them as a record in
`wit/world.wit`, in the interface `enclavid:host-ext/policy-props`, and reads
them with `get()`:

```ts
import * as props from "enclavid:host-ext/policy-props@0.1.0";

if (props.get().selfie === false) { … }
```

The record is the policy's own, so its fields are typed like the rest of the
world. The interface's name and its one function, `get`, are fixed: the host
serves them. The consumer gives the props as a JSON object keyed by the
record's field names as the WIT spells them (`min-age`, not `minAge`), at most
1 KiB, when it creates the session:

```json
{ "policy": "…", "props": { "selfie": false } }
```

A field may be a `bool`, a number type, `char`, `string`, an `enum`, a `list`,
an `option` (`null` or left out is none) or another record. A session whose
props do not fit the record fails when it runs, as does a session given props
for a policy that takes none. A policy that takes none leaves the import out.

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
