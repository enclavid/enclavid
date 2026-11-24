# An empty policy, in TypeScript on QuickJS

A policy to write your own on. It asks the applicant nothing and discloses
nothing: the session ends for review at once. What a policy is made of is in
place — its world, its slot with its texts, the fields it may disclose and its
props, and the build — with a placeholder wherever WIT needs one.

`AGENTS.md` says how a policy works and how to change one. The other
templates, which `npm create enclavid` makes projects of too, show a policy at
work: `kyc` a consent screen with texts, fields and props, `age-verification`
and `liveness` the face plugins.

## Build

Needs Node. `npm install` brings the `enclavid` CLI too, `@enclavid/cli`,
which `npx enclavid` runs.

```
npm install
npm run build
```

`dist/policy.wasm` is the policy, ready to push:

```
npx enclavid oci push dist/policy.wasm <registry>/<repository>:<tag>
```

`npm run format` formats `src/` with Prettier.

`npm run playground` builds the policy and runs it on the playground, which
asks for no account, with the props in `props.json`.

## What is where

- `src/policy.ts` — the policy.
- `wit/world.wit` — what the policy imports and exports, and its slot,
  `enclavid-ext:policy`: the keys of its texts, the fields it may disclose to
  the consumer, on the applicant's consent, and the props it takes.
- `i18n/en.json` — the texts the policy shows, in English: one JSON file per
  language.
- `props.json` — the props `npm run playground` starts the session with.
- `wit/deps/` — the WIT the policy builds against: the platform's, and that
  of the plugins below.
- `types/` — the TypeScript types of everything in `wit/`, written by
  `npm run types` (the build writes them too). Not edited by hand.

## The placeholders

WIT has no empty enum or record, so each interface of the slot holds one
entry, `example`, which nothing uses:

- `i18n` — the case `example` of `key`, with its text in `i18n/en.json`;
- `disclosure-fields` — the case `example` of `key`;
- `props` — the field `example` of the record.

Replace each with the policy's own. Leave out an interface the policy has no
use for, and its import in the world; `i18n` with `i18n/` too.

## Plugins

`wit/deps/` holds the WIT of the platform's plugins, which the world does not
import yet: `enclavid:well-known`, `enclavid:face-detect`, `enclavid:face-age`
and `enclavid:face-liveness`. To use one, import its interfaces in
`wit/world.wit`, run `npm run types`, and import them in `src/policy.ts` by
the same name:

```wit
import enclavid:well-known/photo@0.1.0;
```

```ts
import * as photo from "enclavid:well-known/photo@0.1.0";
```

Another plugin's WIT goes in `wit/deps/` first. The consumer pins an
implementation of each plugin package the world imports when it creates a
session.
