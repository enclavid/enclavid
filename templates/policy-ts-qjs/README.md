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
  `definePolicy` and `withStart` in `@enclavid/policy`. Its first import,
  `@enclavid/policy-quickjs`, fills in what QuickJS lacks; see below.
- `wit/world.wit` — what the policy imports (the host's interfaces and plugins')
  and exports, and its slot, `enclavid-ext:policy`: the keys of its texts; the
  fields it may disclose to the consumer, on the applicant's consent; and the
  props it takes. The WIT it imports is in `wit/deps/`.
- `i18n/en.json` — the texts the policy shows, in English: one JSON file per
  language.
- `types/` — the TypeScript types of everything in `wit/`, written by
  `npm run types` (the build writes them too). Not edited by hand.

## Texts

A text the policy shows is a case of the `key` in `enclavid-ext:policy/i18n`,
in `wit/world.wit`, and its wording is in `i18n/<language>.json`, one file per
language, each text by its key:

```wit
enum key {
    consent-reason,
    requester,
}
```

```json
{
  "consent-reason": "To verify your identity.",
  "requester": "My service"
}
```

```ts
import { localized } from "enclavid-ext:policy/i18n@0.1.0";

localized("consent-reason");
```

A text is shown as it is written: it takes no values.

A plugin's texts are in its own slot, named for its package, and the policy
may show them too: import the slot's `i18n`, with the plugin's WIT for it in
`wit/deps/` (well-known's is `deps/well-known-texts/`):

```wit
import enclavid-ext:well-known/i18n@0.1.0;
```

```ts
import { localized as wellKnown } from "enclavid-ext:well-known/i18n@0.1.0";

wellKnown("nationality-label");
```

They are the plugin's: the host serves them from the plugin's catalog, and a
build of the plugin with other keys needs the policy built again with its WIT.

The texts can also live in one file, every language under its tag —
`{ "en": { "consent-reason": "…" }, "ru": { "consent-reason": "…" } }` —
passed to the build's embed as `--i18n i18n.json`.

The platform picks the applicant's language, and the policy never learns it. A
language without a text of its own shows `en`'s. The build's `enclavid policy
embed` checks the texts against the keys: every key needs a text, and every
text a key.

## Disclosure fields

Every field the consumer may receive is named by a key the policy lists, a
case of the `key` in `enclavid-ext:policy/disclosure-fields`, in
`wit/world.wit`. `disclosureField` makes the field of a key, and a well-known
helper labels it — by convention the helper of its name:

```ts
import { disclosureField } from "enclavid-ext:policy/disclosure-fields@0.1.0";

fields.fullName(disclosureField("full-name"), "Jane Q. Citizen");
```

A field of the policy's own is a `display-field` it builds itself, with
`disclosureField` and a text of its own as the label.

The list is the most a field's key can say to the consumer, so list only the
fields the policy discloses.

## Props

Props are what the consumer sets for each session: a threshold, a mode, a
value to compare the document against. The policy declares them as a record in
`wit/world.wit`, in the interface `enclavid-ext:policy/props`, and reads
them with `get()`:

```ts
import * as props from "enclavid-ext:policy/props@0.1.0";

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

Import its interfaces in `wit/world.wit`, put its WIT in `wit/deps/` — its own
package and, when it has texts, its slot, `enclavid-ext:<name>` — and run
`npm run types`. Then import it in `src/policy.ts` by the interface name, for
example `import * as ocr from "acme:ocr/read@0.1.0"`. The consumer pins an
implementation of the plugin's package when it creates a session.

## The runtime

The policy runs on QuickJS. There is no `console` and no network: what a
policy may know comes from its events, its props and its plugins, and the
round it runs in.

- `Date.now()` and `new Date()` are the second the round started, the same for
  the whole round.
- `Math.random()` and `crypto.getRandomValues()` draw from the round's
  randomness, through `wasi:random`, which the world imports for it. It is
  fresh for every round and unpredictable to anyone outside the enclave; a
  round that runs again draws anew. QuickJS has no `crypto`, and seeds its own
  `Math.random` once, when the policy is built — so without
  `@enclavid/policy-quickjs` every session would draw the same numbers.
- `TextEncoder` and `TextDecoder`, which `@enclavid/policy` keeps the state
  with, come from the `fast-text-encoding` polyfill, also through
  `@enclavid/policy-quickjs`.

`@enclavid/policy-quickjs` is QuickJS's alone, so `@enclavid/policy` stays
what it is under any engine. It goes first among the policy's imports, so
everything after it finds what it puts in place.
