# Changing an Enclavid policy in TypeScript

The templates beside this file are Enclavid policies: TypeScript built into a
WebAssembly component on QuickJS, which the platform runs inside the enclave.
This file is for an agent changing one, in a checkout of a template or in the
playground.

## The files

| What | In a checkout | In the playground |
| --- | --- | --- |
| The policy | `src/policy.ts` | `policy.ts` |
| Its world | `wit/world.wit` | `world.wit` |
| Its texts | `i18n/<language>.json`, a file per language | `i18n.json`, each language under its tag |

Leave `types/` and `wit/deps/` alone: the build writes the first, and the
second holds copies of the platform's and the plugins' WIT. The TypeScript
types of the interfaces the world imports are in `types/`; in the playground
they come with the request.

## How a policy works

The runtime calls the policy once a round, with the state the round before
returned and the event that brought this one, and keeps the state the policy
returns for the next. `definePolicy` and `withStart` from `@enclavid/policy`
make that call of a `start`, for the first round, and a `handle`, for every
round after it; each returns `[state, action]`. The types below are in
`enclavid:policy/types@0.1.0`.

- An event is `start`; `media`, the reply to a media prompt — one capture for
  each step of its spec, or `timed-out`; or `consent-disclosure`, whether the
  applicant accepted.
- An action is `render`, a prompt — `media`, with a spec a plugin makes, such
  as `photo.passport()`, or `consent-disclosure` — or `finish`, with a
  decision: `approved`, `rejected`, `rejected-retryable` or `review`.
- The runtime answers a prompt with the event of its kind and no other, so a
  policy narrows its events to those of the prompts it renders.
- The decision reaches the consumer whatever happens. Anything else reaches it
  only through a `consent-disclosure` the applicant accepts, and exactly the
  fields the screen shows.
- The state is plain data: primitives, `Date`, binary data, and arrays, maps,
  sets and objects of these. Not a photo, a video or another ref a plugin hands
  out: those live for one round. Keep what names one instead, such as a
  photo's `hash()`.
- An action is made in the round that takes it — a function, not a value at
  the top of the module: a plugin cannot be called while the module first
  runs, as the policy is built.
- The policy writes no text the applicant sees. Every text is a key whose
  wording is in the texts, or a plugin's.

## Imports

`policy.ts` imports an interface by its name and version, and `world.wit`
imports the same interface:

```wit
import enclavid:face-age/image@0.1.0;
```

```ts
import { estimate } from "enclavid:face-age/image@0.1.0";
```

WIT names are kebab-case and TypeScript's camelCase: `min-age` is `minAge`,
`id-card` is `idCard`. Variants are `{ tag, val }` objects with the case's
name as the tag; enums are their cases' names as strings.

`import "@enclavid/policy-quickjs";` stays the first import of `policy.ts`,
and `import wasi:random/random@0.2.12;` stays in the world: they give QuickJS
`TextEncoder`, `TextDecoder`, `crypto.getRandomValues` and a `Math.random`
fresh for each round.

## The policy's slot

What the host serves this policy alone is a package of its own in `world.wit`,
`enclavid-ext:policy`, beside the world: its texts' keys, the fields it may
disclose, and its props. The world imports the interfaces it uses, and a
policy that uses none has no slot.

### Texts

A text is a case of `key` in `i18n`, with a wording in each language:

```wit
package enclavid-ext:policy@0.1.0 {
    interface i18n {
        use enclavid:host/refs@0.1.0.{localized-ref};

        enum key {
            consent-reason,
            requester,
        }

        localized: func(key: key) -> localized-ref;
    }
}
```

```json
{ "en": { "consent-reason": "To verify your identity.", "requester": "My service" } }
```

```ts
import { localized as t } from "enclavid-ext:policy/i18n@0.1.0";

t("consent-reason");
```

Every key needs a text, and every text a key; a language without a text of
its own shows `en`'s. A text takes no values. A policy with no texts
has no `i18n` interface, and its texts file is `{}`.

A plugin's texts are in its own slot, named for its package, and the policy
may show them too, for example `import enclavid-ext:well-known/i18n@0.1.0;`.

### Disclosure fields

Every field the consumer may receive is a case of `key` in
`disclosure-fields`. `disclosureField` makes the field of a key, and a
well-known helper labels it:

```wit
interface disclosure-fields {
    use enclavid:host/refs@0.1.0.{disclosure-field-key-ref};

    enum key {
        full-name,
        date-of-birth,
    }

    disclosure-field: func(key: key) -> disclosure-field-key-ref;
}
```

```ts
import * as fields from "enclavid:well-known/disclosure-fields@0.1.0";
import { disclosureField as df } from "enclavid-ext:policy/disclosure-fields@0.1.0";

fields.fullName(df("full-name"), "Jane Q. Citizen");
```

A field no well-known helper is for — a value the policy works out itself,
such as the age face-age reads — the policy makes whole: its key a case of
its list, its label one of its texts, and its value from `text` of
`enclavid:host-disclosure/values`, which the world then imports:

```wit
import enclavid:host-disclosure/values@0.1.0;
```

```ts
import { text } from "enclavid:host-disclosure/values@0.1.0";
import { localized as t } from "enclavid-ext:policy/i18n@0.1.0";

const field = {
  key: df("estimated-age"),
  label: t("estimated-age"),
  value: text(String(Math.round(age))),
};
```

Fields of either kind go in the `fields` of a `consent-disclosure` prompt.
The applicant is shown how many keys the list holds, so list only the fields
the policy discloses.

### Props

Props are what the consumer sets for each session: a threshold, a mode, a
value to compare against. They are a record in `props`, read with `get()`:

```wit
interface props {
    record props {
        min-age: u8,
        selfie: option<bool>,
    }

    get: func() -> props;
}
```

```ts
import * as props from "enclavid-ext:policy/props@0.1.0";

props.get().minAge;
```

The interface's name and `get` are fixed; the record is the policy's own. A
field may be a `bool`, a number type, `char`, `string`, an `enum`, a `list`,
an `option` or another record. The consumer gives them as JSON keyed by the
WIT's names (`{ "min-age": 18 }`), at most 1 KiB, and a session whose props do
not fit the record fails.

## Plugins

A plugin reads what the policy hands it and answers; the consumer pins an
implementation of each plugin package when it creates a session. The
templates use:

- `enclavid:well-known` — capture specs (passport, ID card, driver's license,
  selfie, a liveness video and its guides), the labels of common disclosure
  fields, and texts of its own.
- `enclavid:face-detect` — the face in a photo or in a video's frames, read
  against the guide it was taken to.
- `enclavid:face-age` — the age of a face face-detect read.
- `enclavid:face-liveness` — how live the face held in a video looks.

To use one, import its interfaces in `world.wit` and in `policy.ts`. In a
checkout, also copy its WIT into `wit/deps/` and run `npm run types`; the
playground has the WIT of every plugin above already, and pins those a build
imports.

A plugin's answer is often an `option` or a `result`: a photo that does not
decode, no face, a face too small. Check it, and ask again, reject or send to
review.

## The runtime

- There is no `console`, no network and no file system: what a policy knows
  comes from its events, its props, its plugins and its state.
- `Date.now()` and `new Date()` are the second the round started, the same for
  the whole round.
- `Math.random()` and `crypto.getRandomValues()` draw from the round's
  randomness, fresh for every round.
- An exception the policy does not catch fails the session. Handle every
  `undefined` and `err` it can get.
- The build has `@enclavid/policy`, `@enclavid/policy-quickjs` and the WIT
  interfaces; nothing else can be imported.

## Checking a change

A build checks the world, then the TypeScript against the world's types, then
the texts against their keys, and names the file and line of each problem. In
a checkout, `npm run build`; in the playground, Build.

## Style

Keep the templates' style: a comment above what it explains, saying what the
code does and why; events narrowed with `Extract` to those the policy gets; a
`steps` object of functions that each return `[state, action]`.
