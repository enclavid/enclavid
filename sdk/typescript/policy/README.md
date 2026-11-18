# @enclavid/policy

Write an [enclavid](https://github.com/enclavid/enclavid) policy in
TypeScript, with a state of the policy's own type.

A policy runs inside the enclave as a WebAssembly component. The runtime calls
it once a round, with the state the round before returned and the event that
brought this one, and keeps the state it returns for the next. `definePolicy`
makes that call of a `handle` over the policy's own state, which it keeps as
bytes with `devalue`; `withStart` gives the first round a `start` of its own:

```ts
import "@enclavid/policy-quickjs";
import { definePolicy, withStart } from "@enclavid/policy";
import type { Action, Event } from "enclavid:policy/types@0.1.0";
import * as photo from "enclavid:well-known/photo@0.1.0";

type State = { step: "selfie" };

export const policy = definePolicy(
  withStart<State, Event, Action>({
    start: () => [
      { step: "selfie" },
      { tag: "render", val: { tag: "media", val: photo.selfie() } },
    ],
    handle: (state, event) => [state, { tag: "finish", val: "approved" }],
  }),
);
```

The event and the action are the types of the policy's world, as
`jco guest-types` writes them; this package names neither. A state is plain
data — primitives, `Date`, binary data, and arrays, maps, sets and objects of
these — and a state that is not does not compile, naming the field. `encode`
and `decode` are the state as the runtime keeps it, and `hex` reads a
`face-flashes` guide's colour as CSS writes it.

`TextEncoder` and `TextDecoder` keep the state, so a policy on QuickJS imports
[`@enclavid/policy-quickjs`](https://www.npmjs.com/package/@enclavid/policy-quickjs)
first.

Start from a template with `npm create enclavid`. How a policy works and how
to change one is in
[AGENTS.md](https://github.com/enclavid/enclavid/blob/main/templates/typescript/AGENTS.md).
