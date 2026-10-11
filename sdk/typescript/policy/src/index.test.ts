import assert from "node:assert/strict";
import { test } from "node:test";

import { decode, definePolicy, encode, withStart } from "./index.js";

// The shape of a world's event and action, as `jco guest-types` writes them.
type Event = { tag: "start" } | { tag: "consent-disclosure"; val: boolean } | { tag: "media"; val: null };
type Action = { tag: "render"; val: null } | { tag: "finish"; val: "approved" | "rejected" };

type State = { step: "passport" } | { step: "selfie"; passport: string };

const render = { tag: "render", val: null } as const;
const approved: Action = { tag: "finish", val: "approved" };
const start: Event = { tag: "start" };
const media: Event = { tag: "media", val: null };

test("the first round has no state, a later one the state the round before returned", () => {
  const seen: (State | undefined)[] = [];
  const policy = definePolicy<State, Event, Action>((state, _event) => {
    seen.push(state);
    return state === undefined ? [{ step: "passport" }, render] : [{ step: "selfie", passport: "ab12" }, render];
  });
  const [first] = policy.handle(new Uint8Array(), start);
  const [second] = policy.handle(first, media);
  assert.deepEqual(seen, [undefined, { step: "passport" }]);
  assert.deepEqual(decode(second), { step: "selfie", passport: "ab12" });
});

test("withStart calls start on the event start, and handle on every other", () => {
  const calls: string[] = [];
  const policy = definePolicy(
    withStart<State, Event, Action>({
      start: () => {
        calls.push("start");
        return [{ step: "passport" }, render];
      },
      handle: (state, event) => {
        calls.push(`${state.step} ${event.tag}`);
        return state.step === "passport" ? [{ step: "selfie", passport: "ab12" }, render] : [state, approved];
      },
    }),
  );
  const [first] = policy.handle(new Uint8Array(), start);
  const [second] = policy.handle(first, media);
  const [third, action] = policy.handle(second, media);
  assert.deepEqual(calls, ["start", "passport media", "selfie media"]);
  assert.deepEqual(decode(third), { step: "selfie", passport: "ab12" });
  assert.deepEqual(action, approved);
});

test("a state is never encoded to no bytes", () => {
  for (const state of [null, undefined, ""]) {
    assert.ok(encode(state).length > 0);
  }
  assert.equal(decode(encode(undefined)), undefined);
});

test("a resource in the state ends the round instead of being kept", () => {
  class Blob {
    hash() {
      return "ab";
    }
  }
  assert.throws(() => encode({ step: "selfie", frame: new Blob() }), /non-POJOs/);
});

test("a state comes back as it went, dates and collections included", () => {
  const state = {
    name: "Jane Q. Citizen — Жанна 👩‍💻 ✓",
    passportExpiry: new Date("2030-01-01T00:00:00Z"),
    seen: new Map([["passport", 1]]),
    tags: new Set(["retry"]),
    attempts: 3n,
    photo: new Uint8Array([1, 2, 3]),
    pattern: /^P<UTO/i,
    note: undefined,
  };
  const back = decode<typeof state>(encode(state));
  assert.deepEqual(back, state);
  assert.ok(back.passportExpiry instanceof Date);
  assert.ok(back.seen instanceof Map && back.tags instanceof Set);
  assert.ok(back.photo instanceof Uint8Array && back.pattern instanceof RegExp);
});

// What a state may hold, and what each round is handed, is checked when the
// policy compiles; `tsc` fails this file if a line below stops compiling, or
// one marked as an error starts to. The resources are declared the way
// `jco guest-types` writes them.
declare class Blob implements Disposable {
  constructor(hash: string);
  bytes(): Uint8Array;
  hash(): string;
  [Symbol.dispose](): void;
}
declare class LocalizedRef implements Disposable {
  private constructor();
  [Symbol.dispose](): void;
}
class Hidden {
  #at = 0;
  get at() {
    return this.#at;
  }
}
class Guarded {
  private at = 0;
  readonly step = "a";
}
interface Kept {
  step: string;
  issuedAt?: Date;
  seen: Map<string, number[]>;
  readonly checks: readonly { at: Date; passed: boolean | null }[];
}
export const compiles = () => {
  const kept: Kept = { step: "a", seen: new Map(), checks: [] };
  definePolicy<Kept, Event, Action>((s) => [s ?? kept, render]);
  definePolicy(withStart<Kept, Event, Action>({ start: () => [kept, render], handle: (s) => [s, render] }));
  // Any event and action will do; withStart asks only for a start among the events.
  definePolicy<Kept, string, number>((s, event) => [s ?? kept, event.length]);
  definePolicy(withStart<Kept, { tag: "start" } | { tag: "tick"; n: number }, string>({ start: () => [kept, "go"], handle: (s, e) => [s, `${e.n}`] }));
  // @ts-expect-error an event with no start never starts
  withStart<Kept, { tag: "tick"; n: number }, string>(null!);
  // @ts-expect-error the first round has no state
  definePolicy<Kept, Event, Action>((s) => [s, render]);
  withStart<Kept, Event, Action>({
    start: () => [kept, render],
    handle: (s, event) => {
      // @ts-expect-error the first round's event never reaches handle
      if (event.tag === "start") return [s, approved];
      return [s, render];
    },
  });
  // @ts-expect-error a resource lives for one round
  definePolicy<{ frame: Blob }, Event, Action>(null!);
  // @ts-expect-error a ref is a resource too
  definePolicy<{ reason?: LocalizedRef }, Event, Action>(null!);
  // @ts-expect-error a resource inside a collection is still a resource
  definePolicy<{ frames: Map<string, Blob> }, Event, Action>(null!);
  // @ts-expect-error a resource deep in one case of a union
  withStart<{ step: "a" } | { step: "b"; deep: { frames: Blob[] } }, Event, Action>(null!);
  // @ts-expect-error what a private field holds is not seen, so not kept
  definePolicy<{ hidden: Hidden }, Event, Action>(null!);
  // @ts-expect-error nor what a `private` one holds, even in a collection
  withStart<{ guarded: Map<string, Guarded[]> }, Event, Action>(null!);
  // @ts-expect-error a function is not kept
  definePolicy<{ next: () => void }, Event, Action>(null!);
  // @ts-expect-error what a field holds must be known
  definePolicy<{ anything: unknown }, Event, Action>(null!);
};
