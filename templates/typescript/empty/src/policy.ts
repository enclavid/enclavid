// An empty policy, to write one of your own on: it asks nothing, discloses
// nothing, and ends the session for review at once. Its world,
// `wit/world.wit`, has the policy's slot laid out — its texts, the fields it
// may disclose and its props — each with a placeholder to replace. `AGENTS.md`
// says what each holds and how a policy uses it.
//
// The runtime calls `start` on a session's first round and `handle` on every
// round after it, with the event that brought it. Each returns the state to
// keep for the next round and what to do now: show the applicant something
// (`render`), or end the session with a decision (`finish`).
import "@enclavid/policy-quickjs";
import { definePolicy, withStart } from "@enclavid/policy";
import type { Action, Event } from "enclavid:policy/types@0.1.0";

// The state is this policy's own: kept between rounds, sealed, never seen by
// anyone but the policy. This one keeps nothing yet.
type State = null;

// What a step returns: the state to keep, and what to do now.
type Step = [State, Action];

// What the policy can do: ask the applicant for something, or end the
// session. Functions, not values: a step's action is made in the round that
// takes it, since a plugin cannot be asked when the module first runs, as the
// policy is built.
const steps = {
  // The policy decides nothing yet, so it approves no one.
  review: (): Step => [null, { tag: "finish", val: "review" }],
};

export const policy = definePolicy(
  withStart<State, Event, Action>({
    start: () => steps.review(),
    // No round comes after the first yet: the policy shows the applicant
    // nothing to answer.
    handle: () => steps.review(),
  }),
);
