// A KYC walk: the passport, then a selfie unless the consumer turned it off,
// then a consent screen with the fields the consumer receives if the applicant
// accepts.
//
// The runtime calls `start` on a session's first round and `handle` on every
// round after it, with the event that brought it. Each returns the state to
// keep for the next round and what to do now: show the applicant something
// (`render`), or end the session with a decision (`finish`).
import "@enclavid/policy-quickjs";
import { definePolicy, withStart } from "@enclavid/policy";
import type { Action, Event } from "enclavid:policy/types@0.1.0";
import * as capture from "enclavid:well-known/capture@0.1.0";
import * as fields from "enclavid:well-known/disclosure-fields@0.1.0";
import { localized } from "local:policy/i18n@0.1.0";
import * as props from "enclavid:host-ext/policy-props@0.1.0";

// The state is this policy's own: kept between rounds, sealed, never seen by
// anyone but the policy. Plain data only — the passport's frame cannot be kept,
// but the hash that names it can.
type State =
  | { step: "passport" }
  | { step: "selfie"; passport: string }
  | { step: "consent" };

// The consent screen: the fields the consumer receives if the applicant
// accepts. Each field's key is one of the policy's disclosure fields
// (`wit/world.wit`); the reason and the requester are the policy's own texts
// (`i18n/en.json`).
const consent: () => Action = () => ({
  tag: "render",
  val: {
    tag: "consent-disclosure",
    val: {
      fields: [
        fields.fullName("Jane Q. Citizen"),
        fields.dateOfBirth("1990-04-12"),
        fields.nationality("Utopia"),
      ],
      reason: localized("consent-reason"),
      requester: localized("requester"),
    },
  },
});

export const policy = definePolicy(
  withStart<State, Event, Action>({
    start: () => [
      { step: "passport" },
      { tag: "render", val: { tag: "media", val: capture.passport() } },
    ],

    handle(state, event) {
      switch (state.step) {
        case "passport": {
          const frame =
            event.tag === "media" ? event.val.clip.frames[0] : undefined;
          if (frame === undefined) {
            return [state, { tag: "finish", val: "rejected-retryable" }];
          }
          // The props are the consumer's, the same in every round.
          if (props.get().selfie === false) {
            return [{ step: "consent" }, consent()];
          }
          return [
            { step: "selfie", passport: frame.hash() },
            { tag: "render", val: { tag: "media", val: capture.selfie() } },
          ];
        }

        case "selfie":
          return [{ step: "consent" }, consent()];

        case "consent": {
          const accepted = event.tag === "consent-disclosure" && event.val;
          return [
            state,
            { tag: "finish", val: accepted ? "approved" : "rejected" },
          ];
        }
      }
    },
  }),
);
