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
import * as photo from "enclavid:well-known/photo@0.1.0";
import * as fields from "enclavid:well-known/disclosure-fields@0.1.0";
import { disclosureField as df } from "enclavid-ext:policy/disclosure-fields@0.1.0";
import { localized as t } from "enclavid-ext:policy/i18n@0.1.0";
import * as props from "enclavid-ext:policy/props@0.1.0";

// The state is this policy's own: kept between rounds, sealed, never seen by
// anyone but the policy — the step the session is at. Plain data only: the
// passport's photo cannot be kept, but the hash that names it can.
type StatePassport = { step: "passport" };
type StateSelfie = { step: "selfie"; passport: string };
type StateConsent = { step: "consent" };
type State = StatePassport | StateSelfie | StateConsent;

// What a step returns: the state to keep, and what to do now.
type Step = [State, Action];

type Media = Extract<Event, { tag: "media" }>;
type ConsentAnswer = Extract<Event, { tag: "consent-disclosure" }>;

// A round: a step, and the answer to its prompt — the runtime answers each
// prompt with its own kind of event, and with no other.
type Round =
  | (StatePassport & { event: Media })
  | (StateSelfie & { event: Media })
  | (StateConsent & { event: ConsentAnswer });

// What the policy can do: ask the applicant for something, or end the
// session. Functions, not values: a step's action is made in the round that
// takes it, since a plugin (`photo.passport()`) cannot be asked when the
// module first runs, as the policy is built.
const steps = {
  passport: (): Step => [
    { step: "passport" },
    { tag: "render", val: { tag: "media", val: photo.passport() } },
  ],
  selfie: (passport: string): Step => [
    { step: "selfie", passport },
    { tag: "render", val: { tag: "media", val: photo.selfie() } },
  ],
  // The fields the consumer receives if the applicant accepts. Each is one of
  // the policy's disclosure fields (`wit/world.wit`), which a well-known
  // helper labels; the reason and the requester are the policy's own texts
  // (`i18n/en.json`).
  consent: (): Step => [
    { step: "consent" },
    {
      tag: "render",
      val: {
        tag: "consent-disclosure",
        val: {
          fields: [
            fields.fullName(df("full-name"), "Jane Q. Citizen"),
            fields.dateOfBirth(df("date-of-birth"), "1990-04-12"),
            fields.nationality(df("nationality"), "Utopia"),
          ],
          reason: t("consent-reason"),
          requester: t("requester"),
        },
      },
    },
  ],
  // The session ends on the consent screen's answer.
  approve: (): Step => [
    { step: "consent" },
    { tag: "finish", val: "approved" },
  ],
  reject: (): Step => [{ step: "consent" }, { tag: "finish", val: "rejected" }],
};

export const policy = definePolicy(
  withStart<State, Event, Action>({
    start: () => steps.passport(),
    handle: (state, event) => {
      const round = { ...state, event } as Round;
      switch (round.step) {
        case "passport": {
          // The passport has no time limit, so its reply is its captures: one
          // for each step of the spec, of the kind the step asked for — the
          // passport's spec is one photo.
          const [page] =
            round.event.val.tag === "ok" ? round.event.val.val : [];
          if (page?.tag !== "photo") return steps.passport();
          // The props are the consumer's, the same in every round.
          if (props.get().selfie === false) return steps.consent();
          return steps.selfie(page.val.hash());
        }
        case "selfie":
          return steps.consent();
        case "consent":
          return round.event.val ? steps.approve() : steps.reject();
      }
    },
  }),
);
