// An age check by selfie: the applicant takes a selfie, the policy reads the
// age of the face in it, and the session ends approved when that age is at
// least the consumer's `min-age`, rejected when it is not. Nothing is
// disclosed and nothing is kept: the consumer learns the decision alone.
//
// The runtime calls `start` on a session's first round and `handle` on every
// round after it, with the event that brought it. Each returns the state to
// keep for the next round and what to do now: show the applicant something
// (`render`), or end the session with a decision (`finish`).
import "@enclavid/policy-quickjs";
import { definePolicy, withStart } from "@enclavid/policy";
import type {
  Action,
  Event as AnyEvent,
  MediaResult,
} from "enclavid:policy/types@0.1.0";
import * as capture from "enclavid:well-known/capture@0.1.0";
import { decode } from "enclavid:vision/decode@0.1.0";
import { detect } from "enclavid:face-detect/detect@0.1.0";
import { estimate } from "enclavid:face-age/check@0.1.0";
import * as props from "enclavid-ext:policy/props@0.1.0";

// The policy keeps nothing between rounds.
type State = null;

// What a step returns: the state to keep, and what to do now.
type Step = [State, Action];

// The events this policy gets: `start`, then the answer to the prompt it
// rendered last — it renders media prompts alone, and the runtime delivers no
// other answer.
type Event = Extract<AnyEvent, { tag: "start" | "media" }>;

// What the policy can do: ask the applicant for something, or end the
// session. Functions, not values: a step's action is made in the round that
// takes it, since a plugin (`capture.selfie()`) cannot be asked when the
// module first runs, as the policy is built.
const steps = {
  selfie: (): Step => [
    null,
    { tag: "render", val: { tag: "media", val: capture.selfie() } },
  ],
  approve: (): Step => [null, { tag: "finish", val: "approved" }],
  reject: (): Step => [null, { tag: "finish", val: "rejected" }],
};

export const policy = definePolicy(
  withStart<State, Event, Action>({
    start: () => steps.selfie(),
    handle: (_state, event) => {
      const age = estimateAge(event.val);
      // No face to read. Captures are checked on the applicant's page before
      // they are sent, so this is rare: ask again as is — or ask with a
      // media-spec of your own that says what went wrong, or reject.
      if (age === undefined) return steps.selfie();
      // The props are the consumer's, the same in every round.
      return age >= props.get().minAge ? steps.approve() : steps.reject();
    },
  }),
);

// The age of the face in a selfie, or none: a photo that does not decode,
// holds no face, or a face too small to read. The vision plugin decodes the
// photo once, at half the camera's size, where a selfie's face is a hundred
// pixels and more; face-detect finds the face in it, and face-age reads its
// age from the face's own crop.
function estimateAge(media: MediaResult): number | undefined {
  // A capture for each step of the spec, of the kind the step asked for: the
  // selfie's spec is one photo.
  const [selfie] = media.captures;
  if (selfie?.tag !== "photo") return;
  const picture = decode(selfie.val, "half");
  if (!picture) return;
  const face = detect(picture);
  if (!face) return;
  return estimate(picture, face)?.age;
}
