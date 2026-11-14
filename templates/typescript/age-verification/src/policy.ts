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
  Capture,
  Event as AnyEvent,
} from "enclavid:policy/types@0.1.0";
import * as photo from "enclavid:well-known/photo@0.1.0";
import { read } from "enclavid:face-detect/photo@0.1.0";
import { estimate } from "enclavid:face-age/image@0.1.0";
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
// takes it, since a plugin (`photo.selfie()`) cannot be asked when the
// module first runs, as the policy is built.
const steps = {
  selfie: (): Step => [
    null,
    { tag: "render", val: { tag: "media", val: photo.selfie() } },
  ],
  approve: (): Step => [null, { tag: "finish", val: "approved" }],
  reject: (): Step => [null, { tag: "finish", val: "rejected" }],
};

export const policy = definePolicy(
  withStart<State, Event, Action>({
    start: () => steps.selfie(),
    handle: (_state, event) => {
      // The selfie has no time limit, so its reply is its captures.
      const age =
        event.val.tag === "ok" ? estimateAge(event.val.val) : undefined;
      // No face in the oval to read: ask again as is — or ask with a
      // media-spec of your own that says what went wrong, or reject.
      if (age === undefined) return steps.selfie();
      // The props are the consumer's, the same in every round.
      return age >= props.get().minAge ? steps.approve() : steps.reject();
    },
  }),
);

// The age of the face in a selfie, or none: a photo that does not decode, no
// face filling the oval or more than one face, or a face too small to read.
// The platform decodes the photo into an image; face-detect reads the face in
// it against the guide the selfie was taken to, its oval, and face-age reads
// its age from the face's own crop, at the image's full size.
function estimateAge(captures: Capture[]): number | undefined {
  // A capture for each step of the spec, of the kind the step asked for: the
  // selfie's spec is one photo, with the guide the runtime copied from it.
  const [selfie] = captures;
  if (selfie?.tag !== "photo" || !selfie.val.guide) return;
  const image = selfie.val.photo.image();
  if (!image) return;
  const { face, status } = read(image, selfie.val.guide);
  if (status !== "followed" || !face) return;
  return estimate(image, face)?.age;
}
