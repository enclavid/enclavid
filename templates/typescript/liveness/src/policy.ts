// A liveness check by video: well-known's guides of a check by turns, new for
// each attempt — the applicant fits their face in an oval of a size picked at
// random, then turns their head to one side and the other. The session ends
// approved when the applicant followed every guide and the face they held in
// the oval looks live; rejected when not. Nothing is disclosed and nothing is
// kept: the consumer learns the decision alone.
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
import * as videoGuides from "enclavid:well-known/video-guides@0.1.0";
import * as video from "enclavid:well-known/video@0.1.0";
import { read } from "enclavid:face-detect/video@0.1.0";
import { estimate } from "enclavid:face-liveness/video@0.1.0";

// How many times the video is asked for: a second time, with new values,
// where the first ran out of time.
const ATTEMPTS = 2;
// How live the face held in the oval must look, at least: face-liveness's
// score, from 0 for a spoof to 1 for a live face. A score, not a probability:
// the threshold that suits is the one the implementation pinned is meant for.
const LIVE_MIN = 0.5;

// How many times the video has been asked for.
type State = { attempts: number };

// What a step returns: the state to keep, and what to do now.
type Step = [State, Action];

// The events this policy gets: `start`, then the answer to the video it
// rendered last — it renders media prompts alone, and the runtime delivers no
// other answer.
type Event = Extract<AnyEvent, { tag: "start" | "media" }>;

const steps = {
  // The guides are new for each attempt, drawn from a seed of the round's
  // randomness; the page is given them only once the applicant starts the
  // video, so they are not known before.
  video: (attempts: number): Step => [
    { attempts },
    {
      tag: "render",
      val: {
        tag: "media",
        val: video.liveness(
          videoGuides.livenessTurns(
            crypto.getRandomValues(new Uint32Array(1))[0],
          ),
        ),
      },
    },
  ],
  approve: (state: State): Step => [state, { tag: "finish", val: "approved" }],
  reject: (state: State): Step => [state, { tag: "finish", val: "rejected" }],
};

export const policy = definePolicy(
  withStart<State, Event, Action>({
    start: () => steps.video(1),
    handle: (state, event) => {
      switch (event.tag) {
        case "media": {
          const reply = event.val;
          if (reply.tag === "err") {
            switch (reply.val) {
              case "timed-out":
                return state.attempts < ATTEMPTS
                  ? steps.video(state.attempts + 1)
                  : steps.reject(state);
            }
          }
          return passes(reply.val) ? steps.approve(state) : steps.reject(state);
        }
      }
    },
  }),
);

// Whether the video passes: the applicant followed every guide, and the face
// they held in the oval looks live. The guides are the prompt's own, which the
// runtime hands back with the frames the page says each was held in.
function passes(captures: Capture[]): boolean {
  const [capture] = captures;
  if (capture?.tag !== "video") return false;
  const { video: recording, guides } = capture.val;
  const readings = read(recording, guides);
  if (!readings.every(({ status }) => status === "followed")) return false;
  const held = readings.find(({ guide }) => guide.tag === "face");
  const live = held && estimate(recording, held.faces)?.live;
  return (live ?? 0) >= LIVE_MIN;
}
