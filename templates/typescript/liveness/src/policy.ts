// A liveness check by video: the applicant fits their face in an oval of a
// size picked at random, holds it while the screen flashes colours, then turns
// their head to one side and the other, in an order picked at random. The
// session ends approved when every checked frame holds a face, the face filled
// the oval, it turned as asked, and it looks live; rejected when not. Nothing
// is disclosed and nothing is kept: the consumer learns the decision alone.
//
// The flashes are shown, not checked: what they cast on the face is read by a
// check of its own, which this template does not run.
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
  MediaSpec,
} from "enclavid:policy/types@0.1.0";
import type { Rgb } from "enclavid:host-capture/video@0.1.0";
import type { Video } from "enclavid:host/media@0.1.0";
import type { Face } from "enclavid:vision/types@0.1.0";
import { detect } from "enclavid:face-detect/detect@0.1.0";
import { estimate } from "enclavid:face-liveness/video@0.1.0";
import { selfie } from "enclavid:host-icons/icons@0.1.0";
import { localized as t } from "enclavid-ext:policy/i18n@0.1.0";

// How many times the video is asked for: a second time, with new values,
// where the first ran out of time.
const ATTEMPTS = 2;
// The seconds the applicant has for the video, from when the page starts it.
const TIME_LIMIT_SECS = 60;
// How live the frontal frames must look, at least: MiniFASNet's score. It
// passes live faces and catches most screens; prints are stopped by the turns.
const LIVE_MIN = 0.5;
// The width of the face's box against the oval's, both as fractions of the
// frame's shorter side, that still counts as filling it: the page's reading
// of the face differs from the detector's, so the bounds are wide.
const FILL_MIN = 0.6;
const FILL_MAX = 1.6;
// The share of a turn's degrees the face must be read as turned, at least:
// the page holds the turn at the full degrees, by a reading of its own.
const TURN_SHARE = 0.6;
// The nose tip's depth before the eyes, in eye distances, as the page reads
// a turn with: MediaPipe's canonical face, 4.01 cm over 6.30 cm.
const NOSE_DEPTH = 0.64;

// How many times the video has been asked for.
type State = { attempts: number };

// What a step returns: the state to keep, and what to do now.
type Step = [State, Action];

// The events this policy gets: `start`, then the answer to the video it
// rendered last — it renders media prompts alone, and the runtime delivers no
// other answer.
type Event = Extract<AnyEvent, { tag: "start" | "media" | "timed-out" }>;

const steps = {
  video: (attempts: number): Step => [
    { attempts },
    { tag: "render", val: { tag: "media", val: challenge() } },
  ],
  approve: (state: State): Step => [state, { tag: "finish", val: "approved" }],
  reject: (state: State): Step => [state, { tag: "finish", val: "rejected" }],
};

export const policy = definePolicy(
  withStart<State, Event, Action>({
    start: () => steps.video(1),
    handle: (state, event) => {
      switch (event.tag) {
        case "media":
          return passes(event.val) ? steps.approve(state) : steps.reject(state);
        case "timed-out":
          return state.attempts < ATTEMPTS
            ? steps.video(state.attempts + 1)
            : steps.reject(state);
      }
    },
  }),
);

// The video the applicant is asked for, its values new each time: the face
// in an oval of a random size, the flashes in the same oval, then a turn to a
// random side and one to the other. The page is given them only once the
// applicant starts the video, so they are not known before.
function challenge(): MediaSpec {
  const width = between(0.4, 0.55);
  const side = Math.random() < 0.5 ? -1 : 1;
  return {
    label: t("title"),
    captures: [
      {
        icon: selfie(),
        instructions: t("instructions"),
        label: t("label"),
        camera: "front",
        kind: {
          tag: "video",
          val: {
            guides: [
              { tag: "face", val: { width, holdMs: 800 } },
              {
                tag: "face-flashes",
                val: {
                  width,
                  colors: Array.from({ length: 5 }, brightColor),
                  flashMs: 300,
                },
              },
              {
                tag: "head-turn",
                val: {
                  degrees: side * Math.round(between(20, 30)),
                  holdMs: 500,
                },
              },
              {
                tag: "head-turn",
                val: {
                  degrees: -side * Math.round(between(20, 30)),
                  holdMs: 500,
                },
              },
            ],
          },
        },
      },
    ],
    timeLimitSecs: TIME_LIMIT_SECS,
  };
}

// Whether the video passes: read over the frames the page says each guide was
// held in. The guides are the prompt's own, which the runtime hands back with
// the ranges, so the policy keeps none of them itself.
function passes(media: MediaResult): boolean {
  const [capture] = media.captures;
  if (capture?.tag !== "video") return false;
  const { video, guides } = capture.val;
  // The nose's offset of the face straight on, which a turn is read from.
  let straight: number | undefined;
  for (const { guide, first, last } of guides) {
    if (guide.tag === "face") {
      const faces = facesIn(video, first, last);
      if (!faces || !fills(faces, guide.val.width)) return false;
      const live = estimate(video, faces)?.live;
      if (live === undefined || live < LIVE_MIN) return false;
      straight = median(faces.map(({ face }) => noseOffset(face)));
    } else if (guide.tag === "head-turn") {
      const faces = facesIn(video, first, last);
      if (!faces || straight === undefined) return false;
      const turn = turnOf(
        median(faces.map(({ face }) => noseOffset(face))),
        straight,
      );
      const asked = guide.val.degrees;
      if (
        Math.sign(turn) !== Math.sign(asked) ||
        Math.abs(turn) < TURN_SHARE * Math.abs(asked)
      ) {
        return false;
      }
    }
  }
  return straight !== undefined;
}

// A face found in a frame, and the frame's shorter side, in pixels.
type Found = { index: number; face: Face; shorter: number };

// The face in each of the frames `first` to `last` of `video`, or none where a
// frame is missing or holds no face the detector finds.
function facesIn(
  video: Video,
  first: number,
  last: number,
): Found[] | undefined {
  const frames = video.frames(first, last);
  if (frames.length !== last - first + 1) return;
  const faces: Found[] = [];
  for (const { index, image } of frames) {
    const face = detect(image);
    if (!face) return;
    const { width, height } = image.size();
    faces.push({ index, face, shorter: Math.min(width, height) });
  }
  return faces;
}

// Whether the faces filled an oval `width` of the frame's shorter side wide.
function fills(faces: Found[], width: number): boolean {
  const share =
    median(faces.map(({ face, shorter }) => face.bbox.w / shorter)) / width;
  return share >= FILL_MIN && share <= FILL_MAX;
}

// The nose tip's offset along the axis from the right eye to the left, in eye
// distances, as the page reads a turn: about 0 for a face straight on. The
// keypoints are BlazeFace's, in its order: the right eye, the left eye, the
// nose tip, and three more.
function noseOffset({ landmarks: [right, left, nose] }: Face): number {
  if (!right || !left || !nose) return NaN;
  const ax = left.x - right.x;
  const ay = left.y - right.y;
  const ex = (left.x + right.x) / 2;
  const ey = (left.y + right.y) / 2;
  return ((nose.x - ex) * ax + (nose.y - ey) * ay) / (ax * ax + ay * ay);
}

// How far a face of nose offset `offset` is turned from one of `straight`, in
// degrees, negative to its own left, as a `head-turn` guide counts them.
function turnOf(offset: number, straight: number): number {
  return (-Math.atan((offset - straight) / NOSE_DEPTH) * 180) / Math.PI;
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)] ?? NaN;
}

// A number from `min` to `max`, at random.
function between(min: number, max: number): number {
  return min + Math.random() * (max - min);
}

// A colour of a random hue, at its brightest.
function brightColor(): Rgb {
  const hue = Math.random() * 6;
  const rise = Math.round(255 * (1 - Math.abs((hue % 2) - 1)));
  const [red, green, blue] = [
    [255, rise, 0],
    [rise, 255, 0],
    [0, 255, rise],
    [0, rise, 255],
    [rise, 0, 255],
    [255, 0, rise],
  ][Math.floor(hue)];
  return { red, green, blue };
}
