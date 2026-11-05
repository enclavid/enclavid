// How the page records a video step: the camera drawn onto a canvas as the
// camera sees it — unmirrored — and written as a WebM of VP8 frames, the one
// format the enclave decodes. Through WebCodecs where the browser has them:
// Mediabunny writes the WebM, and the page asks for a frame whole where it
// likes. Else through MediaRecorder: the browser writes the WebM, and puts in
// whole frames as it likes. Either way the recording is read back before it is
// sent, with Mediabunny's own demuxer: what it holds is checked, and each
// frame's time is taken from it. Mediabunny is loaded only when a video step
// asks for it.

/// Frames a second the page draws and records.
export const FPS = 15;

/// The seconds between frames the encoder writes whole on its own, beside
/// those the page asks for.
const KEY_FRAME_SECONDS = 2;

/// The WebM MediaRecorder is asked for: VP8, no sound.
const MIME = "video/webm;codecs=vp8";

/// Which way this browser records.
export type RecorderKind = "webcodecs" | "mediarecorder";

/// The way this browser records a `width` × `height` video at `bitrate` bits a
/// second, or `null` where it records no WebM of VP8 frames.
export async function recorderFor(
  width: number,
  height: number,
  bitrate: number,
): Promise<RecorderKind | null> {
  try {
    const { canEncodeVideo } = await import("mediabunny");
    if (await canEncodeVideo("vp8", { width, height, bitrate })) {
      return "webcodecs";
    }
  } catch {
    // No WebCodecs, or no way to load what writes through them.
  }
  if (typeof MediaRecorder !== "undefined" && MediaRecorder.isTypeSupported(MIME)) {
    return "mediarecorder";
  }
  return null;
}

/// A recording under way of what is drawn on a canvas.
export type Recording = {
  /// Record the canvas as it is drawn now, whole where `whole` asks; resolves
  /// once the encoder can take the next. One at a time.
  frame(whole: boolean): Promise<void>;
  /// End the recording: the video.
  finish(): Promise<Blob>;
  /// Drop the recording.
  cancel(): void;
};

/// What a recording reads back as: the size of its frames, and each frame's
/// time in milliseconds from the first, in order.
export type ReadBack = { width: number; height: number; times: number[] };

/// `video` read back with Mediabunny's own demuxer, or `null` where it is not
/// what the platform decodes: a WebM of VP8 frames, the first written whole.
export async function readBack(video: Blob): Promise<ReadBack | null> {
  try {
    const { BlobSource, EncodedPacketSink, Input, WEBM } = await import("mediabunny");
    const input = new Input({ source: new BlobSource(video), formats: [WEBM] });
    const track = await input.getPrimaryVideoTrack();
    if (!track || track.codec !== "vp8") return null;
    const seconds: number[] = [];
    let whole = false;
    for await (const packet of new EncodedPacketSink(track).packets()) {
      if (seconds.length === 0) whole = packet.type === "key";
      seconds.push(packet.timestamp);
    }
    if (!whole) return null;
    return {
      width: track.codedWidth,
      height: track.codedHeight,
      times: seconds.map((s) => (s - seconds[0]) * 1000),
    };
  } catch {
    return null;
  }
}

/// Start recording `canvas` the `kind` way, at `bitrate` bits a second.
export function startRecording(
  kind: RecorderKind,
  canvas: HTMLCanvasElement,
  bitrate: number,
): Promise<Recording> {
  return kind === "webcodecs"
    ? webCodecsRecording(canvas, bitrate)
    : mediaRecorderRecording(canvas, bitrate);
}

async function webCodecsRecording(
  canvas: HTMLCanvasElement,
  bitrate: number,
): Promise<Recording> {
  const { BufferTarget, CanvasSource, Output, WebMOutputFormat } = await import("mediabunny");
  const target = new BufferTarget();
  const output = new Output({ format: new WebMOutputFormat(), target });
  const source = new CanvasSource(canvas, {
    codec: "vp8",
    bitrate,
    keyFrameInterval: KEY_FRAME_SECONDS,
  });
  output.addVideoTrack(source, { frameRate: FPS });
  await output.start();
  let start: number | null = null;
  return {
    async frame(whole) {
      const now = performance.now();
      start ??= now;
      // At the time it was drawn: a frame the page could not draw on time
      // leaves a gap, not a slower video.
      await source.add((now - start) / 1000, 1 / FPS, { keyFrame: whole });
    },
    async finish() {
      await output.finalize();
      if (!target.buffer) throw new Error("The recording wrote nothing.");
      return new Blob([target.buffer], { type: "video/webm" });
    },
    cancel() {
      void output.cancel();
    },
  };
}

async function mediaRecorderRecording(
  canvas: HTMLCanvasElement,
  bitrate: number,
): Promise<Recording> {
  const stream = canvas.captureStream(FPS);
  const recorder = new MediaRecorder(stream, {
    mimeType: MIME,
    videoBitsPerSecond: bitrate,
  });
  const chunks: Blob[] = [];
  recorder.ondataavailable = (e) => {
    if (e.data.size) chunks.push(e.data);
  };
  const stopped = new Promise<void>((resolve) => {
    recorder.onstop = () => resolve();
  });
  const end = () => stream.getTracks().forEach((t) => t.stop());
  let started = false;
  return {
    async frame() {
      if (!started) {
        started = true;
        // A chunk each second, which the browser begins with a whole frame.
        recorder.start(1000);
      }
    },
    async finish() {
      recorder.stop();
      await stopped;
      end();
      return new Blob(chunks, { type: "video/webm" });
    },
    cancel() {
      if (recorder.state !== "inactive") recorder.stop();
      end();
    },
  };
}
