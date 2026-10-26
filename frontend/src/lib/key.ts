// Applicant key generation + storage.
//
// The applicant_session_token is a 32-byte secret used as the inner AEAD key
// for session state on the host. Real entropy comes from
// `crypto.getRandomValues` — that's what the security guarantee
// rests on. We additionally collect pointer move events while the
// user "draws to seed their key": each (x, y, t) tuple is mixed into
// a SHA-256 accumulator, then HMAC'd with a fresh random IKM at
// finalize. The drawing ritual is **UX**, not a cryptographic
// requirement — it builds trust by giving the user a visible,
// participatory step. Even if the user produces zero entropy via
// drawing, the key is still secure due to the random IKM.
//
// Storage: `enclavid:key:<id>`, as the key and when it was made, in two
// places. localStorage keeps it while the session runs, across reloads and
// tabs; once the session has its decision only this tab keeps it, in
// sessionStorage, so a reload still shows the decision and closing the tab
// forgets it (`keepKeyInTabOnly`). A session that ended without one forgets it
// everywhere (`clearKey`), and keys left behind by sessions never finished
// are dropped by age (`pruneKeys`).

const STORAGE_PREFIX = "enclavid:key:";
const KEY_LEN = 32;

// The longest a key is kept: past it, the session it opens has ended under any
// terms a consumer can be given, and the key opens nothing anyone should still
// hold.
const KEY_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

type Stored = { key: string; created: number };

// Empirically maps to roughly 2-3 seconds of continuous drawing
// on mobile. In theory pointermove fires at 60-120Hz, but browsers
// coalesce events and users draw in short discrete strokes (lift,
// stroke, lift, stroke) so the effective rate is closer to ~30Hz.
// Threshold is purely UX — long enough that the ritual feels
// deliberate, short enough that users don't get bored. Anything
// above ~100 saturates at the same perceived duration because
// extra points are dominated by the natural pause between strokes.
const ENTROPY_TARGET_POINTS = 200;

// --- Storage ---

export function loadKey(sessionId: string): Uint8Array | null {
  const name = STORAGE_PREFIX + sessionId;
  const stored =
    read(localStorage.getItem(name)) ?? read(sessionStorage.getItem(name));
  if (!stored) return null;
  try {
    return base64Decode(stored.key);
  } catch {
    return null;
  }
}

export function storeKey(sessionId: string, key: Uint8Array): void {
  const stored = JSON.stringify({
    key: base64Encode(key),
    created: Date.now(),
  } satisfies Stored);
  localStorage.setItem(STORAGE_PREFIX + sessionId, stored);
  sessionStorage.setItem(STORAGE_PREFIX + sessionId, stored);
}

/// The session has its decision: keep the key in this tab alone, so a reload
/// still shows the decision, and let closing the tab forget it. Once a session
/// is decided its key opens nothing but that decision.
export function keepKeyInTabOnly(sessionId: string): void {
  localStorage.removeItem(STORAGE_PREFIX + sessionId);
}

/// Forget the key of a session that ended without a decision to show: it
/// opens nothing that still runs, and a key kept past its session is only
/// something to take.
export function clearKey(sessionId: string): void {
  localStorage.removeItem(STORAGE_PREFIX + sessionId);
  sessionStorage.removeItem(STORAGE_PREFIX + sessionId);
}

/// Drop every key older than `KEY_MAX_AGE_MS`, and any that cannot be read —
/// those of sessions abandoned before they ended, whose `clearKey` never ran.
export function pruneKeys(): void {
  const now = Date.now();
  const names: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const name = localStorage.key(i);
    if (name?.startsWith(STORAGE_PREFIX)) names.push(name);
  }
  for (const name of names) {
    const stored = read(localStorage.getItem(name));
    if (!stored || now - stored.created > KEY_MAX_AGE_MS) localStorage.removeItem(name);
  }
}

function read(raw: string | null): Stored | null {
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as Partial<Stored>;
    return typeof value.key === "string" && typeof value.created === "number"
      ? { key: value.key, created: value.created }
      : null;
  } catch {
    return null;
  }
}

/// A key straight from the browser's random source, for a link that skips the
/// drawing (`explicitSeed`): what `EntropyAccumulator::finalize` rests on, with
/// nothing mixed in.
export function randomKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(KEY_LEN));
}

// --- Entropy collection ---

/// Accumulator for pointer-event entropy during the ritual. Holds
/// raw event tuples until `finalize()` mixes them into a 32-byte
/// applicant_session_token alongside fresh `crypto.getRandomValues` material.
export class EntropyAccumulator {
  private points: Array<[number, number, number]> = [];

  push(x: number, y: number, t: number): void {
    this.points.push([x, y, t]);
  }

  /// 0..1 fraction of the UX threshold reached.
  progress(): number {
    return Math.min(1, this.points.length / ENTROPY_TARGET_POINTS);
  }

  /// True when enough points are collected to enable "Continue".
  ready(): boolean {
    return this.points.length >= ENTROPY_TARGET_POINTS;
  }

  /// Mix collected points + crypto.getRandomValues into a 32-byte
  /// key. Idempotent on the accumulator state — caller can call
  /// finalize multiple times if they want, though normally we call
  /// once and stash in localStorage.
  async finalize(): Promise<Uint8Array> {
    const drawn = await sha256(serializePoints(this.points));
    const ikm = crypto.getRandomValues(new Uint8Array(KEY_LEN));
    const salt = crypto.getRandomValues(new Uint8Array(KEY_LEN));
    // HKDF-Extract: HMAC-SHA-256(salt, ikm || drawn). Drawn is mixed
    // in as additional input — won't weaken `ikm` even if drawn has
    // zero real entropy.
    const ikmKey = await crypto.subtle.importKey(
      "raw",
      salt,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const combined = new Uint8Array(ikm.length + drawn.length);
    combined.set(ikm, 0);
    combined.set(drawn, ikm.length);
    const sig = await crypto.subtle.sign("HMAC", ikmKey, combined);
    return new Uint8Array(sig);
  }
}

function serializePoints(points: Array<[number, number, number]>): Uint8Array {
  // 24 bytes per point: 3 × float64 (x, y, t). Endianness fixed
  // little-endian so the same input always hashes the same way.
  const buf = new ArrayBuffer(points.length * 24);
  const view = new DataView(buf);
  let off = 0;
  for (const [x, y, t] of points) {
    view.setFloat64(off, x, true);
    view.setFloat64(off + 8, y, true);
    view.setFloat64(off + 16, t, true);
    off += 24;
  }
  return new Uint8Array(buf);
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  // TS 5.7+ types `Uint8Array` as `Uint8Array<ArrayBufferLike>` so a
  // bare `Uint8Array` parameter no longer satisfies `BufferSource`.
  // We always construct from real ArrayBuffers in this module, so
  // the narrowing is sound.
  const buf = await crypto.subtle.digest(
    "SHA-256",
    data as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(buf);
}

// --- Base64 helpers (standard alphabet, matches host-bridge auth) ---

export function base64Encode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function base64Decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
