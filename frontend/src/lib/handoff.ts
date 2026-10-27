// Carrying a session to another device — a computer's applicant who would rather
// use a phone's camera, say. The page that holds the session asks api for a
// hand-over and shows it as a QR code of the page's own address with
// `#handoff=<hand-over>`. The phone's page takes the session over with a key it
// makes itself, and from then on the computer's key opens nothing.
//
// No key travels in an address. A page never adopts a key it was given — a key
// from outside could be one the consumer, who writes the applicant's link, also
// holds. The hand-over is sealed by api, opens nowhere else, and is good for one
// take of the one lock it was made against, within minutes; taking it shuts out
// whoever held the session. So a code from someone else gives them nothing, and
// the applicant's own phone gets the session to itself. The page that showed a
// code takes its own session over when the code is put away, which leaves every
// code it showed dead.
//
// The fragment is never sent to any server, and the receiving page wipes it from
// its address as it takes it. The address must stay one the gateway answers
// without a redirect: a browser carries a fragment on across a redirect whose
// target names none.

import { ApiError, heldBy, takeOver } from "@/lib/api";
import {
  clearPendingKey,
  loadPendingKey,
  randomKey,
  storeKey,
  storePendingKey,
} from "@/lib/key";

const FRAGMENT = /^#handoff=([A-Za-z0-9_-]+)$/;

/// The address that hands this session over to another device.
export function handoffLink(handoff: string): string {
  return `${location.origin}${location.pathname}#handoff=${handoff}`;
}

/// Take a hand-over out of the address, once, before anything else reads it,
/// leaving the page at the session's verification step. The take itself waits
/// for the page to know where the session stands.
export function takeHandoff(): string | null {
  const handed = location.hash.match(FRAGMENT);
  if (!handed) return null;
  history.replaceState(null, "", `${location.pathname}${location.search}#/verify`);
  return handed[1];
}

/// What taking a hand-over came to: the session `taken` under the new key,
/// `refused` (expired, taken already, its lock replaced, or not this session's),
/// or `unknown` when neither api's answer nor the new key said.
export type Take =
  | { kind: "taken"; key: Uint8Array }
  | { kind: "refused" }
  | { kind: "unknown" };

/// Take the session over from `handoff` with a key this browser makes now, kept
/// as this browser's key once taken. The key waits as pending before the
/// request leaves, so an answer lost after api took the session — the network
/// gone, the tab closed — does not lose the session with it: the pending key
/// is asked whether it holds the session, now or on a later load.
export async function takeOverHere(
  sessionId: string,
  handoff: string,
): Promise<Take> {
  const key = randomKey();
  storePendingKey(sessionId, key);
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await takeOver(sessionId, key, handoff);
      storeKey(sessionId, key);
      clearPendingKey(sessionId);
      return { kind: "taken", key };
    } catch (e) {
      if (!(e instanceof ApiError) || e.status >= 500) break;
      // A round or another take landed between api's read and its write:
      // asked once more, against the session as it now is.
      if (e.status === 409 && attempt === 0) continue;
      clearPendingKey(sessionId);
      return { kind: "refused" };
    }
  }
  return (await settlePendingKey(sessionId)) === "held"
    ? { kind: "taken", key }
    : { kind: "unknown" };
}

/// A take whose answer never came, settled: its pending key becomes this
/// browser's key when it holds the session, and is dropped when it does not;
/// it keeps waiting when that cannot be learned yet.
export async function settlePendingKey(
  sessionId: string,
): Promise<"held" | "dropped" | "waiting" | "none"> {
  const pending = loadPendingKey(sessionId);
  if (!pending) return "none";
  try {
    if ((await heldBy(sessionId, pending)) === "held") {
      storeKey(sessionId, pending);
      clearPendingKey(sessionId);
      return "held";
    }
    clearPendingKey(sessionId);
    return "dropped";
  } catch {
    return "waiting";
  }
}
