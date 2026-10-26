// Carrying a session to another device — a computer's applicant who would rather
// use a phone's camera, say. The other device needs nothing but the session's
// address and the applicant's key: api ties a session to no device, only to the
// key its state is sealed under.
//
// The key rides in the fragment of the page's own address, `#key=<base64url>`,
// which a browser never sends to any server. Scanned as a QR code it passes
// through no one; sent as a link through a messenger it would sit on that
// messenger's servers, which is why the page offers only the code. Whoever sees
// the code has the session, so the page shows it only when asked, and the
// receiving page wipes it from its address as it takes it.
//
// The address must stay one the gateway answers without a redirect: a browser
// carries a fragment on across a redirect whose target names none.

import { loadKey, storeKey } from "@/lib/key";

// 32 bytes in unpadded base64url.
const FRAGMENT = /^#key=([A-Za-z0-9_-]{43})$/;

/// The address that continues this session on another device, or null when
/// this one holds no key for it.
export function handoffLink(sessionId: string): string | null {
  const key = loadKey(sessionId);
  if (!key) return null;
  return `${location.origin}${location.pathname}#key=${toBase64Url(key)}`;
}

/// Take a key handed over in the address, once: keep it as this device's for
/// the session, and wipe it from the address — from the screen and the history
/// both — before anything else reads it, leaving the page at the session's
/// verification step.
export function takeHandedKey(sessionId: string): void {
  const handed = location.hash.match(FRAGMENT);
  if (!handed) return;
  storeKey(sessionId, fromBase64Url(handed[1]));
  history.replaceState(null, "", `${location.pathname}${location.search}#/verify`);
}

function toBase64Url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(text: string): Uint8Array {
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
