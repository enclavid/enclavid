// URL convention: a link to one session is the page's own address —
// `…/<session id>`, one segment, `ses_` and hex — and the steps of the
// flow live in the fragment, `#/start` and on. The page is served there
// and at the bare root, at the same depth either way, so what it loads
// and the API it calls resolve beside it (see `vite.config.ts`).
//
// The id is in the path, not the fragment: a browser carries a fragment
// on across a redirect whose target has none, and would take the id to
// wherever one led; a path it never carries.

const SESSION_RE = /\/(ses_[0-9a-f]+)$/;

// The marker a link opens with, `/-<label>.<build>/`: the build the gateway
// routes the link to, an api measurement, 48 bytes in hex.
const BUILD_RE = /^\/-[^/]*\.([0-9a-f]{96})\//;

// The session the page's address names, if it names one.
export function getSessionId(pathname: string): string | null {
  const m = pathname.match(SESSION_RE);
  return m ? m[1] : null;
}

// The build the page's address names, if it came through the gateway.
export function getBuild(pathname: string): string | null {
  const m = pathname.match(BUILD_RE);
  return m ? m[1] : null;
}

// Whether the applicant seeds their key by drawing, which they do unless the
// link says `?explicit_seed=0` — for a consumer whose applicants arrive where
// drawing does not work well. The key is as strong either way: it is drawn
// from the browser's random source, and the strokes are only mixed in (see
// `lib/key.ts`). The parameter only switches a screen; a key never travels in
// an address, and a page never takes one from it (see `lib/handoff.ts`).
export function explicitSeed(search: string): boolean {
  return new URLSearchParams(search).get("explicit_seed") !== "0";
}
