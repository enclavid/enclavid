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

// The session the page's address names, if it names one.
export function getSessionId(pathname: string): string | null {
  const m = pathname.match(SESSION_RE);
  return m ? m[1] : null;
}
