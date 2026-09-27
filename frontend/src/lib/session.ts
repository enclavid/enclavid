// URL convention: the page is served at the root of wherever it is
// reached, and its routes live in the fragment — `…/#/session/{id}/...`.
// The consumer redirects the applicant to such a link with the
// session_id baked into the fragment. A browser never sends a fragment
// to any server, so loading the page names no session; only the API
// calls the page then makes do. We pull the id out of the router's
// hash location for downstream callers.

// The id stops at a slash or a `?`: a query written after the fragment
// stays inside it, and is no part of the id.
const PATH_RE = /^\/session\/([^/?]+)/;

// `location` is what wouter's hash location hook reports: the fragment
// without its `#`, always with a leading slash, run through `decodeURI`,
// and keeping any `?…` written inside it.
export function getSessionId(location: string): string | null {
  const m = location.match(PATH_RE);
  return m ? m[1] : null;
}
