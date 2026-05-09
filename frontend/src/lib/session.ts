// URL convention: `/session/{id}/...` — the consumer redirects the
// applicant here with a session_id baked into the path. We pull the
// id at app start and stash it for downstream callers.

const PATH_RE = /^\/session\/([^/]+)/;

export function getSessionId(): string | null {
  const m = window.location.pathname.match(PATH_RE);
  return m ? m[1] : null;
}
