import { useEffect, useRef, useState, type ReactNode } from "react";
import { Route, Router, Switch, useLocation } from "wouter";
import { useHashLocation } from "wouter/use-hash-location";
import { SessionRequired } from "@/screens/SessionRequired";
import { Loading } from "@/screens/Loading";
import { Welcome } from "@/screens/Welcome";
import { Ritual } from "@/screens/Ritual";
import { Verify } from "@/screens/Verify";
import { Completed } from "@/screens/Completed";
import { Terminated } from "@/screens/Terminated";
import { Unavailable } from "@/screens/Unavailable";
import { getSessionId } from "@/lib/session";
import { loadKey } from "@/lib/key";
import { connect, getStatus, submitInput, ApiError } from "@/lib/api";
import type { Decision, SessionProgress } from "@/types";

// Routing model. The page's address names the session (`…/<session id>`,
// see `lib/session.ts`); the URL fragment is the source of truth for which
// step of it is shown — wouter matches its routes against the fragment
// rather than the path, and the back button works for free. The steps go
// in the fragment because the page's references are relative to its own
// address (see `vite.config.ts`), so its path cannot grow a segment per
// step. Three states sit *outside* the URL because they're decided by
// the server, not user navigation: `completed`, `terminated` (the
// session is gone or over) and `unavailable` (the service did not
// answer — the session is fine). We surface those as overlays that
// ignore the location.
type Terminal = "completed" | "terminated" | "unavailable";

export function App() {
  return (
    <Router hook={useHashLocation}>
      <SessionFromLocation />
    </Router>
  );
}

function SessionFromLocation() {
  // The path is fixed for the page's life: another session is another
  // address, and so another page load.
  const sessionId = getSessionId(window.location.pathname);
  if (!sessionId) return <SessionRequired />;
  return <Session sessionId={sessionId} />;
}

// The fragment as wouter's hash location reads it — without its `#`,
// with one leading slash — but read from the window at the moment of
// asking, for a callback that outlives the render that created it.
function currentLocation(): string {
  return "/" + window.location.hash.replace(/^#?\/?/, "");
}

function Session({ sessionId }: { sessionId: string }) {
  const [location, setLocation] = useLocation();

  const [terminal, setTerminal] = useState<Terminal | null>(null);
  const [statusFetched, setStatusFetched] = useState(false);
  const [terminationReason, setTerminationReason] = useState<
    string | undefined
  >(undefined);
  const [progress, setProgress] = useState<SessionProgress | null>(null);
  const [completedDecision, setCompletedDecision] = useState<
    Decision | undefined
  >(undefined);
  const [error, setError] = useState<string | null>(null);
  // Per-mount latch on the auto-/connect effect: re-armed every time
  // the user leaves /verify so back→forward navigation re-fires the
  // request, but a single visit to /verify only triggers one /connect.
  const connectFiredRef = useRef(false);

  // Status fetch + initial route normalization. Runs once per
  // session_id. Terminal statuses bypass the URL entirely; for a
  // running session we pin location to a valid sub-path.
  // ref guard makes this strict-mode safe in dev: React replays
  // mount→unmount→mount, but we only want one network fetch.
  const statusFiredRef = useRef(false);
  useEffect(() => {
    if (statusFiredRef.current) return;
    statusFiredRef.current = true;
    void (async () => {
      try {
        const { status } = await getStatus(sessionId);
        if (status === "completed") {
          // /status is decisionless on purpose (public endpoint —
          // sensitive verdict shouldn't leak via forwarded URLs).
          // To show the right Completed variant on reload we
          // re-fetch the decision via authenticated /connect,
          // which requires the applicant key. If the key is gone
          // (cleared storage, link reopened in a different
          // browser) we fall through to the neutral fallback.
          const key = loadKey(sessionId);
          if (key) {
            try {
              const next = await connect(sessionId, key);
              if (next.status === "completed") {
                setCompletedDecision(next.decision);
              }
            } catch {
              // Decision unknown — Completed renders its neutral
              // fallback. Not worth a UI error, the session is
              // already done.
            }
          }
          setTerminal("completed");
          return;
        }
        if (
          status === "failed" ||
          status === "expired" ||
          status === "unspecified"
        ) {
          setTerminal("terminated");
          return;
        }
        // Read afresh rather than from the render that started this
        // fetch: the fragment may have moved on while it was out.
        const step = currentLocation().slice(1).replace(/[/?].*$/, "");
        const hasKey = !!loadKey(sessionId);
        const valid =
          step === "start" || step === "keygen" || step === "verify";
        if (!valid) {
          // No step — a fresh link — or one we don't recognize: pick the
          // right starting screen based on whether the user has a key
          // already.
          setLocation(hasKey ? "/verify" : "/start", { replace: true });
        } else if (step === "verify" && !hasKey) {
          // URL says verify but we have no key (cleared storage,
          // shared link). Drop them at the start.
          setLocation("/start", { replace: true });
        }
        setStatusFetched(true);
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) {
          setTerminationReason(
            "We couldn't find this verification session. Request a new link from the service that sent you here.",
          );
          setTerminal("terminated");
        } else {
          // A 5xx or no answer says nothing about the session; telling the
          // applicant it ended would send them away from one that is fine.
          setTerminal("unavailable");
        }
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

  // Auto-/connect on /verify. Re-arms whenever we leave /verify so
  // back→forward through the history re-issues the call (the user may
  // have redrawn the key on the way).
  //
  // Gate on `statusFetched`: the status useEffect sets that flag only
  // for running sessions. Terminal sessions (completed / failed /
  // expired) short-circuit before setting it. Without this gate, a
  // reload on `/verify` for an already-completed session would send a
  // second /connect beside the status effect's own (fired to fetch the
  // decision). /connect only reads a session that has its decision, so
  // the pair would agree — but one is all the page needs.
  useEffect(() => {
    if (!statusFetched) return;
    const onVerify = location === "/verify";
    if (!onVerify) {
      connectFiredRef.current = false;
      return;
    }
    if (connectFiredRef.current) return;
    const key = loadKey(sessionId);
    if (!key) return;
    connectFiredRef.current = true;
    void connectAndRender(sessionId, key);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location, sessionId, statusFetched]);

  async function connectAndRender(id: string, key: Uint8Array) {
    setError(null);
    try {
      const next = await connect(id, key);
      setProgress(next);
    } catch (e) {
      const msg =
        e instanceof ApiError
          ? `Server returned ${e.status}.`
          : "Could not reach the server.";
      setError(msg);
    }
  }

  async function submitAndRender(
    slotId: string,
    form: FormData,
  ): Promise<void> {
    const key = loadKey(sessionId);
    if (!key) {
      // Shouldn't happen on /verify (route guard ensures key exists),
      // but throw rather than silently no-op so the caller surfaces
      // it instead of looking like a successful submit.
      throw new Error("No applicant key available.");
    }
    setError(null);
    try {
      const next = await submitInput(sessionId, slotId, key, form);
      setProgress(next);
    } catch (e) {
      const msg =
        e instanceof ApiError
          ? `Server returned ${e.status}.`
          : "Could not reach the server.";
      setError(msg);
      throw e;
    }
  }

  if (terminal === "completed")
    return wrap("completed", <Completed decision={completedDecision} />);
  if (terminal === "terminated")
    return wrap("terminated", <Terminated reason={terminationReason} />);
  if (terminal === "unavailable") return wrap("unavailable", <Unavailable />);
  if (!statusFetched) return wrap("loading", <Loading />);

  // Keyed wrapper drives the per-screen mount animation. React
  // unmounts the old subtree and mounts a fresh one when `location`
  // changes, so `animate-in` fires on every navigation.
  return wrap(
    location,
    <Switch>
      <Route path="/start">
        <Welcome onBegin={() => setLocation("/keygen")} />
      </Route>
      <Route path="/keygen">
        <Ritual sessionId={sessionId} onReady={() => setLocation("/verify")} />
      </Route>
      <Route path="/verify">
        <Verify
          progress={progress}
          error={error}
          onSubmit={submitAndRender}
        />
      </Route>
      <Route>
        <Loading />
      </Route>
    </Switch>,
  );
}

function wrap(key: string, child: ReactNode) {
  // Caps the content column on wide screens. The flow is mobile-first
  // so a desktop user sees the same proportions instead of a button
  // sprawling edge-to-edge across a 27" monitor. `w-full` lets it
  // collapse below the cap on phones; `mx-auto` centres the column.
  return (
    <div
      key={key}
      className="mx-auto w-full max-w-md animate-in fade-in slide-in-from-bottom-2 duration-300 fill-mode-both"
    >
      {child}
    </div>
  );
}
