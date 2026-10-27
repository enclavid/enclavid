import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
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
import { StartedElsewhere } from "@/screens/StartedElsewhere";
import { Moved } from "@/screens/Moved";
import { explicitSeed, getSessionId } from "@/lib/session";
import { startEnclaveCheck } from "@/lib/enclave";
import { settlePendingKey, takeOverHere } from "@/lib/handoff";
import {
  clearKey,
  keepKeyInTabOnly,
  loadKey,
  pruneKeys,
  randomKey,
  sameKey,
  storeKey,
} from "@/lib/key";
import {
  connect,
  getStatus,
  resetState,
  submitInput,
  warmup,
  ApiError,
} from "@/lib/api";
import type { Decision, SessionProgress } from "@/types";

// Routing model. The page's address names the session (`…/<session id>`,
// see `lib/session.ts`); the URL fragment is the source of truth for which
// step of it is shown — wouter matches its routes against the fragment
// rather than the path, and the back button works for free. The steps go
// in the fragment because the page's references are relative to its own
// address (see `vite.config.ts`), so its path cannot grow a segment per
// step. Six states sit *outside* the URL because they're decided by
// the server, not user navigation: `completed`, `terminated` (the
// session is gone or over), `unavailable` (the service did not
// answer — the session is fine), `elsewhere` (this browser's key
// does not open the session: it is another browser's), `moved`
// (this page showed a code, and the session was taken over from it)
// and `refused_code` (this page was opened from a code that could not
// be taken). We surface those as overlays that ignore the location.
type Terminal =
  | "completed"
  | "terminated"
  | "unavailable"
  | "elsewhere"
  | "moved"
  | "refused_code";

/// `handoff`: a hand-over another device showed this one, taken out of the
/// address before the page started (see `lib/handoff.ts`).
export function App({ handoff }: { handoff: string | null }) {
  return (
    <Router hook={useHashLocation}>
      <SessionFromLocation handoff={handoff} />
    </Router>
  );
}

function SessionFromLocation({ handoff }: { handoff: string | null }) {
  // The path is fixed for the page's life: another session is another
  // address, and so another page load.
  const sessionId = getSessionId(window.location.pathname);
  if (!sessionId) return <SessionRequired />;
  return <Session sessionId={sessionId} handoff={handoff} />;
}

// The fragment as wouter's hash location reads it — without its `#`,
// with one leading slash — but read from the window at the moment of
// asking, for a callback that outlives the render that created it.
function currentLocation(): string {
  return "/" + window.location.hash.replace(/^#?\/?/, "");
}

function Session({
  sessionId,
  handoff,
}: {
  sessionId: string;
  handoff: string | null;
}) {
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

  // The session was taken over from the code this page showed: this browser's
  // key opens nothing any more, and the session goes on without this page.
  // Only when `refused` is still the key this browser holds: one it has made
  // since — its own take landing while the answer for the old key was out —
  // holds the session, and stays.
  const moved = useCallback(
    (refused: Uint8Array) => {
      const held = loadKey(sessionId);
      if (held && !sameKey(held, refused)) return;
      clearKey(sessionId);
      setTerminal("moved");
    },
    [sessionId],
  );

  const finishedElsewhere = useCallback(() => setTerminal("completed"), []);

  // Where the session runs is checked as the page opens, beside the status
  // fetch, so the welcome has the result to show; and keys left behind by
  // sessions abandoned long ago go.
  useEffect(() => {
    startEnclaveCheck(sessionId);
    pruneKeys();
  }, [sessionId]);

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
          // browser or in a new tab after the session ended) we
          // fall through to the neutral fallback.
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
          // The session is decided: its key stays with this tab alone.
          keepKeyInTabOnly(sessionId);
          setTerminal("completed");
          return;
        }
        if (
          status === "init_failed" ||
          status === "expired" ||
          status === "unspecified"
        ) {
          clearKey(sessionId);
          setTerminal("terminated");
          return;
        }
        // A hand-over another device showed this one: taken with a key this
        // browser makes, which alone opens the session from then on. One that
        // is refused — expired, taken already, or made before the session
        // changed hands — is said plainly to a browser with no key of its own;
        // one whose outcome is unknown leaves the page to go on as for any link.
        // A take an earlier visit sent and never heard back from is settled
        // first: its key may be the one that holds the session.
        await settlePendingKey(sessionId);
        if (handoff) {
          const take = await takeOverHere(sessionId, handoff);
          if (take.kind === "refused" && !loadKey(sessionId)) {
            setTerminal("refused_code");
            return;
          }
        }
        // Read afresh rather than from the render that started this
        // fetch: the fragment may have moved on while it was out.
        const step = currentLocation().slice(1).replace(/[/?].*$/, "");
        const hasKey = !!loadKey(sessionId);
        // An applicant with no key yet is a while from /connect: have
        // the session made ready meanwhile.
        if (!hasKey) void warmup(sessionId);
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
          clearKey(sessionId);
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

  // The progress a request answered with; once the session has its decision,
  // its key stays with this tab alone.
  function show(next: SessionProgress) {
    if (next.status === "completed") keepKeyInTabOnly(sessionId);
    setProgress(next);
  }

  async function connectAndRender(id: string, key: Uint8Array) {
    setError(null);
    try {
      show(await connect(id, key));
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        setTerminal("elsewhere");
        return;
      }
      const msg =
        e instanceof ApiError
          ? `Server returned ${e.status}.`
          : "Could not reach the server.";
      setError(msg);
    }
  }

  async function submitAndRender(
    awaitingSeq: number,
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
      show(await submitInput(sessionId, awaitingSeq, slotId, key, form));
    } catch (e) {
      // Refused for its key: the session was started over elsewhere while
      // this page was on a step.
      if (e instanceof ApiError && e.status === 403) {
        setTerminal("elsewhere");
      } else {
        setError(
          e instanceof ApiError
            ? `Server returned ${e.status}.`
            : "Could not reach the server.",
        );
      }
      throw e;
    }
  }

  // A key of this browser's own for the session — drawn, or made at random
  // when the link says to skip the drawing — and on to the session.
  function beginKey() {
    if (explicitSeed(window.location.search)) {
      setLocation("/keygen");
      return;
    }
    storeKey(sessionId, randomKey());
    setLocation("/verify");
  }

  // Hands the session back and claims it anew: what was done in the other
  // browser goes. The claim is made with a key this browser makes now, never
  // with the one the session just refused. A session that finished, or moved
  // on meanwhile, refuses (409) and is read afresh.
  async function startOver() {
    try {
      await resetState(sessionId);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        window.location.reload();
        return;
      }
      throw e;
    }
    clearKey(sessionId);
    setProgress(null);
    setTerminal(null);
    // A page that came here from a refused code never finished reading the
    // session: it has now, as one with no key.
    setStatusFetched(true);
    if (explicitSeed(window.location.search)) {
      setLocation("/keygen");
      return;
    }
    // Already on /verify, whose /connect fired for the refused key: this one
    // is sent from here.
    const key = randomKey();
    storeKey(sessionId, key);
    await connectAndRender(sessionId, key);
  }

  if (terminal === "completed")
    return wrap("completed", <Completed decision={completedDecision} />);
  if (terminal === "terminated")
    return wrap("terminated", <Terminated reason={terminationReason} />);
  if (terminal === "unavailable") return wrap("unavailable", <Unavailable />);
  if (terminal === "elsewhere")
    return wrap(
      "elsewhere",
      <StartedElsewhere reason="elsewhere" onStartOver={startOver} />,
    );
  if (terminal === "refused_code")
    return wrap(
      "refused_code",
      <StartedElsewhere reason="code" onStartOver={startOver} />,
    );
  if (terminal === "moved")
    return wrap(
      "moved",
      <Moved
        sessionId={sessionId}
        onCompleted={finishedElsewhere}
        onStartOver={startOver}
      />,
    );
  if (!statusFetched) return wrap("loading", <Loading />);

  // Keyed wrapper drives the per-screen mount animation. React
  // unmounts the old subtree and mounts a fresh one when `location`
  // changes, so `animate-in` fires on every navigation.
  return wrap(
    location,
    <Switch>
      <Route path="/start">
        <Welcome
          onBegin={() => {
            // A key this browser already holds for the session is kept: a new
            // one would not open what the first one claimed.
            if (loadKey(sessionId)) {
              setLocation("/verify");
              return;
            }
            beginKey();
          }}
        />
      </Route>
      <Route path="/keygen">
        <Ritual sessionId={sessionId} onReady={() => setLocation("/verify")} />
      </Route>
      <Route path="/verify">
        <Verify
          sessionId={sessionId}
          progress={progress}
          error={error}
          onSubmit={submitAndRender}
          onMoved={moved}
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
