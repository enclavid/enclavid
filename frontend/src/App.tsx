import { useEffect, useRef, useState, type ReactNode } from "react";
import { Route, Switch, useLocation } from "wouter";
import { SessionRequired } from "@/screens/SessionRequired";
import { Loading } from "@/screens/Loading";
import { Welcome } from "@/screens/Welcome";
import { Ritual } from "@/screens/Ritual";
import { Verify } from "@/screens/Verify";
import { Completed } from "@/screens/Completed";
import { Terminated } from "@/screens/Terminated";
import { getSessionId } from "@/lib/session";
import { loadKey } from "@/lib/key";
import { connect, getStatus, ApiError } from "@/lib/api";
import { verifyAttestation, type AttestationResult } from "@/lib/attestation";
import type { SessionProgress } from "@/types";

// Routing model. The browser URL is the source of truth for which
// "real" screen is shown — wouter does the path matching and the back
// button works for free. Two states sit *outside* the URL because
// they're decided by the server, not user navigation: `completed` and
// `terminated`. We surface those as overlays that ignore the location.
type Terminal = "completed" | "terminated";

export function App() {
  const sessionId = getSessionId();
  const [location, setLocation] = useLocation();

  const [terminal, setTerminal] = useState<Terminal | null>(null);
  const [statusFetched, setStatusFetched] = useState(false);
  const [terminationReason, setTerminationReason] = useState<
    string | undefined
  >(undefined);
  const [attestation, setAttestation] = useState<AttestationResult | null>(
    null,
  );
  const [progress, setProgress] = useState<SessionProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Per-mount latch on the auto-/connect effect: re-armed every time
  // the user leaves /verify so back→forward navigation re-fires the
  // request, but a single visit to /verify only triggers one /connect.
  const connectFiredRef = useRef(false);

  // Attestation runs in parallel with status — independent concerns,
  // result feeds the footer badge and Welcome's inline animation.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const result = await verifyAttestation();
      if (!cancelled) setAttestation(result);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Status fetch + initial route normalization. Runs once per
  // session_id. Terminal statuses bypass the URL entirely; for a
  // running session we pin location to a valid sub-path.
  useEffect(() => {
    if (!sessionId) return;
    let cancelled = false;
    void (async () => {
      try {
        const { status } = await getStatus(sessionId);
        if (cancelled) return;
        if (status === "completed") {
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
        const prefix = `/session/${sessionId}/`;
        const sub = location.startsWith(prefix)
          ? location.slice(prefix.length).replace(/\/$/, "")
          : "";
        const hasKey = !!loadKey(sessionId);
        const valid =
          sub === "start" || sub === "keygen" || sub === "verify";
        if (!valid) {
          // Bare /session/:id/ (or anything we don't recognize) — pick
          // the right starting screen based on whether the user has a
          // key already.
          setLocation(`${prefix}${hasKey ? "verify" : "start"}`, {
            replace: true,
          });
        } else if (sub === "verify" && !hasKey) {
          // URL says verify but we have no key (cleared storage,
          // shared link). Drop them at the start.
          setLocation(`${prefix}start`, { replace: true });
        }
        setStatusFetched(true);
      } catch (e) {
        if (cancelled) return;
        if (e instanceof ApiError && e.status === 404) {
          setTerminationReason(
            "We couldn't find this verification session. Request a new link from the service that sent you here.",
          );
        } else {
          setTerminationReason(
            "Couldn't reach the verification service. Please check your connection and reload.",
          );
        }
        setTerminal("terminated");
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

  // Auto-/connect on /verify. Re-arms whenever we leave /verify so
  // back→forward through the history re-issues the call (the user may
  // have redrawn the key on the way).
  useEffect(() => {
    if (!sessionId) return;
    const onVerify = location === `/session/${sessionId}/verify`;
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
  }, [location, sessionId]);

  if (!sessionId) return <SessionRequired />;
  const sid = sessionId;

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

  if (terminal === "completed") return wrap("completed", <Completed />);
  if (terminal === "terminated")
    return wrap("terminated", <Terminated reason={terminationReason} />);
  if (!statusFetched) return wrap("loading", <Loading />);

  // Keyed wrapper drives the per-screen mount animation. React
  // unmounts the old subtree and mounts a fresh one when `location`
  // changes, so `animate-in` fires on every navigation.
  return wrap(
    location,
    <Switch>
      <Route path={`/session/${sid}/start`}>
        <Welcome
          attestation={attestation}
          onBegin={() => setLocation(`/session/${sid}/keygen`)}
        />
      </Route>
      <Route path={`/session/${sid}/keygen`}>
        <Ritual
          sessionId={sid}
          attestation={attestation}
          onReady={() => setLocation(`/session/${sid}/verify`)}
        />
      </Route>
      <Route path={`/session/${sid}/verify`}>
        <Verify progress={progress} error={error} />
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
