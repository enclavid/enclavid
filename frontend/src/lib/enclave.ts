// The page's check of where it runs, made once per page load and read by every
// screen that shows it: the welcome narrates it, the footer badge and its
// dialog report it. The checks themselves are in `lib/attestation.ts`, loaded
// with the check rather than with the page.

import { useSyncExternalStore } from "react";
import { getAttestation, getGatewayAttestation } from "@/lib/api";
import { getBuild } from "@/lib/session";
import type { Enclave } from "@/lib/attestation";

export type EnclaveState =
  | { status: "checking" }
  | { status: "done"; enclave: Enclave; verified: boolean };

let state: EnclaveState = { status: "checking" };
let started = false;
const listeners = new Set<() => void>();

/// Start the check for `sessionId`, once: a second call is the first's.
export function startEnclaveCheck(sessionId: string): void {
  if (started) return;
  started = true;
  void check(sessionId).then((enclave) => {
    const verified = enclave.checks.length > 0 && enclave.checks.every((c) => c.ok);
    state = { status: "done", enclave, verified };
    listeners.forEach((listener) => listener());
  });
}

/// The check as it stands, re-rendering when it finishes.
export function useEnclave(): EnclaveState {
  return useSyncExternalStore(subscribe, () => state);
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

async function check(sessionId: string): Promise<Enclave> {
  const [session, gateway] = await Promise.all([
    getAttestation(sessionId).catch(() => null),
    getGatewayAttestation().catch(() => null),
  ]);
  try {
    const { checkEnclave } = await import("@/lib/attestation");
    return await checkEnclave({
      session,
      gateway,
      sessionId,
      build: getBuild(window.location.pathname),
    });
  } catch {
    // The checks could not run at all — their code did not load. No check
    // made is no check passed, and the page says that it could not run them.
    return { checks: [], gateway: null, session: null };
  }
}
