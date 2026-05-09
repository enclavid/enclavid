// Attestation verification.
//
// Phase A: a simple equality check between the live `measurement`
// and the published `reference.expected_measurement`. Both come from
// the same backend mock today, so this always succeeds — but the
// shape is real. Phase B will add AMD-SP cert chain verification on
// top of this in JS (or via a wasm-compiled lib).
//
// `verifyAttestation` stays the public surface; the internals can
// change without breaking callers.

import { getAttestation } from "./api";
import type { AttestationManifest } from "@/types";

export type AttestationResult =
  | {
      ok: true;
      manifest: AttestationManifest;
    }
  | {
      ok: false;
      manifest: AttestationManifest | null;
      reason: AttestationFailure;
    };

export type AttestationFailure =
  | "fetch_failed"
  | "measurement_mismatch"
  | "format_unsupported";

export async function verifyAttestation(): Promise<AttestationResult> {
  let manifest: AttestationManifest;
  try {
    manifest = await getAttestation();
  } catch {
    return { ok: false, manifest: null, reason: "fetch_failed" };
  }

  if (manifest.measurement !== manifest.reference.expected_measurement) {
    return { ok: false, manifest, reason: "measurement_mismatch" };
  }

  // Phase B: also verify quote signature against AMD-SP root cert,
  // check format == "amd-sev-snp", check VCEK chain. For now, mock
  // is acceptable.

  return { ok: true, manifest };
}

/// Short-form commit SHA for display ("commit a1b2c3d4...").
export function shortCommit(sha: string): string {
  return sha.length > 8 ? sha.slice(0, 8) : sha;
}
