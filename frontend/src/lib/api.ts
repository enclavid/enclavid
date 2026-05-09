// Fetch wrappers for the applicant API. All paths are relative —
// served from the same origin as the SPA bundle (TEE-hosted), so no
// CORS / no separate base URL.
//
// Errors collapse to a single `ApiError` carrying the HTTP status.
// Callers can disambiguate (404, 403, 500) when the UI distinction
// matters; otherwise generic "request failed" messaging is fine.

import { base64Encode } from "./key";
import type {
  AttestationManifest,
  SessionProgress,
  StatusResponse,
} from "@/types";

export class ApiError extends Error {
  // Parameter properties aren't allowed under `erasableSyntaxOnly` —
  // declare the field explicitly and assign in the body.
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

async function parseOrThrow<T>(res: Response): Promise<T> {
  if (!res.ok) {
    throw new ApiError(res.status, `HTTP ${res.status}`);
  }
  return (await res.json()) as T;
}

export async function getStatus(sessionId: string): Promise<StatusResponse> {
  const res = await fetch(`/session/${encodeURIComponent(sessionId)}/status`);
  return parseOrThrow(res);
}

export async function connect(
  sessionId: string,
  applicantKey: Uint8Array,
): Promise<SessionProgress> {
  const res = await fetch(`/session/${encodeURIComponent(sessionId)}/connect`, {
    method: "POST",
    headers: bearer(applicantKey),
  });
  return parseOrThrow(res);
}

export async function submitInput(
  sessionId: string,
  applicantKey: Uint8Array,
  body: ArrayBuffer | Uint8Array,
): Promise<SessionProgress> {
  const res = await fetch(`/session/${encodeURIComponent(sessionId)}/input`, {
    method: "POST",
    headers: {
      ...bearer(applicantKey),
      "Content-Type": "application/octet-stream",
    },
    body: body as BodyInit,
  });
  return parseOrThrow(res);
}

export async function resetState(sessionId: string): Promise<void> {
  const res = await fetch(`/session/${encodeURIComponent(sessionId)}/state`, {
    method: "DELETE",
  });
  if (!res.ok) {
    throw new ApiError(res.status, `HTTP ${res.status}`);
  }
}

export async function getAttestation(): Promise<AttestationManifest> {
  const res = await fetch("/.well-known/attestation");
  return parseOrThrow(res);
}

function bearer(key: Uint8Array): Record<string, string> {
  return { Authorization: `Bearer ${base64Encode(key)}` };
}
