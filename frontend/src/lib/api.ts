// Fetch wrappers for the applicant API. All paths are relative to the
// document — no leading slash — so they resolve under whatever path
// the page itself was served at, on the same origin as the SPA bundle
// (TEE-hosted): no CORS, no separate base URL. Behind the gateway the
// page sits under its routing marker, and a relative path keeps every
// request under it too; see `vite.config.ts`.
//
// Errors collapse to a single `ApiError` carrying the HTTP status.
// Callers can disambiguate (404, 403, 500) when the UI distinction
// matters; otherwise generic "request failed" messaging is fine.

import { base64Encode } from "./key";
import type {
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

// All applicant endpoints live under `api/v1/sessions/<id>/...`,
// matching the client-side surface. The page's own routes are not
// paths at all: they live in the fragment (`#/session/<id>/...`),
// which never reaches the server, so it is these API requests, not the
// page's address, that name the session to it.
function endpoint(sessionId: string, suffix: string): string {
  return `api/v1/sessions/${encodeURIComponent(sessionId)}${suffix}`;
}

export async function getStatus(sessionId: string): Promise<StatusResponse> {
  const res = await fetch(endpoint(sessionId, "/status"));
  return parseOrThrow(res);
}

export async function connect(
  sessionId: string,
  applicantKey: Uint8Array,
): Promise<SessionProgress> {
  const res = await fetch(endpoint(sessionId, "/connect"), {
    method: "POST",
    headers: bearer(applicantKey),
  });
  return parseOrThrow(res);
}

export async function submitInput(
  sessionId: string,
  slotId: string,
  applicantKey: Uint8Array,
  body: FormData,
): Promise<SessionProgress> {
  // Don't set Content-Type — fetch derives `multipart/form-data;
  // boundary=…` from the FormData itself. Setting it manually
  // breaks the boundary detection.
  const res = await fetch(
    endpoint(sessionId, `/input/${encodeURIComponent(slotId)}`),
    {
      method: "POST",
      headers: bearer(applicantKey),
      body,
    },
  );
  return parseOrThrow(res);
}

export async function resetState(sessionId: string): Promise<void> {
  const res = await fetch(endpoint(sessionId, "/state"), {
    method: "DELETE",
  });
  if (!res.ok) {
    throw new ApiError(res.status, `HTTP ${res.status}`);
  }
}

function bearer(key: Uint8Array): Record<string, string> {
  return { Authorization: `Bearer ${base64Encode(key)}` };
}
