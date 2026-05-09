// Stub for the next iteration. After Ritual finishes, App calls
// /connect with the freshly-minted applicant_key and lands here with
// a SessionProgress payload. Real rendering of Passport / Liveness /
// Consent / VerificationSet / Completed comes next.

import type { SessionProgress } from "@/types";

type Props = {
  progress: SessionProgress | null;
  error: string | null;
};

export function Verify({ progress, error }: Props) {
  return (
    <main
      className="flex min-h-dvh flex-col gap-4 px-6 py-6"
      style={{
        paddingTop: "max(env(safe-area-inset-top), 1rem)",
        paddingBottom: "max(env(safe-area-inset-bottom), 1.5rem)",
      }}
    >
      <h1 className="text-xl font-semibold">Verification</h1>
      {error && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {error}
        </div>
      )}
      <p className="text-sm text-muted-foreground">
        UI for the next step is under construction. Latest server response:
      </p>
      <pre className="overflow-auto rounded-lg border border-border bg-muted p-3 text-xs">
        {progress ? JSON.stringify(progress, null, 2) : "(awaiting response)"}
      </pre>
    </main>
  );
}
