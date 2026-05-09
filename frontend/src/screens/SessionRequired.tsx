// Reached when the URL has no `/session/{id}/` prefix. We don't
// run anything else — just explain that this page is opened via a
// link from the integrating partner.

export function SessionRequired() {
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center px-6 text-center">
      <div className="max-w-sm space-y-4">
        <div className="text-2xl font-semibold tracking-tight">Enclavid</div>
        <h1 className="text-xl font-semibold">Session ID required</h1>
        <p className="text-sm leading-relaxed text-muted-foreground">
          This page is opened via a link from your bank or exchange.
          Please use the link they provided to continue.
        </p>
      </div>
    </main>
  );
}
