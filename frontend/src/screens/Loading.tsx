import { Spinner } from "@/components/icons";

/// Minimal in-flight screen shown while App is fetching `/status` —
/// the dispatch point that decides which "real" screen to render. A
/// fast Redis lookup on the host means this is usually visible for a
/// few hundred ms; we keep the visual quiet so it doesn't look like
/// a loading state when nothing's actually broken.
export function Loading() {
  return (
    <main className="flex min-h-dvh items-center justify-center">
      <Spinner className="size-6 text-muted-foreground" />
    </main>
  );
}
