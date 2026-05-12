import type { Translations } from "@/types";

/// Pick one rendered string out of the full translation list the
/// host returns for each `text-ref`. Falls back through:
///   1. Exact match of the user's `navigator.language` (e.g. `en-GB`).
///   2. Primary tag match (`en-GB` → any `en-*` or `en`).
///   3. `en` if present.
///   4. First entry in the list (deterministic).
///   5. Empty string — only when the list is empty, which shouldn't
///      reach this layer for a well-formed policy (engine traps on
///      unresolved refs).
export function pickLocalized(
  text: Translations,
  locale = navigator.language,
): string {
  if (text.length === 0) return "";
  const lower = locale.toLowerCase();
  const primary = lower.split("-", 1)[0];
  // Exact, then prefix match on primary tag, then "en", then first.
  return (
    text.find((t) => t.language.toLowerCase() === lower)?.text ??
    text.find((t) => t.language.toLowerCase().startsWith(primary))?.text ??
    text.find((t) => t.language.toLowerCase() === "en")?.text ??
    text[0].text
  );
}
