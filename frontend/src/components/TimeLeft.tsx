import { useEffect, useRef, useState } from "react";

/// The time a prompt with a limit has left, counted down on screen from
/// `remainingMs` — what the server said was left when it answered, so the
/// device's own clock setting does not matter. `onExpired` is called once,
/// when it runs out.
export function TimeLeft({
  remainingMs,
  onExpired,
}: {
  remainingMs: number;
  onExpired: () => void;
}) {
  const [deadline] = useState(() => Date.now() + remainingMs);
  const [now, setNow] = useState(() => Date.now());
  const fired = useRef(false);
  const left = Math.max(0, deadline - now);

  useEffect(() => {
    const tick = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(tick);
  }, []);
  useEffect(() => {
    if (left === 0 && !fired.current) {
      fired.current = true;
      onExpired();
    }
  }, [left, onExpired]);

  const secs = Math.ceil(left / 1000);
  return (
    <div className="pointer-events-none fixed inset-x-0 top-3 z-50 flex justify-center">
      <div
        role="timer"
        className="rounded-full bg-black/70 px-3 py-1 text-sm tabular-nums text-white"
      >
        {Math.floor(secs / 60)}:{String(secs % 60).padStart(2, "0")}
      </div>
    </div>
  );
}
