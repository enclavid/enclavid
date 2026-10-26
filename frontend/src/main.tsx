import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { takeHandedKey } from "@/lib/handoff";
import { getSessionId } from "@/lib/session";
import "./index.css";

// A key handed over from another device is taken before anything reads the
// address — the router included — and leaves it at once.
const sessionId = getSessionId(window.location.pathname);
if (sessionId) takeHandedKey(sessionId);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
