import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { takeHandoff } from "@/lib/handoff";
import { getSessionId } from "@/lib/session";
import "./index.css";

// A hand-over from another device is taken out of the address before anything
// reads it — the router included — and leaves it at once.
const handoff = getSessionId(window.location.pathname) ? takeHandoff() : null;

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App handoff={handoff} />
  </StrictMode>,
);
