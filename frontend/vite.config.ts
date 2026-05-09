import path from "path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Where the api binary listens in dev (matches
// ENCLAVID_ADDRESS_IN_APPLICANT in `../.env`). Override via env if
// you bind the api somewhere else.
const API_TARGET = process.env.ENCLAVID_API_TARGET ?? "http://localhost:8002";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  // Dev-server only: forward API paths to the running api binary.
  // Regex anchored with `^...$` so SPA-shell requests like
  // `/session/<id>/` (no endpoint suffix) fall through to Vite and
  // get served as index.html. Production builds ignore this section
  // entirely — the api binary serves both static + JSON from one
  // origin (see `crates/api/src/applicant/mod.rs`).
  server: {
    proxy: {
      "/.well-known": API_TARGET,
      "^/session/[^/]+/(status|state|connect|input|report)$": API_TARGET,
    },
  },
});
