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
  // Applicant JSON endpoints live under `/api/v1/sessions/<id>/...` —
  // forward the whole prefix wholesale. The user-facing SPA shell URL
  // is `/session/<id>/...` (no `/api/v1/` prefix); those requests
  // fall through to Vite and get served as `index.html`. Production
  // builds ignore this section entirely — the api binary serves both
  // static + JSON from one origin (see `crates/api/src/applicant/mod.rs`).
  server: {
    proxy: {
      "/.well-known": API_TARGET,
      "/api": API_TARGET,
    },
  },
});
