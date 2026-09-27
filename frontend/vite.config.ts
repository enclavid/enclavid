import path from "path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Where the api binary listens in dev (matches
// ENCLAVID_ADDRESS_IN_APPLICANT in `../.env`). Override via env if
// you bind the api somewhere else.
const API_TARGET = process.env.ENCLAVID_API_TARGET ?? "http://localhost:8002";

export default defineConfig({
  // Every reference the built page makes is relative to the document,
  // because the document is not always at the root of its origin. Behind
  // the gateway a link reads `/-<label>.<build>/#/session/<id>`: the
  // gateway routes only a path that begins with that marker, strips it,
  // and refuses anything without it. An absolute `/assets/…` would drop
  // the marker and be refused; `./assets/…` resolves under it. That holds
  // only while the address ends the marker with a slash, which the link
  // shape does — and a marker without one the gateway redirects to the
  // same with a slash. Straight from api the document sits at `/`, where
  // the two spellings mean the same thing.
  base: "./",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  // Dev-server only: forward API paths to the running api binary. The
  // page is served at `/` here, so its relative `api/v1/sessions/<id>/…`
  // requests arrive as `/api/…` and are forwarded wholesale. The page's
  // own routes live in the URL fragment (`/#/session/<id>/…`), which a
  // browser never sends, so every navigation reaches Vite as `/` and is
  // answered with `index.html`. Production builds ignore this section
  // entirely — the api binary serves both the page and the JSON from one
  // origin (see `crates/api/src/applicant/mod.rs`).
  server: {
    proxy: {
      "/.well-known": API_TARGET,
      "/api": API_TARGET,
    },
  },
});
