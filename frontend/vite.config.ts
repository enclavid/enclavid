import path from "path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Where the api binary listens in dev (matches
// ENCLAVID_ADDRESS_IN_APPLICANT in `../.env`). Override via env if
// you bind the api somewhere else.
const API_TARGET = process.env.ENCLAVID_API_TARGET ?? "http://localhost:8002";

// A running gateway's origin (`https://verify.<name>`), to develop the page
// against a deployment instead of a local api: the page is opened at a link's
// own path, `/-<label>.<build>/<session id>`, and its calls go to the gateway
// under that marker, as they would from the link itself. Unset, the local api
// answers.
const GATEWAY = process.env.ENCLAVID_GATEWAY;

// Names besides localhost the dev server answers to — comma-separated — for
// reaching it from a phone through a tunnel, which is also what gives the
// camera the secure context it needs there.
const DEV_HOSTS = process.env.ENCLAVID_DEV_HOSTS?.split(",").filter(Boolean);

export default defineConfig({
  // Every reference the built page makes is relative to the document,
  // because the document is not always at the root of its origin. Behind
  // the gateway a link reads `/-<label>.<build>/<session id>`: the
  // gateway routes only a path that begins with that marker, strips it,
  // and refuses anything without it. An absolute `/assets/…` would drop
  // the marker and be refused; `./assets/…` resolves under it, beside the
  // session's segment. That holds only while the session is the one
  // segment after the marker — the link shape — or there is none and the
  // marker ends with a slash, which the gateway redirects a marker
  // without one to. Straight from api the document sits at `/`, or
  // `/<session id>`, beside the same files.
  base: "./",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  // Dev-server only: forward API paths to the running api binary. The
  // page is served at `/` here, so its relative `api/v1/sessions/<id>/…`
  // requests arrive as `/api/…` and are forwarded wholesale. A session's
  // link, `/<session id>`, is no file, and Vite answers it with
  // `index.html` as it does any page path. Production builds ignore this section
  // entirely — the api binary serves both the page and the JSON from one
  // origin (see `crates/api/src/applicant/mod.rs`).
  //
  // Against a gateway, the page sits under a link's marker instead, so its
  // calls arrive as `/-<label>.<build>/api/…` and go to the gateway as they
  // are; the gateway's own attestation is at its root. The host is the
  // gateway's, which is how it routes.
  server: {
    allowedHosts: DEV_HOSTS,
    proxy: GATEWAY
      ? {
          "^/-[^/]+/api/": { target: GATEWAY, changeOrigin: true },
          "/.well-known/enclavid-attestation": { target: GATEWAY, changeOrigin: true },
        }
      : {
          "/.well-known": API_TARGET,
          "/api": API_TARGET,
        },
  },
});
