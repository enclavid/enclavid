#!/usr/bin/env node
// Runs the enclavid binary built for this platform, which npm installs as the
// one optional dependency of @enclavid/cli that fits it.
"use strict";

const { spawnSync } = require("node:child_process");

const platform = `${process.platform}-${process.arch}`;
let binary;
try {
  binary = require.resolve(`@enclavid/cli-${platform}/enclavid`);
} catch {
  console.error(
    `enclavid: @enclavid/cli has no build for ${platform}, or it was not installed. ` +
      "Build the CLI from source instead: " +
      "cargo install --git https://github.com/enclavid/enclavid enclavid-cli",
  );
  process.exit(1);
}

const run = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });
if (run.error) throw run.error;
if (run.signal) process.kill(process.pid, run.signal);
process.exit(run.status ?? 1);
