#!/usr/bin/env node
// `npm create enclavid`: a policy project made of one of the templates this
// package carries. At a terminal it asks for what the command line leaves
// out; a script names both the directory and the template.
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import {
  cancel,
  intro,
  isCancel,
  note,
  outro,
  select,
  text,
  type CANCEL_SYMBOL,
} from "@clack/prompts";
import { create, refusal, templates, type Template } from "./create.js";

const TEMPLATES = join(dirname(fileURLToPath(import.meta.url)), "..", "templates");

/// Where the CLI the build runs `enclavid policy embed` with is installed from.
const CLI_INSTALL = "https://github.com/enclavid/enclavid/tree/main/crates/cli#install";

/// Where a project goes when the visitor names no other.
const FIRST_DIR = "my-policy";

function usage(available: Template[]): string {
  return `Usage: npm create enclavid@latest [directory] -- [--template <name>]

Templates: ${available.map((t) => t.name).join(", ")}`;
}

async function main() {
  const { values, positionals } = parseArgs({
    options: {
      template: { type: "string", short: "t" },
      help: { type: "boolean", short: "h" },
    },
    allowPositionals: true,
  });
  const available = templates(TEMPLATES);
  if (values.help) {
    console.log(usage(available));
    return;
  }
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    const [dir] = positionals;
    if (!dir || !values.template) {
      throw new Error(`name the directory and the template\n\n${usage(available)}`);
    }
    create(TEMPLATES, values.template, dir);
    const steps = nextSteps(dir).replace(/^/gm, "  ");
    console.log(`Made ${dir}. Next:\n\n${steps}\n\n${afterwards()}`);
    return;
  }

  intro("An enclavid policy");
  const dir =
    positionals[0] ??
    answered(
      await text({
        message: "Where should it go?",
        placeholder: FIRST_DIR,
        defaultValue: FIRST_DIR,
        validate: (value) => refusal(value || FIRST_DIR),
      }),
    );
  const template =
    values.template ??
    answered(
      await select({
        message: "Which template?",
        options: available.map((t) => ({ value: t.name, label: t.name, hint: t.description })),
      }),
    );
  create(TEMPLATES, template, dir);
  note(nextSteps(dir), "Next");
  outro(afterwards());
}

/// What a prompt was answered with; a cancel ends the command.
function answered<T>(value: T | typeof CANCEL_SYMBOL): T {
  if (isCancel(value)) {
    cancel("Nothing made.");
    process.exit(1);
  }
  return value;
}

/// What to run next, with the package manager this was run with.
function nextSteps(dir: string): string {
  const agent = process.env.npm_config_user_agent?.split("/")[0];
  const manager = agent && ["pnpm", "yarn", "bun"].includes(agent) ? agent : "npm";
  const cd = /\s/.test(dir) ? `"${dir}"` : dir;
  return [`cd ${cd}`, `${manager} install`, `${manager} run playground`].join("\n");
}

function afterwards(): string {
  return `\`run playground\` builds the policy and runs it on the playground, which asks for no account.
The build runs the enclavid CLI, which needs to be on the path: ${CLI_INSTALL}
AGENTS.md says how a policy works and how to change one; README.md, how to build and push it.`;
}

main().catch((e: unknown) => {
  console.error(`error: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
