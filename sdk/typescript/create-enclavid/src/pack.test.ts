import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { AGENTS, PACKED_GITIGNORE, templates } from "./create.js";
import { pack } from "./pack.js";

/// A repository holding `files`, committed.
function repository(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "repository-"));
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  git(root, "init", "-q");
  git(root, "add", "-A");
  git(root, "commit", "-q", "-m", "templates");
  return root;
}

function git(cwd: string, ...args: string[]) {
  execFileSync(
    "git",
    [
      "-c",
      "user.name=t",
      "-c",
      "user.email=t@t",
      "-c",
      "commit.gpgsign=false",
      "-c",
      "core.hooksPath=/dev/null",
      ...args,
    ],
    { cwd },
  );
}

const TEMPLATES = {
  "templates/typescript/AGENTS.md": "# Agents\n",
  "templates/typescript/kyc/package.json": '{ "name": "my-policy", "description": "A KYC walk." }\n',
  "templates/typescript/kyc/.gitignore": "node_modules\n",
  "templates/typescript/kyc/README_PLAYGROUND.md": "# KYC\n",
  "templates/typescript/kyc/src/policy.ts": "// kyc\n",
};

test("the package carries the templates as committed", () => {
  const into = join(mkdtempSync(join(tmpdir(), "packed-")), "templates");
  pack(repository(TEMPLATES), into);
  assert.deepEqual(templates(into), [{ name: "kyc", description: "A KYC walk." }]);
  assert.equal(readFileSync(join(into, AGENTS), "utf8"), "# Agents\n");
  assert.deepEqual(readdirSync(join(into, "kyc")).sort(), [PACKED_GITIGNORE, "package.json", "src"]);
  assert.equal(readFileSync(join(into, "kyc", "src", "policy.ts"), "utf8"), "// kyc\n");
});

test("a templates tree with changes git does not hold is not packed", () => {
  const into = join(mkdtempSync(join(tmpdir(), "packed-")), "templates");
  const untracked = repository(TEMPLATES);
  writeFileSync(join(untracked, "templates/typescript/kyc/.env"), "SECRET=1\n");
  assert.throws(() => pack(untracked, into), /commit them/);
  const modified = repository(TEMPLATES);
  writeFileSync(join(modified, "templates/typescript/kyc/src/policy.ts"), "// changed\n");
  assert.throws(() => pack(modified, into), /commit them/);
  assert.ok(!existsSync(into));
});

test("each of the repository's templates is one to pack", () => {
  const source = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..", "templates", "typescript");
  const names = readdirSync(source, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && !entry.name.startsWith("."))
    .map((entry) => entry.name);
  assert.ok(names.length > 0);
  assert.ok(existsSync(join(source, AGENTS)));
  for (const name of names) {
    const pkg = JSON.parse(readFileSync(join(source, name, "package.json"), "utf8"));
    // Each says what it is, for the list a project is chosen from.
    assert.ok(pkg.description, name);
    assert.ok(existsSync(join(source, name, ".gitignore")), name);
  }
});
