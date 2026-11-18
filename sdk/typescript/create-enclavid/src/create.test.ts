import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  AGENTS,
  create,
  packageName,
  PACKED_GITIGNORE,
  refusal,
  templates,
} from "./create.js";

/// Templates laid out as the package carries them: `kyc`, which says what
/// it is, and `liveness`, beside the AGENTS.md they share.
function packed(): string {
  const root = mkdtempSync(join(tmpdir(), "create-enclavid-"));
  for (const name of ["liveness", "kyc"]) {
    mkdirSync(join(root, name, "src"), { recursive: true });
    const pkg = name === "kyc" ? { name: "my-policy", description: "A KYC walk." } : { name: "my-policy" };
    writeFileSync(join(root, name, "package.json"), JSON.stringify(pkg) + "\n");
    writeFileSync(join(root, name, PACKED_GITIGNORE), "node_modules\n");
    writeFileSync(join(root, name, "src", "policy.ts"), `// ${name}\n`);
  }
  writeFileSync(join(root, AGENTS), "# Agents\n");
  return root;
}

test("the templates are the directories beside AGENTS.md, as their packages say", () => {
  assert.deepEqual(templates(packed()), [
    { name: "kyc", description: "A KYC walk." },
    { name: "liveness" },
  ]);
});

test("a project is the template, its .gitignore, AGENTS.md, and its own name", () => {
  const dir = join(mkdtempSync(join(tmpdir(), "project-")), "Age Check");
  create(packed(), "kyc", dir);
  assert.deepEqual(readdirSync(dir).sort(), [".gitignore", AGENTS, "package.json", "src"]);
  assert.equal(readFileSync(join(dir, "src", "policy.ts"), "utf8"), "// kyc\n");
  assert.equal(readFileSync(join(dir, AGENTS), "utf8"), "# Agents\n");
  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  assert.deepEqual(pkg, { name: "age-check", description: "A KYC walk." });
});

test("an empty directory is made into a project; one with anything in it is refused", () => {
  const from = packed();
  const empty = mkdtempSync(join(tmpdir(), "project-"));
  assert.equal(refusal(empty), undefined);
  create(from, "liveness", empty);
  assert.match(refusal(empty)!, /is not empty/);
  assert.throws(() => create(from, "kyc", empty), /is not empty/);
});

test("a template the package has not is refused", () => {
  const dir = join(mkdtempSync(join(tmpdir(), "project-")), "p");
  assert.throws(() => create(packed(), "passport", dir), /no template passport/);
  // A path is no template, even one to a directory with a package.
  assert.throws(() => create(packed(), "..", dir), /no template \.\./);
  assert.throws(() => create(packed(), "kyc/../liveness", dir), /no template/);
});

test("a package name is the directory's, as npm takes one", () => {
  assert.equal(packageName("policies/My Policy"), "my-policy");
  assert.equal(packageName("_age.check"), "age.check");
  assert.equal(packageName("___"), undefined);
  assert.match(refusal("___")!, /makes no package name/);
});
