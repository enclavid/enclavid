// Run before the package is packed: copies the repository's TypeScript
// templates into the package's `templates/`, as committed, with the AGENTS.md
// they share — so a release carries the templates of its own commit, which
// name the versions released with it, and nothing else that lies beside
// them. A templates tree with changes git does not hold is refused.
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { AGENTS, PACKED_GITIGNORE } from "./create.js";

/// What the playground alone shows: a project made of a template has the
/// template's README.
const PLAYGROUND_README = "README_PLAYGROUND.md";

/// Copy the templates of the repository at `repository` into `into`, in
/// place of what is there.
export function pack(repository: string, into: string) {
  const source = join(repository, "templates", "typescript");
  const changed = git(source, ["status", "--porcelain", "-z", "--", "."]);
  if (changed.length > 0) {
    throw new Error(
      `${source} has changes git does not hold — ${changed.slice(0, 3).join(", ")}: commit them, then pack`,
    );
  }
  rmSync(into, { recursive: true, force: true });
  for (const path of git(source, ["ls-files", "-z", "--", "."])) {
    const [template, ...inside] = path.split("/");
    // A file of the templates' own, beside them: AGENTS.md, copied below.
    if (inside.length === 0) continue;
    if (inside.at(-1) === PLAYGROUND_README) continue;
    // npm leaves `.gitignore` out of a package, so it travels renamed.
    const name = inside.at(-1) === ".gitignore" ? PACKED_GITIGNORE : inside.at(-1)!;
    const to = join(into, template, ...inside.slice(0, -1), name);
    mkdirSync(dirname(to), { recursive: true });
    copyFileSync(join(source, path), to);
  }
  copyFileSync(join(source, AGENTS), join(into, AGENTS));
}

/// What `git <args>` prints in `dir`, as the NUL-separated entries it lists.
function git(dir: string, args: string[]): string[] {
  return execFileSync("git", args, { cwd: dir, encoding: "utf8" })
    .split("\0")
    .filter(Boolean);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const repository = execFileSync("git", ["rev-parse", "--show-toplevel"], {
    cwd: root,
    encoding: "utf8",
  }).trim();
  pack(repository, join(root, "templates"));
}
