// A project made of one of the templates this package carries.
import {
  copyFileSync,
  cpSync,
  existsSync,
  readdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

/// What an agent changing a policy goes by: one file beside the templates,
/// which every project gets.
export const AGENTS = "AGENTS.md";

/// A template's `.gitignore`, as the package carries it.
export const PACKED_GITIGNORE = "_gitignore";

/// A template: its name, and what its package says it is, if it says.
export type Template = { name: string; description?: string };

/// The templates in `templates`, by name.
export function templates(templates: string): Template[] {
  return readdirSync(templates, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
    .map((name) => {
      const pkg = JSON.parse(readFileSync(join(templates, name, "package.json"), "utf8"));
      return typeof pkg.description === "string"
        ? { name, description: pkg.description }
        : { name };
    });
}

/// The name of the package a project at `dir` is: the directory's own name,
/// as npm takes one — none for a name with no letter or digit.
export function packageName(dir: string): string | undefined {
  const name = basename(resolve(dir))
    .toLowerCase()
    .replace(/[^a-z0-9._~-]+/g, "-")
    .replace(/^[._-]+/, "");
  return name || undefined;
}

/// Why a project cannot be made at `dir`, or nothing when it can: a
/// directory with anything in it is left as it is.
export function refusal(dir: string): string | undefined {
  if (!packageName(dir)) return `${dir} makes no package name: name it with a letter or a digit`;
  if (existsSync(dir) && readdirSync(dir).length > 0) return `${dir} is not empty`;
  return undefined;
}

/// Make a project at `dir` of the template `template` in `from`: its files,
/// with the AGENTS.md beside them, its package named for the project.
export function create(from: string, template: string, dir: string) {
  if (!templates(from).some((t) => t.name === template)) {
    throw new Error(`there is no template ${template}`);
  }
  const refused = refusal(dir);
  if (refused) throw new Error(refused);
  cpSync(join(from, template), dir, { recursive: true });
  for (const path of readdirSync(dir, { recursive: true, encoding: "utf8" })) {
    if (basename(path) === PACKED_GITIGNORE) {
      renameSync(join(dir, path), join(dir, dirname(path), ".gitignore"));
    }
  }
  copyFileSync(join(from, AGENTS), join(dir, AGENTS));
  const manifest = join(dir, "package.json");
  const pkg = JSON.parse(readFileSync(manifest, "utf8"));
  pkg.name = packageName(dir);
  writeFileSync(manifest, JSON.stringify(pkg, null, 2) + "\n");
}
