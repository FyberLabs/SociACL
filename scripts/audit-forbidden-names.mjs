// Close-out audit. Whole-token match, the same boundary rg uses.
// Fails when a forbidden name appears in its scope, or when
// typescript/src contains node:crypto or the bare "crypto" specifier.
// *.js also covers .mjs and .cjs. *.ts also covers .mts and .cts.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const doc = JSON.parse(readFileSync(join(root, "vectors/mesh/forbidden-names.json"), "utf8"));

function globMatch(glob, path) {
  const rec = (pattern, value) => {
    if (pattern.length === 0) return value.length === 0;
    if (pattern.startsWith("**")) {
      const rest = pattern[2] === "/" ? pattern.slice(3) : pattern.slice(2);
      if (rec(rest, value)) return true;
      for (let index = 0; index < value.length; index += 1) {
        if (rec(pattern, value.slice(index + 1))) return true;
      }
      return false;
    }
    if (pattern[0] === "*") {
      for (let index = 0; index <= value.length; index += 1) {
        if (index > 0 && value[index - 1] === "/") return false;
        if (rec(pattern.slice(1), value.slice(index))) return true;
        if (index === value.length) return false;
      }
      return false;
    }
    if (value.length === 0 || pattern[0] !== value[0]) return false;
    return rec(pattern.slice(1), value.slice(1));
  };
  return rec(glob, path);
}

function filesForGlob(glob) {
  if (!glob.includes("*")) {
    const path = join(root, glob);
    if (!statSync(path).isFile()) throw new Error(`missing ${glob}`);
    return [path];
  }
  const files = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      if (name === "node_modules" || name === "target") continue;
      const path = join(dir, name);
      const info = statSync(path);
      if (info.isDirectory()) walk(path);
      else if (sourceFile(name)) {
        const relative = path.slice(root.length).replaceAll("\\", "/").replace(/^\//, "");
        if (globMatchSource(glob, relative)) files.push(path);
      }
    }
  };
  walk(root);
  return files;
}

const SOURCE_EXT = [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".rs"];

function sourceFile(name) {
  return SOURCE_EXT.some((ext) => name.endsWith(ext));
}

function globMatchSource(glob, path) {
  if (globMatch(glob, path)) return true;
  const pairs = [
    [".js", ".mjs"],
    [".js", ".cjs"],
    [".ts", ".mts"],
    [".ts", ".cts"],
  ];
  for (const [from, to] of pairs) {
    if (!glob.endsWith(`*${from}`) || !path.endsWith(to)) continue;
    if (globMatch(glob, path.slice(0, -to.length) + from)) return true;
  }
  return false;
}

function present(text, name) {
  const needle = new RegExp(`(^|[^A-Za-z0-9_])${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^A-Za-z0-9_]|$)`);
  return needle.test(text);
}

let failed = false;
for (const glob of doc.scopes) {
  const files = filesForGlob(glob);
  if (files.length === 0) {
    console.error(`scope has no files: ${glob}`);
    failed = true;
    continue;
  }
  for (const name of doc.identifiers) {
    for (const path of files) {
      if (present(readFileSync(path, "utf8"), name)) {
        console.error(`${name} in ${path}`);
        failed = true;
      }
    }
  }
}

const cryptoNames = ["node:crypto", "crypto"];
for (const glob of ["typescript/src/**/*.js", "typescript/src/**/*.ts"]) {
  for (const path of filesForGlob(glob)) {
    const text = readFileSync(path, "utf8");
    for (const name of cryptoNames) {
      if (present(text, name)) {
        console.error(`${name} in ${path}`);
        failed = true;
      }
    }
  }
}

if (failed) process.exit(1);
console.log("forbidden-names and node:crypto audit ok");
