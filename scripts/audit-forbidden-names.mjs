// Close-out audit. Whole-token match, the same boundary rg uses.
// Fails when a forbidden name appears in its scope, or when
// typescript/src imports "crypto" or "node:crypto". WebCrypto stays allowed.
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

const CRYPTO_SPECIFIERS = new Set(["crypto", "node:crypto"]);

function isIdent(c) {
  return c !== undefined && /[A-Za-z0-9_$]/.test(c);
}

/** Import, export-from, require, import(), createRequire, and getBuiltinModule.
 * Strings and comments are not code. Template specifiers count. The same
 * scanner is copied in typescript/tests/test_see.js and see_vectors.rs.
 * @param {string} source */
function importsNodeCrypto(source) {
  const n = source.length;
  let i = 0;
  let nestedCrypto = false;
  /** @type {'import'|'export'|null} */ let stmt = null;
  const skipSpace = (at) => {
    while (at < n) {
      if (/\s/.test(source[at])) { at += 1; continue; }
      if (source.startsWith("//", at)) {
        at += 2;
        while (at < n && !/[\n\r\u2028\u2029]/.test(source[at])) at += 1;
        continue;
      }
      if (source.startsWith("/*", at)) {
        const end = source.indexOf("*/", at + 2);
        at = end < 0 ? n : end + 2;
        continue;
      }
      break;
    }
    return at;
  };
  const wordAt = (at, word) => source.startsWith(word, at) && !isIdent(source[at - 1]) && !isIdent(source[at + word.length]);
  const readString = (at, scanExpressions = true) => {
    const quote = source[at];
    let j = at + 1;
    let value = "";
    let interpolated = false;
    while (j < n) {
      const c = source[j];
      if (c === "\\") {
        value += source[j + 1] ?? "";
        j += 2;
        continue;
      }
      if (quote === "`" && c === "$" && source[j + 1] === "{") {
        interpolated = true;
        const end = skipBalanced(j + 1, "{", "}");
        const contentEnd = source[end - 1] === "}" ? end - 1 : end;
        if (scanExpressions && importsNodeCrypto(source.slice(j + 2, contentEnd))) nestedCrypto = true;
        j = end;
        continue;
      }
      if (c === quote) return { value: interpolated ? null : value, end: j + 1 };
      value += c;
      j += 1;
    }
    return { value: interpolated ? null : value, end: n };
  };
  const skipBalanced = (at, open = "(", close = ")") => {
    let depth = 0;
    let j = at;
    while (j < n) {
      const c = source[j];
      if (c === "/" && source[j + 1] === "/") {
        j += 2;
        while (j < n && source[j] !== "\n") j += 1;
        continue;
      }
      if (c === "/" && source[j + 1] === "*") {
        j += 2;
        while (j < n && !(source[j] === "*" && source[j + 1] === "/")) j += 1;
        j = Math.min(n, j + 2);
        continue;
      }
      if (c === "'" || c === '"' || c === "`") {
        // Balance nested strings without scanning their expressions twice.
        j = readString(j, false).end;
        continue;
      }
      if (c === open) depth += 1;
      else if (c === close) {
        depth -= 1;
        if (depth === 0) return j + 1;
      }
      j += 1;
    }
    return n;
  };
  const specifierAt = (at) => {
    if (source[at] !== "'" && source[at] !== '"' && source[at] !== "`") return false;
    const read = readString(at);
    return read.value !== null && CRYPTO_SPECIFIERS.has(read.value);
  };
  while (i < n) {
    const c = source[i];
    if (c === "/" && source[i + 1] === "/") {
      i += 2;
      while (i < n && source[i] !== "\n") i += 1;
      continue;
    }
    if (c === "/" && source[i + 1] === "*") {
      i += 2;
      while (i < n && !(source[i] === "*" && source[i + 1] === "/")) i += 1;
      i = Math.min(n, i + 2);
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      i = readString(i).end;
      continue;
    }
    if (c === ";") {
      stmt = null;
      i += 1;
      continue;
    }
    if ((stmt === "import" || stmt === "export") && wordAt(i, "from")) {
      if (specifierAt(skipSpace(i + 4))) return true;
      i += 4;
      continue;
    }
    if (wordAt(i, "import")) {
      const j = skipSpace(i + 6);
      if (source[j] === "(") {
        if (specifierAt(skipSpace(j + 1))) return true;
        i = j + 1;
        continue;
      }
      if (specifierAt(j)) return true;
      stmt = "import";
      i += 6;
      continue;
    }
    if (wordAt(i, "export")) {
      stmt = "export";
      i += 6;
      continue;
    }
    if (wordAt(i, "createRequire")) {
      let j = skipSpace(i + 13);
      if (source[j] === "(") {
        j = skipSpace(skipBalanced(j));
        if (source[j] === "(" && specifierAt(skipSpace(j + 1))) return true;
      }
      i += 13;
      continue;
    }
    if (wordAt(i, "getBuiltinModule") || wordAt(i, "require")) {
      const word = wordAt(i, "getBuiltinModule") ? "getBuiltinModule" : "require";
      const j = skipSpace(i + word.length);
      if (source[j] === "(" && specifierAt(skipSpace(j + 1))) return true;
      i += word.length;
      continue;
    }
    i += 1;
  }
  return nestedCrypto;
}

const cryptoVectors = JSON.parse(readFileSync(join(root, "vectors/mesh/crypto-import.json"), "utf8"));
for (const row of cryptoVectors.allowed) {
  if (importsNodeCrypto(row.source)) {
    console.error(`allowed crypto snippet flagged: ${row.name}`);
    failed = true;
  }
}
for (const row of cryptoVectors.banned) {
  if (!importsNodeCrypto(row.source)) {
    console.error(`banned crypto snippet missed: ${row.name}`);
    failed = true;
  }
}
for (const glob of ["typescript/src/**/*.js", "typescript/src/**/*.ts"]) {
  for (const path of filesForGlob(glob)) {
    if (importsNodeCrypto(readFileSync(path, "utf8"))) {
      console.error(`crypto import in ${path}`);
      failed = true;
    }
  }
}

if (failed) process.exit(1);
console.log("forbidden-names and node:crypto audit ok");
