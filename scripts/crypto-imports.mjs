// Build/test tooling only. Use the pinned TypeScript parser so comments, regex
// literals, escaped identifiers, division, and nested templates share JS syntax.
import ts from '../typescript/node_modules/typescript/lib/typescript.js';

const CRYPTO_SPECIFIERS = new Set(['crypto', 'node:crypto']);
const unwrap = (node) => {
  while (node && (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) ||
    ts.isTypeAssertionExpression(node) || ts.isNonNullExpression(node) || ts.isSatisfiesExpression(node))) {
    node = node.expression;
  }
  return node;
};
const literal = (node) => {
  node = unwrap(node);
  return node && ts.isStringLiteralLike(node) ? node.text : undefined;
};
const name = (node) => {
  node = unwrap(node);
  if (!node) return undefined;
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (ts.isElementAccessExpression(node)) return literal(node.argumentExpression);
  return undefined;
};

/** Detect literal Node crypto loads; this is a dependency audit, not dataflow analysis.
 * Invalid source fails the audit instead of letting parser recovery skip imports. */
export function importsNodeCrypto(source, path = 'source.ts') {
  const kind = /\.[cm]?js$/i.test(path) ? ts.ScriptKind.JS : ts.ScriptKind.TS;
  const file = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, false, kind);
  if (file.parseDiagnostics.length) {
    const diagnostic = file.parseDiagnostics[0];
    throw new SyntaxError(`${path}: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n')}`);
  }
  const pending = [file];
  while (pending.length) {
    const node = pending.pop();
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      CRYPTO_SPECIFIERS.has(literal(node.moduleSpecifier))) return true;
    if (ts.isExternalModuleReference(node) && CRYPTO_SPECIFIERS.has(literal(node.expression))) return true;
    if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument) &&
      CRYPTO_SPECIFIERS.has(literal(node.argument.literal))) return true;
    if (ts.isCallExpression(node)) {
      const callee = unwrap(node.expression);
      const load = callee.kind === ts.SyntaxKind.ImportKeyword ||
        ['require', 'getBuiltinModule'].includes(name(callee)) ||
        (ts.isCallExpression(callee) && name(callee.expression) === 'createRequire');
      if (load && CRYPTO_SPECIFIERS.has(literal(node.arguments[0]))) return true;
    }
    ts.forEachChild(node, child => { pending.push(child); });
  }
  return false;
}
