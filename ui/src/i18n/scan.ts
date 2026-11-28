/**
 * Reading a source file for the text it shows, for the catalog tests.
 *
 * Two lists come out of a file. `keys` is every string passed to `t` or `tn`,
 * which the catalog of each language has to carry. `literals` is text that
 * reaches the screen without going through either: JSX text, a string in an
 * attribute a person reads (`title`, `placeholder`, `aria-label`, `label`
 * and the like), or a string literal in a JSX expression. On a screen that is
 * meant to be translated, each of those is a string somebody forgot.
 *
 * It walks the real syntax tree (the parser Vite already ships), not a
 * regular expression, so `a > b && c < d` in code is never mistaken for text.
 */
import { parseAst } from "rolldown/parseAst";

/** Attributes whose value a person reads or hears. */
export const TEXT_ATTRIBUTES = new Set([
  "title",
  "placeholder",
  "aria-label",
  "aria-description",
  "alt",
  "label",
  "description",
  "hint",
  "confirmLabel",
  "cancelLabel",
  "message",
  "heading",
  "subtitle",
  "emptyText",
  "tooltip",
]);

export interface Found {
  text: string;
  line: number;
}

export interface Scan {
  keys: Found[];
  literals: Found[];
}

type Node = { type: string; start: number; [key: string]: unknown };

function isNode(value: unknown): value is Node {
  return typeof value === "object" && value !== null && typeof (value as Node).type === "string";
}

/** The text of a string literal or a template with nothing interpolated. */
function staticString(node: unknown): string | null {
  if (!isNode(node)) return null;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  if (node.type === "TemplateLiteral") {
    const quasis = node.quasis as { value: { cooked: string } }[];
    const expressions = node.expressions as unknown[];
    if (expressions.length === 0) return quasis.map((q) => q.value.cooked).join("");
  }
  return null;
}

/** Whether a piece of text has a word in it, as opposed to `·`, `/` or `3`. */
export function hasWords(text: string): boolean {
  return /[A-Za-z]{2,}/.test(text);
}

export function scanSource(source: string, filename: string): Scan {
  const program = parseAst(source, { lang: filename.endsWith(".tsx") ? "tsx" : "ts" }, filename);
  const lineStarts = [0];
  for (let i = 0; i < source.length; i++) if (source[i] === "\n") lineStarts.push(i + 1);
  const lineOf = (offset: number): number => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };

  const keys: Found[] = [];
  const literals: Found[] = [];

  // Strings that are shown as they are: the branches of `a ? "x" : "y"` and
  // `a || "x"` lead to the screen as surely as a plain literal does.
  const shown = (node: unknown): void => {
    if (!isNode(node)) return;
    const text = staticString(node);
    if (text !== null) {
      if (hasWords(text)) literals.push({ text, line: lineOf(node.start) });
      return;
    }
    if (node.type === "ConditionalExpression") {
      shown(node.consequent);
      shown(node.alternate);
    } else if (node.type === "LogicalExpression") {
      shown(node.right);
      if (node.operator !== "&&") shown(node.left);
    }
  };

  const visit = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const child of node) visit(child);
      return;
    }
    if (!isNode(node)) return;

    if (node.type === "CallExpression" && isNode(node.callee) && node.callee.type === "Identifier") {
      const name = node.callee.name as string;
      const args = node.arguments as unknown[];
      if (name === "t") {
        const key = staticString(args[0]);
        if (key !== null) keys.push({ text: key, line: lineOf(node.start) });
      } else if (name === "tn") {
        const key = staticString(args[2]);
        if (key !== null) keys.push({ text: key, line: lineOf(node.start) });
      }
    }

    if (node.type === "JSXText") {
      const text = (node.value as string).replace(/\s+/g, " ").trim();
      if (hasWords(text)) literals.push({ text, line: lineOf(node.start) });
    }

    if (node.type === "JSXElement" || node.type === "JSXFragment") {
      for (const child of (node.children as Node[]) ?? []) {
        if (child.type === "JSXExpressionContainer") shown(child.expression);
      }
    }

    if (node.type === "JSXAttribute" && isNode(node.name)) {
      const name = node.name.name as string;
      if (TEXT_ATTRIBUTES.has(name)) {
        const value = node.value;
        if (isNode(value) && value.type === "JSXExpressionContainer") shown(value.expression);
        else shown(value);
      }
    }

    for (const [field, child] of Object.entries(node)) {
      if (field === "type" || field === "start" || field === "end") continue;
      if (typeof child === "object" && child !== null) visit(child);
    }
  };

  visit(program);
  return { keys, literals };
}

/** The `{name}` placeholders in a string, sorted, for comparing two strings. */
export function placeholders(text: string): string[] {
  return [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
}
