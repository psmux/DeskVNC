// cd mobile/scripts && npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { escapeHtml } from "./html.mjs";

test("text cannot open a tag", () => {
  assert.equal(escapeHtml("<script>alert(1)</script>"), "&lt;script&gt;alert(1)&lt;/script&gt;");
});

test("a value cannot leave a quoted attribute", () => {
  const v = escapeHtml(`x" onmouseover="alert(1)' y='`);
  assert.ok(!v.includes('"') && !v.includes("'"), v);
  assert.equal(v, "x&quot; onmouseover=&quot;alert(1)&#39; y=&#39;");
});

test("ampersands are escaped once", () => {
  assert.equal(escapeHtml("a & b &amp; c"), "a &amp; b &amp;amp; c");
});

test("non strings are stringified", () => {
  assert.equal(escapeHtml(42), "42");
});
