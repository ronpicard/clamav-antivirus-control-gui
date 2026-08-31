/**
 * Unit + regression tests for sync-server-resources.mjs helpers.
 * Runs with the built-in Node test runner: `node --test scripts/`.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import { SERVER_FILTER, copyTree, rmrf } from "./sync-server-resources.mjs";

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sync-resources-test-"));
}

// Regression: v2.0.0 "Resource staging on hoisted node_modules". The old
// hand-rolled walker skipped symlinked packages entirely, breaking the Tauri
// bundler with `resource path '…/node_modules/destroy' doesn't exist`.
// copyTree must stage the entry so the path exists and resolves to the
// package content. (Node's cpSync may keep it as a link that resolves —
// what matters is that it is never dropped or dangling.)
test("copyTree stages symlinked packages instead of dropping them (regression, v2.0.0)", (t) => {
  const root = tmpdir();
  t.after(() => rmrf(root));
  const src = path.join(root, "src");
  const realPkg = path.join(root, "real-pkg");
  fs.mkdirSync(path.join(src, "node_modules"), { recursive: true });
  fs.mkdirSync(realPkg);
  fs.writeFileSync(path.join(realPkg, "index.js"), "module.exports = 1;\n");
  fs.symlinkSync(realPkg, path.join(src, "node_modules", "destroy"), "junction");

  const dest = path.join(root, "dest");
  copyTree(src, dest);

  const staged = path.join(dest, "node_modules", "destroy");
  assert.ok(fs.existsSync(staged), "symlinked package staged, not skipped");
  assert.ok(fs.statSync(staged).isDirectory(), "staged entry resolves to a directory");
  assert.equal(
    fs.readFileSync(path.join(staged, "index.js"), "utf8"),
    "module.exports = 1;\n"
  );
});

test("copyTree copies regular files and creates parent directories", (t) => {
  const root = tmpdir();
  t.after(() => rmrf(root));
  const src = path.join(root, "src");
  fs.mkdirSync(src);
  fs.writeFileSync(path.join(src, "index.js"), "ok\n");

  const dest = path.join(root, "deep", "nested", "dest");
  copyTree(src, dest);

  assert.equal(fs.readFileSync(path.join(dest, "index.js"), "utf8"), "ok\n");
});

test("SERVER_FILTER excludes .git path segments only", () => {
  assert.equal(SERVER_FILTER(path.join("server", ".git", "config")), false);
  assert.equal(SERVER_FILTER(path.join("server", ".git")), false);
  assert.equal(SERVER_FILTER(path.join("server", "index.js")), true);
  // A file merely containing ".git" in its name must not be filtered.
  assert.equal(SERVER_FILTER(path.join("server", ".gitignore")), true);
});

test("rmrf removes a tree and tolerates a missing path", (t) => {
  const root = tmpdir();
  t.after(() => rmrf(root));
  const victim = path.join(root, "victim");
  fs.mkdirSync(path.join(victim, "sub"), { recursive: true });
  fs.writeFileSync(path.join(victim, "sub", "f"), "x");

  rmrf(victim);
  assert.ok(!fs.existsSync(victim));

  // Second call on the now-missing path must not throw.
  rmrf(victim);
});
