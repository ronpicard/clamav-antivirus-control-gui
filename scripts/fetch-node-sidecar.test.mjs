import assert from "node:assert/strict";
import { test } from "node:test";

import { NODE_VERSION, expectedSha, plan, sha256Of } from "./fetch-node-sidecar.mjs";

test("plan stages a universal binary under all three Apple triples on macOS", () => {
  const p = plan("darwin", "arm64");
  assert.equal(p.universal, true);
  assert.deepEqual(
    p.outputs.slice().sort(),
    [
      "node-aarch64-apple-darwin",
      "node-universal-apple-darwin",
      "node-x86_64-apple-darwin",
    ],
  );
  assert.deepEqual(
    p.downloads.map((d) => d.file).sort(),
    [
      `node-v${NODE_VERSION}-darwin-arm64.tar.gz`,
      `node-v${NODE_VERSION}-darwin-x64.tar.gz`,
    ],
  );
});

test("plan targets the msvc triple with .exe on Windows", () => {
  const p = plan("win32", "x64");
  assert.deepEqual(p.outputs, ["node-x86_64-pc-windows-msvc.exe"]);
  assert.equal(p.downloads.length, 1);
  assert.equal(p.downloads[0].file, `node-v${NODE_VERSION}-win-x64.zip`);
  assert.equal(p.downloads[0].member, `node-v${NODE_VERSION}-win-x64/node.exe`);
});

test("plan targets the gnu triple per arch on Linux", () => {
  assert.deepEqual(plan("linux", "x64").outputs, ["node-x86_64-unknown-linux-gnu"]);
  assert.deepEqual(plan("linux", "arm64").outputs, ["node-aarch64-unknown-linux-gnu"]);
  assert.equal(
    plan("linux", "x64").downloads[0].member,
    `node-v${NODE_VERSION}-linux-x64/bin/node`,
  );
});

test("expectedSha finds the checksum for an exact filename only", () => {
  const sums = [
    `${"a".repeat(64)}  node-v${NODE_VERSION}-linux-x64.tar.gz`,
    `${"b".repeat(64)}  node-v${NODE_VERSION}-linux-x64.tar.xz`,
  ].join("\n");
  assert.equal(expectedSha(sums, `node-v${NODE_VERSION}-linux-x64.tar.gz`), "a".repeat(64));
  assert.equal(expectedSha(sums, "node-v0.0.0-linux-x64.tar.gz"), null);
});

test("sha256Of hashes bytes to lowercase hex", () => {
  assert.equal(
    sha256Of(Buffer.from("abc")),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});
