/**
 * Unit tests for bump-version.mjs helpers.
 * Runs with the built-in Node test runner: `node --test scripts/`.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { SEMVER, bumpCargoVersion, bumpJsonField } from "./bump-version.mjs";

test("SEMVER accepts release, prerelease, and build-metadata versions", () => {
  assert.ok(SEMVER.test("1.0.0"));
  assert.ok(SEMVER.test("2.10.3"));
  assert.ok(SEMVER.test("1.0.0-rc.1"));
  assert.ok(SEMVER.test("1.0.0+build.5"));
  assert.ok(SEMVER.test("1.0.0-rc.1+build.5"));
});

test("SEMVER rejects malformed versions", () => {
  assert.ok(!SEMVER.test("1.0"));
  assert.ok(!SEMVER.test("v1.0.0"));
  assert.ok(!SEMVER.test("1.0.0 "));
  assert.ok(!SEMVER.test("latest"));
  assert.ok(!SEMVER.test(""));
});

test("bumpJsonField replaces only the requested field", () => {
  const raw = '{\n  "name": "app",\n  "version": "1.0.0"\n}\n';

  const out = bumpJsonField(raw, "version", "2.0.0");

  assert.equal(JSON.parse(out).version, "2.0.0");
  assert.equal(JSON.parse(out).name, "app");
});

test("bumpJsonField throws when the field is missing", () => {
  assert.throws(() => bumpJsonField('{ "name": "app" }', "version", "2.0.0"), {
    message: /"version" not found/,
  });
});

test("bumpCargoVersion replaces the top-level version line", () => {
  const raw = '[package]\nname = "app"\nversion = "1.0.0"\nedition = "2021"\n';

  const out = bumpCargoVersion(raw, "2.0.0");

  assert.match(out, /^version = "2\.0\.0"$/m);
  assert.match(out, /^name = "app"$/m);
});

test("bumpCargoVersion throws when no version line exists", () => {
  assert.throws(() => bumpCargoVersion('[package]\nname = "app"\n', "2.0.0"), {
    message: /not found in Cargo\.toml/,
  });
});
