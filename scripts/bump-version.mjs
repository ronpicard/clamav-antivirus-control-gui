/**
 * Bumps the app version everywhere it lives.
 *
 * Single source of truth (UI badge, GitHub Release tag, Tauri bundle
 * metadata, Cargo crate) is the same semantic version, kept in sync
 * across the four files below.
 *
 * Usage:
 *   node scripts/bump-version.mjs <semver>
 *   e.g. node scripts/bump-version.mjs 1.1.0
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");

export const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

const TARGETS = [
  {
    file: "package.json",
    update: (raw, version) => bumpJsonField(raw, "version", version),
  },
  {
    file: "client/package.json",
    update: (raw, version) => bumpJsonField(raw, "version", version),
  },
  {
    file: "server/package.json",
    update: (raw, version) => bumpJsonField(raw, "version", version),
  },
  {
    file: "src-tauri/tauri.conf.json",
    update: (raw, version) => bumpJsonField(raw, "version", version),
  },
  {
    file: "src-tauri/Cargo.toml",
    update: (raw, version) => bumpCargoVersion(raw, version),
  },
];

export function bumpJsonField(raw, key, value) {
  const re = new RegExp(`("${key}"\\s*:\\s*)"[^"]*"`);
  if (!re.test(raw)) {
    throw new Error(`field "${key}" not found`);
  }
  return raw.replace(re, (_m, prefix) => `${prefix}"${value}"`);
}

export function bumpCargoVersion(raw, version) {
  const re = /^(version\s*=\s*)"[^"]*"/m;
  if (!re.test(raw)) {
    throw new Error('top-level `version = "..."` not found in Cargo.toml');
  }
  return raw.replace(re, (_m, prefix) => `${prefix}"${version}"`);
}

function main() {
  const [, , raw] = process.argv;
  if (!raw) {
    console.error("usage: node scripts/bump-version.mjs <semver>");
    process.exit(1);
  }
  const version = raw.replace(/^v/, "").trim();
  if (!SEMVER.test(version)) {
    console.error(`bump-version: "${version}" is not a valid semver string.`);
    process.exit(1);
  }

  for (const t of TARGETS) {
    const abs = path.join(root, t.file);
    if (!fs.existsSync(abs)) {
      console.error(`bump-version: missing ${t.file}`);
      process.exit(1);
    }
    const before = fs.readFileSync(abs, "utf8");
    const after = t.update(before, version);
    if (before === after) {
      console.warn(`bump-version: ${t.file} unchanged (already at ${version}?)`);
      continue;
    }
    fs.writeFileSync(abs, after);
    console.log(`bump-version: ${t.file} → ${version}`);
  }

  console.log("\nNext steps:");
  console.log("  1. Review:   git diff");
  console.log("  2. Stage:    git add -A");
  console.log(`  3. Commit:   git commit -m "release: v${version}"`);
  console.log(`  4. Tag:      git tag -a v${version} -m "ClamAV Control v${version}"`);
  console.log("  5. Push:     git push origin main && git push origin v" + version);
}

// Run only when executed directly, so tests can import the helpers.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
