/**
 * Stages the Node server tree and the built UI under
 * `src-tauri/resources/` so Tauri's bundler picks them up via
 * `bundle.resources` in `tauri.conf.json`.
 *
 * Tauri does not run `prepare:server` or `build:client` for us; this script
 * is invoked from the `stage-tauri-bundle` npm script after both completed
 * (or directly via Tauri's `beforeDevCommand`/`beforeBuildCommand`).
 *
 * Layout produced:
 *   src-tauri/resources/server/        (full server tree, incl. node_modules)
 *   src-tauri/resources/client/dist/   (built React app)
 *
 * Implementation notes:
 * * We use `fs.cpSync(..., { recursive: true })` rather than a hand-rolled
 *   walker. `npm ci` can produce hoisted symlinks (e.g. on Linux/macOS for
 *   peer-deduped packages), and a naive `Dirent.isDirectory() / isFile()`
 *   walker silently skips symlinks, leaving Tauri's bundler dangling at
 *   `resources/server/node_modules/<pkg> doesn't exist`. `fs.cpSync` follows
 *   them via `dereference: true`.
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");

const SERVER_SRC = path.join(root, "server");
const CLIENT_DIST_SRC = path.join(root, "client", "dist");
const STAGE_ROOT = path.join(root, "src-tauri", "resources");
const SERVER_DEST = path.join(STAGE_ROOT, "server");
const CLIENT_DIST_DEST = path.join(STAGE_ROOT, "client", "dist");

const SERVER_FILTER = (src) => !src.split(path.sep).includes(".git");

function rmrf(p) {
  if (!fs.existsSync(p)) return;
  fs.rmSync(p, { recursive: true, force: true });
}

function ensure(name, src) {
  if (!fs.existsSync(src)) {
    console.error(`sync-server-resources: missing ${name} at ${src}`);
    process.exit(1);
  }
}

function copyTree(src, dest, opts = {}) {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.cpSync(src, dest, {
    recursive: true,
    dereference: true,
    errorOnExist: false,
    force: true,
    ...opts,
  });
}

function main() {
  ensure("server source", SERVER_SRC);
  ensure("server node_modules (run `make install-server` first)", path.join(SERVER_SRC, "node_modules"));
  ensure("client/dist (run `make build:client` first)", CLIENT_DIST_SRC);

  rmrf(STAGE_ROOT);
  copyTree(SERVER_SRC, SERVER_DEST, { filter: SERVER_FILTER });
  copyTree(CLIENT_DIST_SRC, CLIENT_DIST_DEST);

  console.log(
    `sync-server-resources: staged → ${path.relative(root, STAGE_ROOT)}`
  );
}

main();
