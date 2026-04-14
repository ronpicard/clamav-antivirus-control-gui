/**
 * Builds square 1024×1024 PNGs with transparency from assets/icon-source.png.
 * The source is a wide canvas with a grid margin; we cover-crop then mask to a squircle.
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import sharp from "sharp";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");

const SRC = path.join(root, "assets", "icon-source.png");
const OUT_BUILD = path.join(root, "build", "icon.png");
const OUT_PUBLIC = path.join(root, "client", "public", "icon.png");

const SIZE = 1024;
/** ~iOS/macOS icon grid corner radius ratio */
const RX = Math.round(SIZE * 0.2237);

async function main() {
  if (!fs.existsSync(SRC)) {
    console.error("render-app-icon: missing", SRC);
    process.exit(1);
  }

  const maskSvg = Buffer.from(
    `<svg width="${SIZE}" height="${SIZE}" xmlns="http://www.w3.org/2000/svg">
      <rect width="${SIZE}" height="${SIZE}" rx="${RX}" ry="${RX}" fill="#ffffff"/>
    </svg>`
  );

  const maskPng = await sharp(maskSvg).png().toBuffer();

  const out = await sharp(SRC)
    .resize(SIZE, SIZE, { fit: "cover", position: "center" })
    .ensureAlpha()
    .composite([{ input: maskPng, blend: "dest-in" }])
    .png({ compressionLevel: 9 })
    .toBuffer();

  fs.mkdirSync(path.dirname(OUT_BUILD), { recursive: true });
  fs.mkdirSync(path.dirname(OUT_PUBLIC), { recursive: true });
  fs.writeFileSync(OUT_BUILD, out);
  fs.writeFileSync(OUT_PUBLIC, out);
  console.log("render-app-icon: wrote", path.relative(root, OUT_BUILD), path.relative(root, OUT_PUBLIC));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
