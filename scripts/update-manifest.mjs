import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

export function buildUpdateManifest({ version, tag, filename, signature, notes = "", date = new Date().toISOString() }) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error("Use the numeric application version.");
  if (tag !== `v${version}` && !new RegExp(`^v${version.replaceAll(".", "\\.")}-alpha\\.[1-9]\\d*$`).test(tag)) throw new Error("Release tag must match the application version.");
  if (basename(filename) !== filename || /[\\/]/.test(filename) || !filename.endsWith(`_${version}_x64-setup.exe`)) throw new Error("Use the matching Windows x64 installer filename.");
  const cleanSignature = signature.trim();
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(cleanSignature)) throw new Error("Missing or malformed Tauri signature.");
  const decoded = Buffer.from(cleanSignature, "base64").toString("utf8");
  if (!decoded.startsWith("untrusted comment:") || !decoded.includes("trusted comment:")) throw new Error("Expected Tauri's signed minisign envelope.");
  const trustedComment = decoded.split("\n").find((line) => line.startsWith("trusted comment:"));
  const signedVersion = trustedComment?.split("\t").find((field) => field.startsWith("version:"))?.slice("version:".length).trim();
  if (signedVersion !== version) throw new Error("Signature must contain the matching signed version; update the Tauri CLI if necessary.");
  if (!Number.isFinite(Date.parse(date))) throw new Error("Invalid publication date.");
  return {
    version, notes, pub_date: new Date(date).toISOString(),
    platforms: {
      "windows-x86_64": {
        signature: cleanSignature,
        url: `https://github.com/Dasshopen/reverse-assistant/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(filename)}`,
      },
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [installer, tag, output, notesFile] = process.argv.slice(2);
  if (!installer || !tag || !output) throw new Error("Usage: node scripts/update-manifest.mjs INSTALLER TAG OUTPUT [NOTES_FILE]");
  const config = JSON.parse(readFileSync(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"));
  const manifest = buildUpdateManifest({ version: config.version, tag, filename: basename(installer), signature: readFileSync(`${installer}.sig`, "utf8"), notes: notesFile ? readFileSync(notesFile, "utf8") : "" });
  writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  const hash = createHash("sha256").update(readFileSync(installer)).digest("hex");
  writeFileSync(join(dirname(output), "SHA256SUMS.txt"), `${hash}  ${basename(installer)}\n`, "utf8");
  copyFileSync(new URL("../.release-assets/THIRD_PARTY_NOTICES.txt", import.meta.url), join(dirname(output), "THIRD_PARTY_NOTICES.txt"));
  console.log(`Signed update manifest prepared: ${basename(output)}. Publish only after the matching assets are available and tested.`);
}
