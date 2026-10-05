import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { UpdateController } from "../../src/lib/updates.ts";
import { buildUpdateManifest } from "../../scripts/update-manifest.mjs";

test("published feed uses the GitHub asset filename and a matching signed version", () => {
  const manifest = JSON.parse(readFileSync(new URL("../../updates/latest.json", import.meta.url), "utf8"));
  const platform = manifest.platforms["windows-x86_64"];
  const expected = buildUpdateManifest({
    version: manifest.version, tag: `v${manifest.version}-alpha.1`,
    filename: `Reverse.Assistant_${manifest.version}_x64-setup.exe`,
    signature: platform.signature, notes: manifest.notes, date: manifest.pub_date,
  });
  assert.deepEqual(manifest, expected);
});

function fixture(overrides = {}, fetcher) {
  const calls = [];
  const update = {
    version: "0.1.4", body: "Release notes",
    download: async (event) => { calls.push("download"); event({ event: "Started", data: { contentLength: 100 } }); event({ event: "Progress", data: { chunkLength: 100 } }); event({ event: "Finished" }); },
    install: async () => { calls.push("install"); },
    close: async () => { calls.push("close"); }, ...overrides,
  };
  const states = [];
  const controller = new UpdateController(fetcher ?? (async () => update), (state) => states.push(state));
  return { controller, calls, states, update };
}

test("checking never downloads or installs without an explicit action", async () => {
  const f = fixture();
  await f.controller.check();
  assert.equal(f.controller.state.stage, "available");
  assert.deepEqual(f.calls, []);
  assert.equal(f.controller.state.notes, "Release notes");
});

test("a successful null response means no newer update", async () => {
  const f = fixture({}, async () => null);
  await f.controller.check();
  assert.equal(f.controller.state.stage, "current");
});

test("offline, private and missing feeds are not reported as up to date", async () => {
  const f = fixture({}, async () => { throw new Error("404 or network failure"); });
  await f.controller.check();
  assert.equal(f.controller.state.stage, "error");
  assert.equal(f.controller.state.version, null);
});

test("signature failure after transport Finished prevents installation", async () => {
  const f = fixture({ download: async (event) => { event({ event: "Finished" }); throw new Error("invalid signature"); } });
  await f.controller.check();
  await f.controller.download();
  assert.equal(f.controller.state.stage, "error");
  await f.controller.install(() => false, async () => true, async () => {});
  assert(!f.calls.includes("install"));
});

test("download tracks progress but never starts the installer", async () => {
  const f = fixture();
  await f.controller.check();
  await f.controller.download();
  assert.equal(f.controller.state.stage, "ready");
  assert.equal(f.controller.state.downloaded, 100);
  assert.deepEqual(f.calls, ["download"]);
});

test("busy app and cancelled confirmation leave the update staged", async () => {
  const f = fixture();
  await f.controller.check(); await f.controller.download();
  let confirmed = false;
  await f.controller.install(() => true, async () => { confirmed = true; return true; }, async () => {});
  assert.equal(confirmed, false);
  await f.controller.install(() => false, async () => false, async () => {});
  assert.equal(f.controller.state.stage, "ready");
  assert(!f.calls.includes("install"));
});

test("operations started during confirmation block installation", async () => {
  const f = fixture();
  await f.controller.check(); await f.controller.download();
  let busy = false;
  await f.controller.install(() => busy, async () => { busy = true; return true; }, async () => {});
  assert(!f.calls.includes("install"));
  assert.equal(f.controller.state.stage, "ready");
});

test("install failure unlocks the app and permits a retry", async () => {
  let installs = 0;
  const f = fixture({ install: async () => { installs += 1; if (installs === 1) throw new Error("failed"); } });
  const locks = [];
  await f.controller.check(); await f.controller.download();
  await f.controller.install(() => false, async () => true, async (locked) => { locks.push(locked); });
  assert.equal(f.controller.state.stage, "ready");
  assert.deepEqual(locks, [true, false]);
  await f.controller.install(() => false, async () => true, async () => {});
  assert.equal(f.controller.state.stage, "installed");
});

test("concurrent checks are serialized and stale resources closed on unmount", async () => {
  let resolve;
  let fetches = 0;
  const f = fixture({}, () => { fetches += 1; return new Promise((done) => { resolve = done; }); });
  const first = f.controller.check();
  await f.controller.check();
  assert.equal(fetches, 1);
  await f.controller.dispose();
  resolve(f.update); await first;
  assert.deepEqual(f.calls, ["close"]);
});

test("alpha manifests use explicit versioned HTTPS installer URLs", () => {
  const input = { version: "0.1.3", tag: "v0.1.3-alpha.1", filename: "Reverse Assistant_0.1.3_x64-setup.exe", signature: Buffer.from("untrusted comment: test envelope\nfixture\ntrusted comment: test\tversion:0.1.3\nfixture").toString("base64"), date: "2026-10-05T12:00:00Z" };
  const result = buildUpdateManifest(input);
  assert.equal(result.version, "0.1.3");
  assert(result.platforms["windows-x86_64"].url.includes("/v0.1.3-alpha.1/Reverse%20Assistant_0.1.3_x64-setup.exe"));
  assert.equal(result.platforms["windows-x86_64"].signature, input.signature);
  assert.throws(() => buildUpdateManifest({ ...input, tag: "v0.1.2-alpha.1" }));
  assert.throws(() => buildUpdateManifest({ ...input, filename: "other.exe" }));
  assert.throws(() => buildUpdateManifest({ ...input, signature: "https://example.com/installer.sig" }));
  assert.throws(() => buildUpdateManifest({ ...input, signature: Buffer.from("not a signature").toString("base64") }));
  assert.throws(() => buildUpdateManifest({ ...input, signature: Buffer.from("untrusted comment: test\nfixture\ntrusted comment: test\tversion:0.1.2\nfixture").toString("base64") }));
});
