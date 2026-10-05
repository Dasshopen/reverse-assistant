import test from "node:test";
import assert from "node:assert/strict";
import { SymbolPresentationQueue, displaySymbolName, decodedRenameName } from "../../src/lib/symbolNames.ts";

const presentation = (raw_name) => ({ raw_name, display_name: "Foo::bar", signature: "Foo::bar(int)", rename_name: "Foo_bar", scheme: "itanium", decoded: true });

test("readable display and flat rename are separate from the unchanged raw symbol", () => {
  const result = presentation("_ZN3Foo3barEi");
  assert.equal(displaySymbolName(result.raw_name, result), "Foo::bar");
  assert.equal(decodedRenameName(result.raw_name, result), "Foo_bar");
  assert.equal(result.raw_name, "_ZN3Foo3barEi");
  assert.equal(decodedRenameName("_Zbroken"), null);
  assert.equal(displaySymbolName("_Zbroken"), "_Zbroken");
  assert.equal(decodedRenameName(result.raw_name, { ...result, rename_name: "invalid name" }), null);
});

test("duplicate symbols are batched, cached and never fetched per row", async () => {
  const calls = [];
  const results = [];
  const queue = new SymbolPresentationQueue(async (names) => { calls.push(names); return names.map(presentation); }, (batch) => results.push(...batch));
  const names = Array.from({ length: 600 }, (_, index) => `_Z${index}`);
  queue.request([...names, ...names, "memcpy"]);
  await queue.settled();
  queue.request(names);
  await queue.settled();
  assert.equal(calls.length, 3);
  assert(calls.every((batch) => batch.length <= 256));
  assert.equal(results.length, 600);
});

test("failed IPC retains raw names and does not create a retry loop", async () => {
  let calls = 0;
  let result;
  const queue = new SymbolPresentationQueue(async () => { calls += 1; throw new Error("unavailable"); }, (batch) => { result = batch[0]; });
  queue.request(["?broken"]);
  await queue.settled();
  queue.request(["?broken"]);
  await queue.settled();
  assert.equal(calls, 1);
  assert.equal(result.raw_name, "?broken");
  assert.equal(result.rename_name, null);
  assert.equal(result.decoded, false);
});

test("oversized encoded symbols remain visible without IPC or a permanent loading label", async () => {
  const raw = `?${"x".repeat(2048)}`;
  const results = [];
  let calls = 0;
  const queue = new SymbolPresentationQueue(async () => { calls += 1; return []; }, (batch) => results.push(...batch));
  queue.request([raw]);
  queue.request([raw]);
  await queue.settled();
  assert.equal(calls, 0);
  assert.equal(results.length, 1);
  assert.equal(results[0].raw_name, raw);
  assert.equal(results[0].decoded, false);
  assert.equal(results[0].rename_name, null);
});

test("project reset discards in-flight presentations from the previous project", async () => {
  let resolveOld;
  const results = [];
  let calls = 0;
  const queue = new SymbolPresentationQueue((names) => {
    calls += 1;
    return calls === 1 ? new Promise((resolve) => { resolveOld = resolve; }) : Promise.resolve(names.map(presentation));
  }, (batch) => results.push(...batch));
  queue.request(["_Zold"]);
  queue.reset();
  queue.request(["_Znew"]);
  resolveOld([presentation("_Zold")]);
  await queue.settled();
  assert.deepEqual(results.map((result) => result.raw_name), ["_Znew"]);
});
