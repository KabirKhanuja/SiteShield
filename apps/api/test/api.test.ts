// Response bodies are typed unknown; these tests assert on their shape directly.
/* eslint-disable @typescript-eslint/no-explicit-any */
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import type { Report, ScanOptions } from "@siteshield/core";
import { createApp } from "../src/app.ts";
import { loadConfig } from "../src/config.ts";
import { openDatabase } from "../src/db.ts";
import { ScanQueue } from "../src/jobs.ts";

// A fake engine, so these tests never touch the network.
async function fakeScan(options: ScanOptions): Promise<Report> {
  if (options.url.includes("broken")) throw new Error("boom");
  const now = new Date().toISOString();
  return { target: options.url, startedAt: now, finishedAt: now, grade: "B", score: 80, checks: [], findings: [] };
}

const db = openDatabase(":memory:");
const queue = new ScanQueue(db, 2, fakeScan);
const app = createApp(loadConfig({ SCANS_PER_10_MIN: "100" }), db, queue);
let base = "";
let server: ReturnType<typeof app.listen>;

before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => {
  server.close();
  db.close();
});

const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  fetch(base + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });

test("health responds and carries security headers", async () => {
  const res = await fetch(`${base}/health`);
  assert.equal(res.status, 200);
  assert.ok(res.headers.get("content-security-policy"));
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.equal(res.headers.get("x-powered-by"), null);
});

test("a scan is queued, runs, and its report can be read", async () => {
  const res = await post("/api/scans", { url: "example.com" });
  assert.equal(res.status, 202);
  const { id, target } = await res.json() as any;
  assert.equal(target, "https://example.com");

  await queue.idle();
  const scan = await (await fetch(`${base}/api/scans/${id}`)).json() as any;
  assert.equal(scan.status, "done");
  assert.equal(scan.grade, "B");
  assert.equal(scan.report.score, 80);
});

test("a failing scan is stored as failed with its reason", async () => {
  const { id } = await (await post("/api/scans", { url: "broken.example.com" })).json() as any;
  await queue.idle();
  const scan = await (await fetch(`${base}/api/scans/${id}`)).json() as any;
  assert.equal(scan.status, "failed");
  assert.equal(scan.error, "boom");
});

test("the event stream of a finished scan sends the result and closes", async () => {
  const { id } = await (await post("/api/scans", { url: "example.org" })).json() as any;
  await queue.idle();
  const text = await (await fetch(`${base}/api/scans/${id}/events`)).text();
  assert.match(text, /event: done\ndata: \{"type":"done","grade":"B","score":80\}/);
});

test("internal targets are refused before anything is queued", async () => {
  for (const url of ["localhost", "http://169.254.169.254", "https://10.0.0.1"]) {
    const res = await post("/api/scans", { url });
    assert.equal(res.status, 400, url);
    assert.equal((await res.json() as any).error.code, "invalid_target");
  }
});

test("bad input gets a 400 with a readable message", async () => {
  const res = await post("/api/scans", { url: 42 });
  assert.equal(res.status, 400);
  assert.equal((await res.json() as any).error.code, "invalid_request");

  assert.equal((await fetch(`${base}/api/scans/not-a-uuid`)).status, 400);
  assert.equal((await fetch(`${base}/api/scans/${crypto.randomUUID()}`)).status, 404);
  assert.equal((await fetch(`${base}/nope`)).status, 404);
});

test("active scans need a verified ownership key", async () => {
  const denied = await post("/api/scans", { url: "example.net", active: true });
  assert.equal(denied.status, 403);
  assert.equal((await denied.json() as any).error.code, "ownership_required");

  const created = await post("/api/verifications", { domain: "https://www.example.net/some/page" });
  assert.equal(created.status, 201);
  const v = await created.json() as any;
  assert.equal(v.domain, "example.net");
  assert.equal(v.verified, false);
  assert.equal(v.instructions.dns.name, "_siteshield.example.net");
  assert.equal(typeof v.key, "string");

  // The key is required to read the verification, and a wrong key looks like a missing id.
  assert.equal((await fetch(`${base}/api/verifications/${v.id}`)).status, 404);
  assert.equal((await fetch(`${base}/api/verifications/${v.id}`, { headers: { "x-ownership-key": "wrong" } })).status, 404);
  const read = await fetch(`${base}/api/verifications/${v.id}`, { headers: { "x-ownership-key": v.key } });
  assert.equal(read.status, 200);
  assert.equal("key" in (await read.json() as any), false);

  // Simulate a successful DNS check, then the same key unlocks active scans.
  db.markVerified(v.id, "dns", new Date(Date.now() + 60_000));
  const allowed = await post("/api/scans", { url: "example.net", active: true }, { "x-ownership-key": v.key });
  assert.equal(allowed.status, 202);

  // Someone else's key for the same domain does not.
  const other = await (await post("/api/verifications", { domain: "example.net" })).json() as any;
  const stranger = await post("/api/scans", { url: "example.net", active: true }, { "x-ownership-key": other.key });
  assert.equal(stranger.status, 403);
  await queue.idle();
});

test("oversized bodies are rejected", async () => {
  const res = await post("/api/scans", { url: "x".repeat(20_000) });
  assert.equal(res.status, 413);
});

test("scan creation is rate limited per client", async () => {
  const limited = createApp(loadConfig({ SCANS_PER_10_MIN: "2" }), db, queue);
  const s = limited.listen(0);
  await new Promise((r) => s.once("listening", r));
  const url = `http://127.0.0.1:${(s.address() as AddressInfo).port}/api/scans`;
  const send = () => fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: '{"url":"example.com"}' });
  assert.equal((await send()).status, 202);
  assert.equal((await send()).status, 202);
  const third = await send();
  assert.equal(third.status, 429);
  assert.equal((await third.json() as any).error.code, "rate_limited");
  s.close();
  await queue.idle();
});
