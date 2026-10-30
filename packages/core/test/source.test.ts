import assert from "node:assert/strict";
import { test } from "node:test";
import { authCheck } from "../src/source/checks/auth.ts";
import { configCheck } from "../src/source/checks/config.ts";
import { corsCheck } from "../src/source/checks/cors.ts";
import { injectionCheck } from "../src/source/checks/injection.ts";
import { publicEnvCheck } from "../src/source/checks/public-env.ts";
import { rateLimitCheck } from "../src/source/checks/rate-limit.ts";
import { secretsCheck } from "../src/source/checks/secrets.ts";
import { xssCheck } from "../src/source/checks/xss.ts";
import { scan } from "../src/scan.ts";
import { sourceFilesFromUploads } from "../src/source/walk.ts";
import { detectStacks } from "../src/source/stack.ts";
import type { SourceContext, SourceFile } from "../src/source/types.ts";

function file(path: string, content: string): SourceFile {
  return { path, content, lines: content.split(/\r?\n/) };
}

function ctx(files: SourceFile[]): SourceContext {
  const packages = files
    .filter((f) => /package\.json$/.test(f.path))
    .map((f) => ({ path: f.path, data: JSON.parse(f.content) }));
  return { root: "", files, packages, stacks: [], offline: true };
}

async function run(check: { run: (c: SourceContext) => unknown }, files: SourceFile[]) {
  return (await check.run(ctx(files))) as Awaited<ReturnType<typeof secretsCheck.run>>;
}

test("SEC001 finds a hardcoded GitHub token", async () => {
  const f = await run(secretsCheck, [file("a.js", `const t = "ghp_${"a".repeat(36)}";`)]);
  assert.equal(f.length, 1);
  assert.equal(f[0]!.checkId, "SEC001");
  assert.ok(!f[0]!.evidence!.includes("aaaa".repeat(9)), "secret should be masked");
});

test("SEC001 ignores placeholders and example env files", async () => {
  const code = await run(secretsCheck, [file("a.js", `const password = "your-password-here";`)]);
  assert.equal(code.length, 0);
  const env = await run(secretsCheck, [file(".env.example", `API_SECRET=replace_me_with_real_value_123`)]);
  assert.equal(env.length, 0);
});

test("SEC001 flags a real secret in a committed .env", async () => {
  const f = await run(secretsCheck, [file(".env", `DB_PASSWORD=r3alLiveP@ssw0rd_2024`)]);
  assert.equal(f.length, 1);
  assert.match(f[0]!.title, /committed/i);
});

test("PUB001 flags a secret public var but not a publishable key", async () => {
  const f = await run(publicEnvCheck, [
    file(".env", "NEXT_PUBLIC_API_SECRET=abc\nNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_x"),
  ]);
  assert.equal(f.length, 1);
  assert.match(f[0]!.title, /NEXT_PUBLIC_API_SECRET/);
});

test("COR002 flags wildcard origin with credentials as high", async () => {
  const f = await run(corsCheck, [file("s.js", `app.use(cors({ origin: "*", credentials: true }));`)]);
  assert.equal(f.length, 1);
  assert.equal(f[0]!.severity, "high");
});

test("INJ002 flags eval on request data but not a parameterised query", async () => {
  const bad = await run(injectionCheck, [file("s.js", `app.get("/x", (req,res)=>{ eval(req.query.code); });`)]);
  assert.ok(bad.some((x) => x.title.includes("eval")));
  const good = await run(injectionCheck, [file("s.js", `db.query("SELECT * FROM users WHERE id = $1", [id]);`)]);
  assert.equal(good.length, 0);
});

test("INJ002 flags SQL built by concatenation with request data", async () => {
  const f = await run(injectionCheck, [file("s.js", `const q = "SELECT * FROM u WHERE n='" + req.body.name + "'";`)]);
  assert.ok(f.some((x) => x.title.includes("SQL")));
});

test("XSS001 flags unsanitised dangerouslySetInnerHTML but not a sanitised one", async () => {
  const bad = await run(xssCheck, [file("c.jsx", `<div dangerouslySetInnerHTML={{ __html: userText }} />`)]);
  assert.equal(bad.length, 1);
  const good = await run(xssCheck, [file("c.jsx", `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userText) }} />`)]);
  assert.equal(good.length, 0);
});

test("CFG001 flags rejectUnauthorized:false and alg none", async () => {
  const f = await run(configCheck, [file("s.js", `const o = { rejectUnauthorized: false };\njwt.verify(t, k, { algorithms: ["none"] });`)]);
  assert.ok(f.some((x) => x.title.includes("TLS certificate")));
  assert.ok(f.some((x) => x.severity === "critical"));
});

test("AUT001 flags a mutating route with no auth, passes one with auth", async () => {
  const bad = await run(authCheck, [file("s.js", `app.post("/items", (req,res)=>{ db.insert(req.body); });`)]);
  assert.equal(bad.length, 1);
  const good = await run(authCheck, [file("s.js", `app.post("/items", requireAuth, (req,res)=>{ db.insert(req.body); });`)]);
  assert.equal(good.length, 0);
});

test("RTL002 flags a login route with no limiter", async () => {
  const bad = await run(rateLimitCheck, [file("s.js", `app.post("/login", (req,res)=>{ check(req.body); });`)]);
  assert.equal(bad.length, 1);
  const good = await run(rateLimitCheck, [
    file("s.js", `import { rateLimit } from "express-rate-limit";\napp.post("/login", limiter, h);`),
  ]);
  assert.equal(good.length, 0);
});

test("sourceFilesFromUploads filters junk and scan() grades in-memory files", async () => {
  const uploads = [
    { path: "node_modules/pkg/evil.js", content: `app.use(cors({ origin: "*", credentials: true }));` }, // dependency, skipped
    { path: "app/server.js", content: `app.use(cors({ origin: "*", credentials: true }));` },
    { path: "logo.png", content: "not real binary" }, // not a scannable type, skipped
  ];
  const files = sourceFilesFromUploads(uploads);
  assert.deepEqual(
    files.map((f) => f.path),
    ["app/server.js"],
  );
  const report = await scan({ srcFiles: files, offline: true });
  assert.equal(report.src, "uploaded source");
  assert.ok(report.findings.some((f) => f.checkId === "COR002"));
});

test("detectStacks recognises Next.js and Express from package.json", () => {
  const files = [file("package.json", JSON.stringify({ dependencies: { next: "15", express: "5" } }))];
  const stacks = detectStacks(files, [{ path: "package.json", data: { dependencies: { next: "15", express: "5" } } }]);
  assert.ok(stacks.includes("nextjs"));
  assert.ok(stacks.includes("express"));
});
