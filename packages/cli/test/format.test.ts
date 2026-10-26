import assert from "node:assert/strict";
import { test } from "node:test";
import type { Finding, Report } from "@siteshield/core";
import { formatJson, formatSarif, formatText } from "../src/format.ts";
import { formatHtml } from "../src/html.ts";

const findings: Finding[] = [
  {
    checkId: "SEC001",
    layer: "source",
    severity: "critical",
    status: "confirmed",
    title: "Stripe secret key hardcoded",
    detail: "A key is in the code.",
    evidence: "sk_l…yz",
    location: "src/pay.ts:4",
    source: { file: "src/pay.ts", line: 4, column: 7, snippet: 'const k = "sk_live_…"' },
    owasp: "A05:2021 Security Misconfiguration",
    cwe: "CWE-798",
    cvss: 9.1,
    remediation: [{ stack: "any", summary: "Rotate it and read from env.", code: "process.env.STRIPE_KEY" }],
  },
  {
    checkId: "HDR001",
    layer: "live",
    severity: "medium",
    status: "live",
    title: "No Content Security Policy",
    detail: "No CSP header.",
    remediation: [{ stack: "nextjs", summary: "Add it." }],
  },
];

const report: Report = {
  target: "https://example.com",
  url: "https://example.com",
  src: ".",
  stacks: ["nextjs"],
  startedAt: new Date().toISOString(),
  finishedAt: new Date().toISOString(),
  grade: "D",
  score: 45,
  checks: [
    { checkId: "SEC001", ran: true, findings: [findings[0]!] },
    { checkId: "HDR001", ran: true, findings: [findings[1]!] },
    { checkId: "EXP001", ran: false, skippedReason: "Needs ownership verification.", findings: [] },
  ],
  findings,
};

test("text report shows grade, confirmed and a fix", () => {
  const out = formatText(report);
  assert.match(out, /Grade/);
  assert.match(out, /CONFIRMED/);
  assert.match(out, /Rotate it/);
  assert.match(out, /Not run: EXP001/);
});

test("json report round-trips", () => {
  const parsed = JSON.parse(formatJson(report)) as Report;
  assert.equal(parsed.grade, "D");
  assert.equal(parsed.findings.length, 2);
  assert.equal(parsed.findings[0]!.cvss, 9.1);
});

test("sarif is valid 2.1.0 with rules, results and a source location", () => {
  const sarif = JSON.parse(formatSarif(report));
  assert.equal(sarif.version, "2.1.0");
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, "SiteShield");
  assert.equal(run.results.length, 2);
  const sec = run.results.find((r: { ruleId: string }) => r.ruleId === "SEC001");
  assert.equal(sec.level, "error");
  assert.equal(sec.locations[0].physicalLocation.artifactLocation.uri, "src/pay.ts");
  assert.equal(sec.locations[0].physicalLocation.region.startLine, 4);
});

test("html report is self-contained and escapes content", () => {
  const html = formatHtml({
    ...report,
    findings: [{ ...findings[0]!, title: "<script>alert(1)</script>" }],
  });
  assert.match(html, /<!doctype html>/i);
  assert.match(html, /Executive summary/);
  assert.ok(!html.includes("<script>alert(1)</script>"), "title must be HTML-escaped");
  assert.match(html, /&lt;script&gt;/);
});
