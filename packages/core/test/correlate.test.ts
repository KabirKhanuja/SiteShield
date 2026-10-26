import assert from "node:assert/strict";
import { test } from "node:test";
import { correlate, diffReports, fingerprint } from "../src/correlate.ts";
import type { Finding, Report } from "../src/types.ts";

function finding(partial: Partial<Finding> & Pick<Finding, "checkId" | "layer">): Finding {
  return {
    severity: "high",
    status: partial.layer === "live" ? "live" : "code",
    title: "t",
    detail: "d",
    remediation: [],
    ...partial,
  };
}

test("correlate confirms a secret found in both the bundle and the source", () => {
  const live = finding({ checkId: "BND001", layer: "live", evidence: "AKIA…YZ in /app.js" });
  const source = finding({ checkId: "SEC001", layer: "source", evidence: "AKIA…YZ" });
  const other = finding({ checkId: "HDR001", layer: "live", status: "live" });
  correlate([live, source, other]);
  assert.equal(live.status, "confirmed");
  assert.equal(source.status, "confirmed");
  assert.equal(other.status, "live", "an unrelated finding is untouched");
});

test("correlate confirms a vulnerable library on a shared version", () => {
  const live = finding({ checkId: "VER001", layer: "live", title: "jQuery 3.4.1 has known vulnerabilities" });
  const source = finding({ checkId: "DEP001", layer: "source", title: "jquery@3.4.1 has 2 advisories" });
  correlate([live, source]);
  assert.equal(live.status, "confirmed");
  assert.equal(source.status, "confirmed");
});

test("correlate does not confirm when the subjects differ", () => {
  const live = finding({ checkId: "BND001", layer: "live", evidence: "AKIA…11 in /a.js" });
  const source = finding({ checkId: "SEC001", layer: "source", evidence: "ghpX…99" });
  correlate([live, source]);
  assert.equal(live.status, "live");
  assert.equal(source.status, "code");
});

test("diffReports reports fixed, open and new findings", () => {
  const a = finding({ checkId: "SEC001", layer: "source", title: "A", source: { file: "x.js", line: 1 } });
  const b = finding({ checkId: "HDR001", layer: "live", title: "B", location: "https://s/" });
  const c = finding({ checkId: "CFG001", layer: "source", title: "C", source: { file: "y.js", line: 9 } });

  const baseline = report([a, b]);
  const current = report([b, c]);
  const diff = diffReports(current, baseline);

  assert.deepEqual(diff.fixed.map((f) => f.title), ["A"]);
  assert.deepEqual(diff.open.map((f) => f.title), ["B"]);
  assert.deepEqual(diff.introduced.map((f) => f.title), ["C"]);
});

test("fingerprint is stable for the same finding", () => {
  const f = finding({ checkId: "SEC001", layer: "source", title: "A", source: { file: "x.js", line: 3 } });
  assert.equal(fingerprint(f), fingerprint({ ...f }));
});

function report(findings: Finding[]): Report {
  return {
    target: "https://s/",
    startedAt: "",
    finishedAt: "",
    grade: "C",
    score: 60,
    checks: [],
    findings,
  };
}
