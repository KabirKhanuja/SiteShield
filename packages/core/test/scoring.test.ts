import assert from "node:assert/strict";
import { test } from "node:test";
import { scoreFindings } from "../src/scoring.ts";
import type { Finding, FindingStatus, Severity } from "../src/types.ts";

const f = (severity: Severity, status: FindingStatus = "live"): Finding => ({
  checkId: "TEST",
  layer: "live",
  severity,
  status,
  title: "t",
  detail: "d",
  remediation: [],
});

test("clean scan is an A", () => {
  assert.deepEqual(scoreFindings([]), { score: 100, grade: "A" });
});

test("info findings cost nothing", () => {
  assert.equal(scoreFindings([f("info"), f("info")]).score, 100);
});

test("confirmed findings cost one and a half times as much", () => {
  assert.equal(scoreFindings([f("high")]).score, 88);
  assert.equal(scoreFindings([f("high", "confirmed")]).score, 82);
});

test("a confirmed critical caps the grade at D", () => {
  const { score, grade } = scoreFindings([f("critical", "confirmed")]);
  assert.equal(score, 63); // would be a C on points alone
  assert.equal(grade, "D");
});

test("score never goes below zero", () => {
  assert.deepEqual(scoreFindings(Array.from({ length: 10 }, () => f("critical"))), { score: 0, grade: "F" });
});
