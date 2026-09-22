import assert from "node:assert/strict";
import { test } from "node:test";
import { TargetError, isPublicAddress, normalizeTarget } from "../src/target.ts";

test("public addresses pass", () => {
  for (const ip of ["8.8.8.8", "1.1.1.1", "142.250.183.14", "2606:4700:4700::1111"]) {
    assert.equal(isPublicAddress(ip), true, ip);
  }
});

test("private, loopback, metadata and mapped addresses are blocked", () => {
  for (const ip of [
    "127.0.0.1",
    "10.1.2.3",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "::1",
    "::",
    "fe80::1",
    "fd00::1",
    "::ffff:127.0.0.1",
    "::ffff:169.254.169.254",
    "64:ff9b::a9fe:a9fe",
  ]) {
    assert.equal(isPublicAddress(ip), false, ip);
  }
});

test("normalizeTarget adds https and keeps only the origin", () => {
  assert.equal(normalizeTarget("example.com").href, "https://example.com/");
  assert.equal(normalizeTarget("http://example.com/login?x=1").href, "http://example.com/");
});

test("normalizeTarget rejects internal and unusual targets", () => {
  for (const input of [
    "localhost",
    "http://localhost:3000",
    "https://127.0.0.1",
    "http://[::1]/",
    "http://169.254.169.254/latest/meta-data",
    "https://printer.local",
    "https://db.internal",
    "https://intranet",
    "ftp://example.com",
    "file:///etc/passwd",
    "https://user:pass@example.com",
    "https://example.com:22",
    "",
  ]) {
    assert.throws(() => normalizeTarget(input), TargetError, input);
  }
});
