import { cookiesCheck } from "./checks/cookies.ts";
import { dnsCheck } from "./checks/dns.ts";
import { headersCheck } from "./checks/headers.ts";
import { tlsCheck } from "./checks/tls.ts";
import type { Check } from "./checks/types.ts";
import { readLimited, safeFetch } from "./http.ts";
import { findIcon } from "./icon.ts";
import { scoreFindings } from "./scoring.ts";
import { normalizeTarget } from "./target.ts";
import type { Response } from "undici";
import type { CheckResult, Report, ScanEvent, ScanOptions } from "./types.ts";

export const liveChecks: Check[] = [tlsCheck, headersCheck, cookiesCheck, dnsCheck];

/** Listed so reports show them as skipped instead of silently leaving them out. */
const plannedActiveChecks = ["EXP001", "RTL001", "INJ001"];

export async function scan(options: ScanOptions, onEvent: (e: ScanEvent) => void = () => {}): Promise<Report> {
  const startedAt = new Date().toISOString();
  const url = normalizeTarget(options.url);
  const signal = options.signal;

  const home = await safeFetch(url, { signal });
  // The checks only need headers. The start of the HTML is read for the tab icon, and the
  // rest is dropped so the socket is freed.
  const icon = await readIcon(home.response, home.finalUrl);

  const checks: CheckResult[] = [];
  for (const check of liveChecks) {
    signal?.throwIfAborted();
    onEvent({ type: "check:start", checkId: check.id });
    try {
      const findings = await check.run({ url, home, signal });
      checks.push({ checkId: check.id, ran: true, findings });
      onEvent({ type: "check:done", checkId: check.id, findings: findings.length, ran: true });
    } catch (err) {
      if (signal?.aborted) throw err;
      // One broken check should not sink the whole scan. Record why it did not run.
      checks.push({ checkId: check.id, ran: false, skippedReason: (err as Error).message, findings: [] });
      onEvent({ type: "check:done", checkId: check.id, findings: 0, ran: false });
    }
  }

  for (const id of plannedActiveChecks) {
    checks.push({
      checkId: id,
      ran: false,
      skippedReason: options.active ? "Not implemented yet." : "Needs ownership verification.",
      findings: [],
    });
  }

  const findings = checks.flatMap((c) => c.findings);
  const { score, grade } = scoreFindings(findings);

  return {
    target: url.origin,
    icon,
    startedAt,
    finishedAt: new Date().toISOString(),
    grade,
    score,
    checks,
    findings,
  };
}

async function readIcon(response: Response, pageUrl: URL): Promise<string> {
  const fallback = new URL("/favicon.ico", pageUrl).href;
  if (!response.headers.get("content-type")?.includes("html")) {
    await response.body?.cancel();
    return fallback;
  }
  try {
    // Icon links live in <head>, which is almost always inside the first 128 KB.
    return findIcon(await readLimited(response, 128 * 1024), pageUrl);
  } catch {
    return fallback;
  }
}
