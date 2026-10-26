import { bundleCheck } from "./checks/bundle.ts";
import { cookiesCheck } from "./checks/cookies.ts";
import { corsLiveCheck } from "./checks/cors.ts";
import { disclosureCheck } from "./checks/disclosure.ts";
import { dnsCheck } from "./checks/dns.ts";
import { headersCheck } from "./checks/headers.ts";
import { tlsCheck } from "./checks/tls.ts";
import type { Check } from "./checks/types.ts";
import { versionCheck } from "./checks/version.ts";
import { correlate } from "./correlate.ts";
import { readLimited, safeFetch } from "./http.ts";
import { findIcon } from "./icon.ts";
import { scoreFindings } from "./scoring.ts";
import { scanSource } from "./source/index.ts";
import { normalizeTarget } from "./target.ts";
import type { CheckResult, Finding, Report, ScanEvent, ScanOptions, Stack } from "./types.ts";

export const liveChecks: Check[] = [
  tlsCheck,
  headersCheck,
  cookiesCheck,
  dnsCheck,
  corsLiveCheck,
  bundleCheck,
  versionCheck,
  disclosureCheck,
];

/** Active checks that send test traffic. Listed so reports show them as skipped, not missing. */
const plannedActiveChecks = ["EXP001", "RTL001", "INJ001"];

const HOME_HTML_BYTES = 512 * 1024;

export async function scan(options: ScanOptions, onEvent: (e: ScanEvent) => void = () => {}): Promise<Report> {
  const startedAt = new Date().toISOString();
  const signal = options.signal;
  const wanted = (id: string) =>
    (!options.only || options.only.includes(id)) && !(options.ignore ?? []).includes(id);

  if (!options.url && !options.src) {
    throw new Error("Nothing to scan: pass a url, a src folder, or both.");
  }

  const checks: CheckResult[] = [];
  let icon: string | undefined;
  let origin: string | undefined;
  let stacks: Stack[] | undefined;

  // ---- Live scan ----
  if (options.url) {
    const url = normalizeTarget(options.url);
    origin = url.origin;

    const home = await safeFetch(url, { signal });
    const html = await readHomeHtml(home.response);
    icon = html !== undefined ? safeIcon(html, home.finalUrl) : new URL("/favicon.ico", home.finalUrl).href;

    for (const check of liveChecks) {
      if (!wanted(check.id)) {
        checks.push({ checkId: check.id, ran: false, skippedReason: "Excluded by --only/--ignore.", findings: [] });
        continue;
      }
      signal?.throwIfAborted();
      onEvent({ type: "check:start", checkId: check.id });
      try {
        const findings = await check.run({ url, home: { response: home.response, finalUrl: home.finalUrl }, html, signal });
        checks.push({ checkId: check.id, ran: true, findings });
        onEvent({ type: "check:done", checkId: check.id, findings: findings.length, ran: true });
      } catch (err) {
        if (signal?.aborted) throw err;
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
  }

  // ---- Source scan ----
  if (options.src) {
    const result = await scanSource({
      root: options.src,
      stack: options.stack,
      offline: options.offline,
      only: options.only,
      ignore: options.ignore,
      signal,
      onEvent: (e) =>
        onEvent(
          e.type === "check:done"
            ? { type: "check:done", checkId: e.checkId, findings: e.findings ?? 0, ran: true }
            : { type: "check:start", checkId: e.checkId },
        ),
    });
    stacks = result.stacks;
    for (const r of result.results) {
      checks.push({
        checkId: r.checkId,
        ran: r.ran,
        skippedReason: r.ran ? undefined : "Excluded by --only/--ignore.",
        findings: r.findings,
      });
    }
  }

  const findings: Finding[] = checks.flatMap((c) => c.findings);
  // Mark the findings that both layers agree on. Only meaningful when both ran.
  if (options.url && options.src) correlate(findings);

  const { score, grade } = scoreFindings(findings);

  return {
    target: origin ?? options.src ?? "source",
    icon,
    url: origin,
    src: options.src,
    stacks,
    startedAt,
    finishedAt: new Date().toISOString(),
    grade,
    score,
    checks,
    findings,
  };
}

/** Reads the homepage HTML (bounded) once, for the icon and the script-reading checks. */
async function readHomeHtml(response: import("undici").Response): Promise<string | undefined> {
  if (!response.headers.get("content-type")?.includes("html")) {
    await response.body?.cancel();
    return undefined;
  }
  try {
    return await readLimited(response, HOME_HTML_BYTES);
  } catch {
    return undefined;
  }
}

function safeIcon(html: string, pageUrl: URL): string {
  try {
    return findIcon(html, pageUrl);
  } catch {
    return new URL("/favicon.ico", pageUrl).href;
  }
}
