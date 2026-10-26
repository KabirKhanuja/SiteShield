#!/usr/bin/env -S node --import tsx
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { parseArgs } from "node:util";
import {
  checkOwnership,
  createVerificationToken,
  diffReports,
  domainOf,
  normalizeTarget,
  scan,
  verificationInstructions,
  type Report,
  type ScanEvent,
  type Severity,
  type Stack,
} from "@siteshield/core";
import { SEVERITY_RANK, checkName, formatJson, formatSarif, formatText } from "./format.ts";
import { formatHtml } from "./html.ts";

const VERSION = "0.1.0";
const STACKS = new Set<Stack>(["nextjs", "express", "nginx", "vercel"]);
const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

type Format = "text" | "json" | "sarif" | "html";

function fail(message: string): never {
  process.stderr.write(`siteshield: ${message}\n`);
  process.exit(1);
}

function help(): void {
  process.stdout.write(`SiteShield ${VERSION} - audit a live site and the code behind it.

Usage:
  siteshield scan [url] [options]     Scan a live site, source code, or both
  siteshield verify <domain>          Prove you own a domain (needed for active checks)

Options:
  --src <path>            Folder to read source code from (omit to skip the code scan)
  --stack <names>         Force stacks for fixes: nextjs,express,nginx,vercel
  --format <type>         text (default), json, sarif, or html
  --min-severity <level>  Hide findings below this level
  --fail-on <level>       Exit 2 if any finding is at or above this level (for CI)
  --only <ids>            Run only these check ids, e.g. --only HDR001,TLS001
  --ignore <ids>          Skip these check ids
  --baseline <file>       Compare with an earlier JSON report (what's fixed / still open / new)
  --offline               Skip the OSV.dev dependency lookup
  --passive               Never run active checks, even on a verified domain
  -h, --help              Show this help
  -v, --version           Show the version

Exit codes: 0 finished, 1 bad arguments or runtime error, 2 --fail-on threshold hit.
`);
}

type CliConfig = {
  url?: string;
  src?: string;
  stack?: string;
  format?: Format;
  failOn?: Severity;
  minSeverity?: Severity;
  only?: string[];
  ignore?: string[];
  baseline?: string;
  offline?: boolean;
  passive?: boolean;
};

function loadConfigFile(): CliConfig {
  const path = resolve(process.cwd(), "siteshield.config.json");
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, "utf8")) as CliConfig;
  } catch (err) {
    fail(`could not read siteshield.config.json: ${(err as Error).message}`);
  }
}

function asSeverity(value: string | undefined, flag: string): Severity | undefined {
  if (value === undefined) return undefined;
  if (!SEVERITIES.includes(value as Severity)) fail(`${flag} must be one of ${SEVERITIES.join(", ")}`);
  return value as Severity;
}

function asStacks(value: string | undefined): Stack[] | undefined {
  if (!value) return undefined;
  const list = value.split(",").map((s) => s.trim()).filter(Boolean);
  for (const s of list) if (!STACKS.has(s as Stack)) fail(`unknown stack "${s}". Use nextjs, express, nginx or vercel.`);
  return list as Stack[];
}

function ids(value: string | undefined): string[] | undefined {
  if (!value) return undefined;
  return value.split(",").map((s) => s.trim().toUpperCase()).filter(Boolean);
}

async function runScan(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      src: { type: "string" },
      stack: { type: "string" },
      format: { type: "string" },
      "min-severity": { type: "string" },
      "fail-on": { type: "string" },
      only: { type: "string" },
      ignore: { type: "string" },
      baseline: { type: "string" },
      offline: { type: "boolean" },
      passive: { type: "boolean" },
    },
  });

  const file = loadConfigFile();
  const url = positionals[0] ?? file.url;
  const src = values.src ?? file.src;
  if (!url && !src) fail("nothing to scan. Give a url, --src <path>, or both. See --help.");

  const format = (values.format ?? file.format ?? "text") as Format;
  if (!["text", "json", "sarif", "html"].includes(format)) fail(`--format must be text, json, sarif or html`);

  const failOn = asSeverity(values["fail-on"], "--fail-on") ?? file.failOn;
  const minSeverity = asSeverity(values["min-severity"], "--min-severity") ?? file.minSeverity;

  if (src && !existsSync(resolve(process.cwd(), src))) fail(`source folder not found: ${src}`);

  // Progress goes to stderr so stdout stays a clean report (important for --format json|sarif).
  const quiet = format !== "text" || !process.stderr.isTTY;
  const onEvent = (e: ScanEvent) => {
    if (quiet) return;
    if (e.type === "check:start") process.stderr.write(`  … ${checkName(e.checkId)}\r`);
    if (e.type === "check:done") process.stderr.write(`  ${e.ran ? "✓" : "–"} ${checkName(e.checkId)}${" ".repeat(20)}\n`);
  };

  let report: Report;
  try {
    report = await scan(
      {
        url,
        src: src ? resolve(process.cwd(), src) : undefined,
        stack: asStacks(values.stack ?? file.stack),
        offline: values.offline ?? file.offline,
        only: ids(values.only) ?? file.only,
        ignore: ids(values.ignore) ?? file.ignore,
        signal: AbortSignal.timeout(120_000),
      },
      onEvent,
    );
  } catch (err) {
    fail((err as Error).message);
  }

  // Baseline comparison.
  const baselinePath = values.baseline ?? file.baseline;
  if (baselinePath) {
    try {
      const baseline = JSON.parse(readFileSync(resolve(process.cwd(), baselinePath), "utf8")) as Report;
      report.diff = diffReports(report, baseline);
    } catch (err) {
      process.stderr.write(`siteshield: could not read baseline ${baselinePath}: ${(err as Error).message}\n`);
    }
  }

  // --min-severity hides lower findings from the output, but the grade still reflects them all.
  if (minSeverity) {
    const floor = SEVERITY_RANK[minSeverity];
    report = { ...report, findings: report.findings.filter((f) => SEVERITY_RANK[f.severity] >= floor) };
  }

  const rendered =
    format === "json" ? formatJson(report) : format === "sarif" ? formatSarif(report) : format === "html" ? formatHtml(report) : formatText(report);
  process.stdout.write(rendered + "\n");

  // --fail-on: exit 2 when something at or above the threshold exists (CI gate).
  if (failOn) {
    const floor = SEVERITY_RANK[failOn];
    const hit = report.findings.some((f) => SEVERITY_RANK[f.severity] >= floor);
    if (hit) {
      process.stderr.write(`\nsiteshield: found findings at or above ${failOn}. Failing (exit 2).\n`);
      process.exit(2);
    }
  }
}

// ---- verify ----

type VerifyStore = Record<string, { token: string; verifiedAt?: string; expiresAt?: string }>;
const STORE_PATH = resolve(process.cwd(), ".siteshield", "verifications.json");

function loadStore(): VerifyStore {
  if (!existsSync(STORE_PATH)) return {};
  try {
    return JSON.parse(readFileSync(STORE_PATH, "utf8")) as VerifyStore;
  } catch {
    return {};
  }
}

function saveStore(store: VerifyStore): void {
  mkdirSync(dirname(STORE_PATH), { recursive: true });
  writeFileSync(STORE_PATH, JSON.stringify(store, null, 2));
}

async function runVerify(args: string[]): Promise<void> {
  const { positionals } = parseArgs({ args, allowPositionals: true, options: {} });
  const input = positionals[0];
  if (!input) fail("usage: siteshield verify <domain>");

  const domain = domainOf(normalizeTarget(input));
  const store = loadStore();
  const existing = store[domain];

  if (!existing) {
    const token = createVerificationToken();
    store[domain] = { token };
    saveStore(store);
    const inst = verificationInstructions(domain, token);
    process.stdout.write(`\nAdd ONE of these, then run "siteshield verify ${domain}" again:\n\n`);
    process.stdout.write(`  DNS   ${inst.dns.name}  ${inst.dns.type}  "${inst.dns.value}"\n`);
    process.stdout.write(`  HTTP  ${inst.http.url}  containing  ${token}\n\n`);
    return;
  }

  if (existing.expiresAt && existing.expiresAt > new Date().toISOString()) {
    process.stdout.write(`${domain} is already verified until ${existing.expiresAt}.\n`);
    return;
  }

  process.stderr.write(`Checking ${domain}…\n`);
  const result = await checkOwnership(domain, existing.token, AbortSignal.timeout(20_000));
  if (!result.verified) {
    process.stderr.write(`\nNot verified yet: ${result.reason}\n`);
    process.exit(1);
  }
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  store[domain] = { ...existing, verifiedAt: new Date().toISOString(), expiresAt };
  saveStore(store);
  process.stdout.write(`\n✓ Verified ${domain} by ${result.method.toUpperCase()}. Valid until ${expiresAt}.\n`);
}

async function main(): Promise<void> {
  const [, , command, ...rest] = process.argv;

  if (command === "-h" || command === "--help" || command === undefined) return help();
  if (command === "-v" || command === "--version") return void process.stdout.write(VERSION + "\n");
  if (command === "scan") return runScan(rest);
  if (command === "verify") return runVerify(rest);

  fail(`unknown command "${command}". Try: siteshield scan, siteshield verify, or siteshield --help.`);
}

main().catch((err) => fail(err instanceof Error ? err.message : String(err)));
