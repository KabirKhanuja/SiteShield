import type { Finding, Stack } from "../types.ts";
import { authCheck } from "./checks/auth.ts";
import { configCheck } from "./checks/config.ts";
import { corsCheck } from "./checks/cors.ts";
import { depsCheck } from "./checks/deps.ts";
import { injectionCheck } from "./checks/injection.ts";
import { publicEnvCheck } from "./checks/public-env.ts";
import { rateLimitCheck } from "./checks/rate-limit.ts";
import { secretsCheck } from "./checks/secrets.ts";
import { xssCheck } from "./checks/xss.ts";
import { detectStacks } from "./stack.ts";
import { forStacks, type PackageJson, type SourceCheck, type SourceContext } from "./types.ts";
import { walkSource } from "./walk.ts";

export const sourceChecks: SourceCheck[] = [
  secretsCheck,
  publicEnvCheck,
  depsCheck,
  authCheck,
  rateLimitCheck,
  corsCheck,
  injectionCheck,
  xssCheck,
  configCheck,
];

export type SourceScanResult = {
  stacks: Stack[];
  findings: Finding[];
  fileCount: number;
  /** Per-check outcome, so the report can show which ran and what each found. */
  results: { checkId: string; ran: boolean; findings: Finding[] }[];
};

export type SourceScanOptions = {
  root: string;
  stack?: Stack[];
  offline?: boolean;
  only?: string[];
  ignore?: string[];
  signal?: AbortSignal;
  onEvent?: (e: { type: "check:start" | "check:done"; checkId: string; findings?: number }) => void;
};

function parsePackages(files: SourceContext["files"]): PackageJson[] {
  const out: PackageJson[] = [];
  for (const file of files) {
    if (!/(^|\/)package\.json$/.test(file.path)) continue;
    try {
      out.push({ path: file.path, data: JSON.parse(file.content) });
    } catch {
      // Skip a package.json we cannot parse.
    }
  }
  return out;
}

/** Reads a source tree once and runs every source check against it. */
export async function scanSource(options: SourceScanOptions): Promise<SourceScanResult> {
  const files = walkSource(options.root);
  const packages = parsePackages(files);
  const stacks = options.stack?.length ? options.stack : detectStacks(files, packages);

  const ctx: SourceContext = {
    root: options.root,
    files,
    packages,
    stacks,
    offline: options.offline ?? false,
    signal: options.signal,
  };

  const wanted = (id: string) =>
    (!options.only || options.only.includes(id)) && !(options.ignore ?? []).includes(id);

  const results: SourceScanResult["results"] = [];
  const findings: Finding[] = [];

  for (const check of sourceChecks) {
    if (!wanted(check.id)) {
      results.push({ checkId: check.id, ran: false, findings: [] });
      continue;
    }
    options.signal?.throwIfAborted();
    options.onEvent?.({ type: "check:start", checkId: check.id });
    const raw = await check.run(ctx);
    // Keep only the remediation that fits the detected stacks, so a Next.js project does
    // not see nginx snippets.
    const scoped = raw.map((f) => ({ ...f, remediation: forStacks(f.remediation, stacks) }));
    results.push({ checkId: check.id, ran: true, findings: scoped });
    findings.push(...scoped);
    options.onEvent?.({ type: "check:done", checkId: check.id, findings: scoped.length });
  }

  return { stacks, findings, fileCount: files.length, results };
}
