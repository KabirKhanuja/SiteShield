import type { Finding, Severity } from "../../types.ts";
import { codeFinding, type PackageJson, type SourceCheck, type SourceFile } from "../types.ts";

/**
 * DEP001 - dependencies with a published advisory. Versions come from the lockfile when
 * there is one (exact), or from package.json ranges otherwise (approximate). They are
 * looked up in a single batch call to OSV.dev, the free public advisory database.
 */

const OSV_BATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN = "https://api.osv.dev/v1/vulns/";
const MAX_DETAIL_LOOKUPS = 40; // Enough for a real project, bounded so a huge tree cannot stall.

type Dep = { name: string; version: string };

type OsvSeverity = { type: string; score: string };
type OsvVuln = {
  id: string;
  summary?: string;
  aliases?: string[];
  severity?: OsvSeverity[];
  database_specific?: { severity?: string };
};

function parseLockfile(file: SourceFile): Dep[] {
  const deps: Dep[] = [];
  try {
    const data = JSON.parse(file.content) as {
      packages?: Record<string, { version?: string }>;
      dependencies?: Record<string, { version?: string }>;
    };
    // npm lockfile v2/v3: keys like "node_modules/react" or "node_modules/a/node_modules/b".
    if (data.packages) {
      for (const [key, info] of Object.entries(data.packages)) {
        if (!key || !info.version) continue;
        const name = key.split("node_modules/").pop();
        if (name) deps.push({ name, version: info.version });
      }
    }
    // npm lockfile v1.
    if (data.dependencies) {
      const walk = (tree: Record<string, { version?: string; dependencies?: Record<string, unknown> }>) => {
        for (const [name, info] of Object.entries(tree)) {
          if (info.version) deps.push({ name, version: info.version });
          if (info.dependencies) walk(info.dependencies as never);
        }
      };
      walk(data.dependencies as never);
    }
  } catch {
    // A malformed lockfile: nothing to scan here.
  }
  return deps;
}

function depsFromPackageJson(pkg: PackageJson): Dep[] {
  const out: Dep[] = [];
  for (const [name, range] of Object.entries({ ...pkg.data.dependencies, ...pkg.data.devDependencies })) {
    // Strip range operators to a plain version. Imperfect, but OSV matches it against the
    // affected ranges, so "^4.17.20" becomes "4.17.20" and still catches a known-bad pin.
    const version = String(range).replace(/^[\^~>=<\s]+/, "").split(/\s|\|\|/)[0] ?? "";
    if (/^\d+\.\d+/.test(version)) out.push({ name, version });
  }
  return out;
}

function severityFrom(vuln: OsvVuln): Severity {
  const label = vuln.database_specific?.severity?.toUpperCase();
  if (label === "CRITICAL") return "critical";
  if (label === "HIGH") return "high";
  if (label === "MODERATE" || label === "MEDIUM") return "medium";
  if (label === "LOW") return "low";
  // Fall back to the CVSS vector if there is one.
  const cvss = cvssScore(vuln);
  if (cvss >= 9) return "critical";
  if (cvss >= 7) return "high";
  if (cvss >= 4) return "medium";
  if (cvss > 0) return "low";
  return "medium";
}

function cvssScore(vuln: OsvVuln): number {
  for (const s of vuln.severity ?? []) {
    // OSV stores the vector string; the base score is not always separate. Pull a number
    // if the string is already a score, otherwise leave it to the label.
    const n = Number(s.score);
    if (!Number.isNaN(n)) return n;
  }
  return 0;
}

export const depsCheck: SourceCheck = {
  id: "DEP001",
  async run({ files, packages, offline, signal }) {
    const lockfiles = files.filter((f) => /(^|\/)package-lock\.json$/.test(f.path));

    // One entry per name+version, from the lockfile if present, else package.json ranges.
    const unique = new Map<string, Dep>();
    const source = lockfiles.length > 0 ? lockfiles.flatMap(parseLockfile) : packages.flatMap(depsFromPackageJson);
    for (const d of source) {
      if (d.name && d.version) unique.set(`${d.name}@${d.version}`, d);
    }
    const deps = [...unique.values()];
    if (deps.length === 0) return [];

    if (offline) {
      return [
        codeFinding({
          checkId: "DEP001",
          severity: "info",
          status: "code",
          title: "Dependency check skipped (offline)",
          detail: `Found ${deps.length} dependency versions but did not look them up because the scan was run offline. Run without --offline to check them against OSV.dev.`,
          location: lockfiles[0]?.path ?? packages[0]?.path,
          remediation: [{ stack: "any", summary: "Run the scan with network access, or run npm audit." }],
        }),
      ];
    }

    let results: { vulns?: { id: string }[] }[];
    try {
      const res = await fetch(OSV_BATCH, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ queries: deps.map((d) => ({ package: { name: d.name, ecosystem: "npm" }, version: d.version })) }),
        signal: signal ?? AbortSignal.timeout(20_000),
      });
      if (!res.ok) throw new Error(`OSV responded ${res.status}`);
      results = ((await res.json()) as { results?: { vulns?: { id: string }[] }[] }).results ?? [];
    } catch (err) {
      return [
        codeFinding({
          checkId: "DEP001",
          severity: "info",
          status: "code",
          title: "Could not reach OSV.dev",
          detail: `The dependency lookup failed (${(err as Error).message}). Dependencies were not checked this run. Try again, or run npm audit.`,
          location: lockfiles[0]?.path ?? packages[0]?.path,
          remediation: [{ stack: "any", summary: "Re-run with network access, or use npm audit as a fallback." }],
        }),
      ];
    }

    // Collect the advisory ids, then fetch details for a bounded number of them so we can
    // report a real severity and summary rather than just an id.
    const vulnerable: { dep: Dep; ids: string[] }[] = [];
    const idSet = new Set<string>();
    results.forEach((r, i) => {
      if (r.vulns && r.vulns.length > 0) {
        const ids = r.vulns.map((v) => v.id);
        vulnerable.push({ dep: deps[i]!, ids });
        for (const id of ids) idSet.add(id);
      }
    });
    if (vulnerable.length === 0) return [];

    const details = new Map<string, OsvVuln>();
    const toFetch = [...idSet].slice(0, MAX_DETAIL_LOOKUPS);
    await Promise.all(
      toFetch.map(async (id) => {
        try {
          const res = await fetch(OSV_VULN + id, { signal: signal ?? AbortSignal.timeout(15_000) });
          if (res.ok) details.set(id, (await res.json()) as OsvVuln);
        } catch {
          // Leave it out of the details map; the id still gets reported.
        }
      }),
    );

    const findings: Finding[] = [];
    const lockPath = lockfiles[0]?.path ?? packages[0]?.path ?? "package.json";
    for (const { dep, ids } of vulnerable) {
      const vulns = ids.map((id) => details.get(id)).filter((v): v is OsvVuln => Boolean(v));
      const severity = vulns.length > 0 ? worst(vulns.map(severityFrom)) : "medium";
      const cve = vulns.flatMap((v) => v.aliases ?? []).find((a) => a.startsWith("CVE-"));
      const summary = vulns[0]?.summary;
      const cvss = Math.max(0, ...vulns.map(cvssScore));

      findings.push(
        codeFinding({
          checkId: "DEP001",
          severity,
          status: "code",
          title: `${dep.name}@${dep.version} has ${ids.length} known ${ids.length === 1 ? "advisory" : "advisories"}`,
          detail: summary
            ? `${summary} (${ids.slice(0, 5).join(", ")}${ids.length > 5 ? ", …" : ""})`
            : `Advisories: ${ids.slice(0, 5).join(", ")}${ids.length > 5 ? ", …" : ""}. See the OSV links for details.`,
          evidence: (cve ? `${cve} · ` : "") + ids.slice(0, 3).join(", "),
          location: lockPath,
          cwe: "CWE-1035",
          owasp: "A06:2021 Vulnerable and Outdated Components",
          cvss: cvss > 0 ? cvss : undefined,
          remediation: [
            {
              stack: "any",
              summary: `Upgrade ${dep.name} to a version without the advisory, then re-run npm install.`,
              code: `npm install ${dep.name}@latest`,
            },
          ],
        }),
      );
    }

    return findings;
  },
};

function worst(severities: Severity[]): Severity {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  return order.find((s) => severities.includes(s)) ?? "medium";
}
