import type { Finding, Report, Severity } from "@siteshield/core";

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const STATUS_LABEL: Record<Finding["status"], string> = {
  confirmed: "CONFIRMED",
  code: "code",
  live: "live",
};

// Human-friendly names for each check id, for the text report headings.
const CHECK_NAMES: Record<string, string> = {
  TLS001: "Certificate and TLS",
  HDR001: "Security headers",
  CKE001: "Cookie flags",
  DNS001: "Email authentication",
  COR001: "Live CORS policy",
  BND001: "Secrets in shipped JavaScript",
  VER001: "Outdated software",
  DSC001: "Responsible disclosure (security.txt)",
  EXP001: "Exposed files",
  RTL001: "Rate limiting",
  INJ001: "Injection surface",
  SEC001: "Hardcoded secrets",
  PUB001: "Secrets in public env vars",
  DEP001: "Vulnerable dependencies",
  AUT001: "Routes with no auth check",
  RTL002: "Auth routes with no limiter",
  COR002: "Permissive CORS config",
  INJ002: "Untrusted input in dangerous calls",
  XSS001: "Unsafe HTML sinks",
  CFG001: "Unsafe settings",
};

export function checkName(id: string): string {
  return CHECK_NAMES[id] ?? id;
}

const COLOR = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string, s: string) => (COLOR ? `\x1b[${code}m${s}\x1b[0m` : s);
const dim = (s: string) => c("2", s);
const bold = (s: string) => c("1", s);

function sevTag(sev: Severity): string {
  const label = sev.toUpperCase().padEnd(8);
  if (!COLOR) return label;
  const code = sev === "critical" ? "1;41" : sev === "high" ? "31" : sev === "medium" ? "33" : sev === "low" ? "36" : "2";
  return c(code, label);
}

function gradeColor(grade: string): string {
  const code = grade === "A" ? "32" : grade === "B" ? "32" : grade === "C" ? "33" : grade === "D" ? "33" : "31";
  return c("1;" + code, grade);
}

/** The default human-readable report. */
export function formatText(report: Report): string {
  const out: string[] = [];
  const sorted = [...report.findings].sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      (b.status === "confirmed" ? 1 : 0) - (a.status === "confirmed" ? 1 : 0),
  );

  out.push("");
  out.push(`  ${bold("SiteShield report")}  ${dim(report.target)}`);
  if (report.stacks?.length) out.push(`  ${dim("stack: " + report.stacks.join(", "))}`);
  out.push("");

  const counts = countBySeverity(report.findings);
  out.push(
    `  Grade ${gradeColor(report.grade)}  (${report.score}/100)   ` +
      `${counts.critical} critical · ${counts.high} high · ${counts.medium} medium · ${counts.low} low · ${counts.info} info`,
  );
  const confirmed = report.findings.filter((f) => f.status === "confirmed").length;
  if (confirmed) out.push(`  ${bold(c("31", String(confirmed) + " confirmed"))} (found in both the code and the live site)`);
  out.push("");

  if (sorted.length === 0) {
    out.push("  No findings. Nice.");
  }

  for (const f of sorted) {
    const status = f.status === "confirmed" ? bold(c("31", "[CONFIRMED]")) : dim(`[${STATUS_LABEL[f.status]}]`);
    out.push(`  ${sevTag(f.severity)} ${status} ${bold(f.title)}`);
    out.push(`           ${dim(f.checkId + (f.cvss ? ` · CVSS ${f.cvss}` : "") + (f.owasp ? " · " + f.owasp : ""))}`);
    if (f.location) out.push(`           ${dim("at " + f.location)}`);
    out.push(wrap(f.detail, "           "));
    if (f.source?.snippet) out.push(`           ${dim("> " + f.source.snippet)}`);
    const fix = f.remediation[0];
    if (fix) {
      out.push(`           ${c("32", "fix")} ${fix.summary}`);
      if (fix.code) for (const line of fix.code.split("\n")) out.push(`               ${dim(line)}`);
    }
    out.push("");
  }

  if (report.diff) {
    out.push(dim("  ─────────────────────────────────────────────"));
    out.push(`  ${bold("Compared with baseline")} (was grade ${report.diff.baselineGrade}, ${report.diff.baselineScore}/100)`);
    out.push(`  ${c("32", "fixed " + report.diff.fixed.length)} · still open ${report.diff.open.length} · ${c("31", "new " + report.diff.introduced.length)}`);
    for (const f of report.diff.fixed) out.push(`    ${c("32", "✓ fixed")} ${f.title}`);
    for (const f of report.diff.introduced) out.push(`    ${c("31", "✗ new")}   ${f.title}`);
    out.push("");
  }

  const skipped = report.checks.filter((ch) => !ch.ran);
  if (skipped.length) {
    out.push(dim(`  Not run: ${skipped.map((s) => `${s.checkId} (${s.skippedReason ?? "skipped"})`).join(", ")}`));
    out.push("");
  }

  return out.join("\n");
}

function countBySeverity(findings: Finding[]) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

function wrap(text: string, indent: string, width = 76): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = indent;
  for (const w of words) {
    if (line.length + w.length + 1 > indent.length + width && line !== indent) {
      lines.push(line);
      line = indent + w;
    } else {
      line += (line === indent ? "" : " ") + w;
    }
  }
  lines.push(line);
  return lines.join("\n");
}

/** The report as JSON, for scripts and for use as a baseline later. */
export function formatJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}

/** SARIF 2.1.0, so findings show up in GitHub code scanning. */
export function formatSarif(report: Report): string {
  const levelOf = (s: Severity) => (s === "critical" || s === "high" ? "error" : s === "medium" ? "warning" : "note");
  const ruleIds = [...new Set(report.findings.map((f) => f.checkId))];

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "SiteShield",
            version: "0.1.0",
            informationUri: "https://github.com/KabirKhanuja/SiteShield",
            rules: ruleIds.map((id) => ({
              id,
              name: checkName(id),
              shortDescription: { text: checkName(id) },
            })),
          },
        },
        results: report.findings.map((f) => ({
          ruleId: f.checkId,
          level: levelOf(f.severity),
          message: { text: `${f.title}. ${f.detail}` },
          properties: {
            severity: f.severity,
            status: f.status,
            ...(f.cvss ? { cvss: f.cvss } : {}),
            ...(f.cwe ? { cwe: f.cwe } : {}),
            ...(f.owasp ? { owasp: f.owasp } : {}),
          },
          locations: f.source
            ? [
                {
                  physicalLocation: {
                    artifactLocation: { uri: f.source.file },
                    region: { startLine: f.source.line, ...(f.source.column ? { startColumn: f.source.column } : {}) },
                  },
                },
              ]
            : f.location
              ? [{ physicalLocation: { artifactLocation: { uri: f.location } } }]
              : [],
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
