import type { Finding, Report, Severity } from "@siteshield/core";
import { SEVERITY_RANK, checkName } from "./format.ts";

/**
 * A self-contained HTML report in the shape of a penetration-testing write-up: an executive
 * summary, a risk breakdown, and one entry per finding with its CVSS, OWASP category, CWE,
 * evidence and remediation. Opens in any browser and prints to PDF, which is what the
 * syllabus asks for in Unit V (report writing with executive summary, risk rating, remediation).
 */

function esc(s: string): string {
  return s.replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[ch]!);
}

const SEV_COLOR: Record<Severity, string> = {
  critical: "#b91c1c",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#0891b2",
  info: "#64748b",
};

function countBySeverity(findings: Finding[]) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

function findingRow(f: Finding): string {
  const badges = [
    `<span class="sev" style="background:${SEV_COLOR[f.severity]}">${f.severity.toUpperCase()}</span>`,
    f.status === "confirmed" ? `<span class="confirmed">CONFIRMED</span>` : `<span class="status">${f.status}</span>`,
    f.cvss ? `<span class="meta">CVSS ${f.cvss}</span>` : "",
    f.cwe ? `<span class="meta">${esc(f.cwe)}</span>` : "",
    f.owasp ? `<span class="meta">${esc(f.owasp)}</span>` : "",
  ].join(" ");

  const fix = f.remediation[0];
  return `
    <article class="finding">
      <div class="badges">${badges}</div>
      <h3>${esc(f.title)}</h3>
      <p class="checkid">${esc(f.checkId)} · ${esc(checkName(f.checkId))}${f.location ? " · " + esc(f.location) : ""}</p>
      <p>${esc(f.detail)}</p>
      ${f.evidence ? `<pre class="evidence">${esc(f.evidence)}</pre>` : ""}
      ${f.source?.snippet ? `<pre class="evidence">${esc(f.source.snippet)}</pre>` : ""}
      ${
        fix
          ? `<div class="fix"><strong>Remediation${fix.stack !== "any" ? " (" + esc(fix.stack) + ")" : ""}:</strong> ${esc(fix.summary)}${fix.code ? `<pre>${esc(fix.code)}</pre>` : ""}</div>`
          : ""
      }
    </article>`;
}

export function formatHtml(report: Report): string {
  const counts = countBySeverity(report.findings);
  const confirmed = report.findings.filter((f) => f.status === "confirmed");
  const sorted = [...report.findings].sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      (b.status === "confirmed" ? 1 : 0) - (a.status === "confirmed" ? 1 : 0),
  );
  const total = report.findings.length;

  const summary =
    total === 0
      ? "No findings were identified in this scan."
      : `The scan identified ${total} finding${total === 1 ? "" : "s"}: ` +
        `${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low and ${counts.info} informational. ` +
        (confirmed.length
          ? `${confirmed.length} ${confirmed.length === 1 ? "was" : "were"} confirmed across both the live site and the source code, and should be remediated first. `
          : "") +
        `The overall security posture is rated ${report.grade} (${report.score}/100).`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SiteShield Security Report — ${esc(report.target)}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font: 15px/1.6 -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; color: #0f172a; background: #f8fafc; margin: 0; padding: 0 16px; }
  main { max-width: 820px; margin: 0 auto; padding: 48px 0; }
  h1 { font-size: 28px; margin: 0 0 4px; }
  h2 { font-size: 20px; margin: 40px 0 12px; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; }
  h3 { font-size: 17px; margin: 0 0 4px; }
  .sub { color: #64748b; margin: 0 0 24px; }
  .grade { display: inline-flex; align-items: center; gap: 16px; background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px 28px; margin: 8px 0; }
  .grade .letter { font-size: 56px; font-weight: 700; line-height: 1; }
  .risk { display: flex; flex-wrap: wrap; gap: 8px; margin: 16px 0; }
  .risk span { padding: 4px 12px; border-radius: 999px; color: #fff; font-size: 13px; font-weight: 600; }
  .finding { background: #fff; border: 1px solid #e2e8f0; border-left-width: 4px; border-radius: 10px; padding: 18px 20px; margin: 14px 0; }
  .badges { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 8px; }
  .sev, .confirmed, .status, .meta { font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px; color: #fff; letter-spacing: .03em; }
  .confirmed { background: #991b1b; }
  .status { background: #94a3b8; text-transform: uppercase; }
  .meta { background: #e2e8f0; color: #334155; font-weight: 600; }
  .checkid { color: #64748b; font-size: 13px; margin: 0 0 8px; font-family: ui-monospace, Menlo, monospace; }
  pre { background: #f1f5f9; border-radius: 6px; padding: 10px 12px; overflow-x: auto; font-size: 13px; font-family: ui-monospace, Menlo, monospace; white-space: pre-wrap; word-break: break-word; }
  .evidence { background: #fef2f2; }
  .fix { background: #f0fdf4; border-radius: 6px; padding: 10px 12px; margin-top: 10px; font-size: 14px; }
  .fix pre { background: #dcfce7; margin: 8px 0 0; }
  footer { color: #94a3b8; font-size: 12px; margin-top: 48px; text-align: center; }
  @media print { body { background: #fff; } .finding, .grade { break-inside: avoid; } }
</style>
</head>
<body>
<main>
  <h1>SiteShield Security Report</h1>
  <p class="sub">${esc(report.target)} · generated ${esc(new Date(report.finishedAt).toLocaleString())}${report.stacks?.length ? " · " + esc(report.stacks.join(", ")) : ""}</p>

  <div class="grade">
    <div class="letter" style="color:${report.grade === "A" || report.grade === "B" ? "#16a34a" : report.grade === "C" || report.grade === "D" ? "#ca8a04" : "#b91c1c"}">${report.grade}</div>
    <div><div style="font-size:24px;font-weight:700">${report.score}/100</div><div style="color:#64748b">overall security score</div></div>
  </div>

  <h2>Executive summary</h2>
  <p>${esc(summary)}</p>
  <div class="risk">
    <span style="background:${SEV_COLOR.critical}">Critical ${counts.critical}</span>
    <span style="background:${SEV_COLOR.high}">High ${counts.high}</span>
    <span style="background:${SEV_COLOR.medium}">Medium ${counts.medium}</span>
    <span style="background:${SEV_COLOR.low}">Low ${counts.low}</span>
    <span style="background:${SEV_COLOR.info}">Info ${counts.info}</span>
  </div>

  <h2>Findings</h2>
  ${sorted.length ? sorted.map(findingRow).join("\n") : "<p>No findings.</p>"}

  ${
    report.diff
      ? `<h2>Change since baseline</h2>
         <p>Baseline grade ${report.diff.baselineGrade} (${report.diff.baselineScore}/100). Fixed: ${report.diff.fixed.length}, still open: ${report.diff.open.length}, new: ${report.diff.introduced.length}.</p>`
      : ""
  }

  <footer>Generated by SiteShield ${esc(new Date().getFullYear().toString())}. For authorised security testing only.</footer>
</main>
</body>
</html>`;
}
