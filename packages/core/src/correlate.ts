import type { Finding, Report, ReportDiff } from "./types.ts";

/**
 * Confirmed findings are the heart of what SiteShield does differently: when the live scan
 * and the source scan independently find the same problem, we know it is real and deployed,
 * not a maybe. These pairs mirror the pairsWith relationships shown in the docs.
 */
const PAIRS: { live: string; source: string }[] = [
  { live: "BND001", source: "SEC001" }, // a secret shipped in JS that is also hardcoded
  { live: "BND001", source: "PUB001" }, // a secret shipped in JS that is also a public env var
  { live: "VER001", source: "DEP001" }, // a vulnerable library both served and in the lockfile
  { live: "COR001", source: "COR002" }, // permissive CORS seen live and set in code
];

const MASK = /[A-Za-z0-9]{4}…[A-Za-z0-9]{2}/;
const VERSION = /\b\d+\.\d+(?:\.\d+)?\b/g;

function tokens(f: Finding): { masks: Set<string>; versions: Set<string> } {
  const text = `${f.title} ${f.detail} ${f.evidence ?? ""}`;
  const masks = new Set((text.match(new RegExp(MASK, "g")) ?? []));
  const versions = new Set((text.match(VERSION) ?? []));
  return { masks, versions };
}

function sameSubject(live: Finding, source: Finding): boolean {
  // CORS has no identifier to match on: both sides describing a permissive policy is enough.
  if (live.checkId === "COR001") return true;

  const a = tokens(live);
  const b = tokens(source);
  for (const m of a.masks) if (b.masks.has(m)) return true; // same masked secret
  for (const v of a.versions) if (b.versions.has(v)) return true; // same version string
  return false;
}

/**
 * Marks a live and a source finding confirmed when they describe the same problem. Mutates
 * the findings in place, so the change shows everywhere they are referenced.
 */
export function correlate(findings: Finding[]): void {
  const live = findings.filter((f) => f.layer === "live");
  const source = findings.filter((f) => f.layer === "source");

  for (const { live: liveId, source: sourceId } of PAIRS) {
    for (const l of live.filter((f) => f.checkId === liveId)) {
      for (const s of source.filter((f) => f.checkId === sourceId)) {
        if (sameSubject(l, s)) {
          l.status = "confirmed";
          s.status = "confirmed";
        }
      }
    }
  }
}

/**
 * A stable identity for a finding across two scans, so a re-scan can tell which findings are
 * fixed, still open or new. Deliberately coarse: same check, same place, same title.
 */
export function fingerprint(f: Finding): string {
  const place = f.source ? `${f.source.file}:${f.source.line}` : f.location ?? "";
  return `${f.checkId}|${place}|${f.title}`;
}

/** Compares this report against an earlier one and reports what changed. */
export function diffReports(current: Report, baseline: Report): ReportDiff {
  const now = new Map(current.findings.map((f) => [fingerprint(f), f]));
  const before = new Map(baseline.findings.map((f) => [fingerprint(f), f]));

  const fixed = [...before.values()].filter((f) => !now.has(fingerprint(f)));
  const introduced = [...now.values()].filter((f) => !before.has(fingerprint(f)));
  const open = [...now.values()].filter((f) => before.has(fingerprint(f)));

  return {
    baselineGrade: baseline.grade,
    baselineScore: baseline.score,
    fixed,
    open,
    introduced,
  };
}
