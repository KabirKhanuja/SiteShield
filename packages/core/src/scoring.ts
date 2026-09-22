import type { Finding, Grade, Severity } from "./types.ts";

// Kept in sync with the "How the grade works" section of the docs site.
export const SEVERITY_POINTS: Record<Severity, number> = {
  critical: 25,
  high: 12,
  medium: 5,
  low: 1,
  info: 0,
};
export const CONFIRMED_MULTIPLIER = 1.5;

export function scoreFindings(findings: Finding[]): { score: number; grade: Grade } {
  const lost = findings.reduce(
    (sum, f) => sum + SEVERITY_POINTS[f.severity] * (f.status === "confirmed" ? CONFIRMED_MULTIPLIER : 1),
    0,
  );
  const score = Math.max(0, Math.round(100 - lost));
  let grade: Grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  // A site leaking a live secret should never show a B, however clean the rest is.
  const confirmedCritical = findings.some((f) => f.status === "confirmed" && f.severity === "critical");
  if (confirmedCritical && (grade === "A" || grade === "B" || grade === "C")) grade = "D";

  return { score, grade };
}
