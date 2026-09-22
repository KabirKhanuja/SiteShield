export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Layer = "live" | "source";

/**
 * confirmed: the code scan and the live scan found the same problem.
 * code: found only in source. live: found only on the deployed site.
 */
export type FindingStatus = "confirmed" | "code" | "live";

export type Stack = "nextjs" | "express" | "nginx" | "vercel";

export type Remediation = {
  stack: Stack | "any";
  summary: string;
  file?: string;
  code?: string;
};

export type Finding = {
  checkId: string;
  layer: Layer;
  severity: Severity;
  status: FindingStatus;
  title: string;
  detail: string;
  /** What we actually observed: a header value, a DNS record, a file and line. */
  evidence?: string;
  location?: string;
  remediation: Remediation[];
};

export type CheckResult = {
  checkId: string;
  ran: boolean;
  /** Why a check did not run, for example "needs ownership verification". */
  skippedReason?: string;
  findings: Finding[];
};

export type Grade = "A" | "B" | "C" | "D" | "F";

export type Report = {
  target: string;
  /** The site's tab icon, found in the homepage HTML, or its /favicon.ico. */
  icon?: string;
  startedAt: string;
  finishedAt: string;
  grade: Grade;
  score: number;
  checks: CheckResult[];
  findings: Finding[];
};

export type ScanOptions = {
  url: string;
  /** Run checks that send test traffic. Callers must verify ownership first. */
  active?: boolean;
  signal?: AbortSignal;
};

export type ScanEvent =
  | { type: "check:start"; checkId: string }
  | { type: "check:done"; checkId: string; findings: number; ran: boolean };
