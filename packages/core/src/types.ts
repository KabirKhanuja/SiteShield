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

/** A line and column inside a source file, for findings the code scan can point at. */
export type SourceLocation = {
  /** Path relative to the scanned source root. */
  file: string;
  line: number;
  column?: number;
  /** The offending line of code, trimmed, so the report can show it without opening the file. */
  snippet?: string;
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
  /** Free text location, for live findings (a URL) or a short description. */
  location?: string;
  /** Precise source position, set by the code scan. */
  source?: SourceLocation;
  /** OWASP Top 10 2021 category, for the pentest-style report. */
  owasp?: string;
  /** CWE identifier, for example CWE-798. */
  cwe?: string;
  /** CVSS 3.1 base score, 0-10, for risk rating. */
  cvss?: number;
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

/** How a finding changed between a baseline report and this one. */
export type DiffStatus = "fixed" | "open" | "new";

export type ReportDiff = {
  baselineGrade: Grade;
  baselineScore: number;
  fixed: Finding[];
  open: Finding[];
  introduced: Finding[];
};

export type Report = {
  target: string;
  /** The site's tab icon, found in the homepage HTML, or its /favicon.ico. */
  icon?: string;
  /** The deployed site that was scanned, if any. */
  url?: string;
  /** The source folder that was scanned, if any. */
  src?: string;
  /** Stacks detected (or forced) for remediation and routing. */
  stacks?: Stack[];
  startedAt: string;
  finishedAt: string;
  grade: Grade;
  score: number;
  checks: CheckResult[];
  findings: Finding[];
  /** Present when --baseline was given: what changed since that report. */
  diff?: ReportDiff;
};

export type ScanOptions = {
  /** Deployed site to scan. Leave out to scan only source. */
  url?: string;
  /** Folder to read source code from. Leave out to scan only the live site. */
  src?: string;
  /** Force the stack(s) used for remediation. Detected from the source otherwise. */
  stack?: Stack[];
  /** Run checks that send test traffic. Callers must verify ownership first. */
  active?: boolean;
  /** Run only these check IDs. */
  only?: string[];
  /** Skip these check IDs. */
  ignore?: string[];
  /** Skip the dependency check's network lookup to OSV.dev. */
  offline?: boolean;
  signal?: AbortSignal;
};

export type ScanEvent =
  | { type: "check:start"; checkId: string }
  | { type: "check:done"; checkId: string; findings: number; ran: boolean };
