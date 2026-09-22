// Mirrors the report shape from packages/core. Kept as a copy so the website does not
// have to compile the engine's source.

export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000").replace(/\/$/, "");

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Grade = "A" | "B" | "C" | "D" | "F";

export type Remediation = {
  stack: "nextjs" | "express" | "nginx" | "vercel" | "any";
  summary: string;
  file?: string;
  code?: string;
};

export type Finding = {
  checkId: string;
  layer: "live" | "source";
  severity: Severity;
  status: "confirmed" | "code" | "live";
  title: string;
  detail: string;
  evidence?: string;
  remediation: Remediation[];
};

export type CheckResult = { checkId: string; ran: boolean; skippedReason?: string; findings: Finding[] };

export type Report = {
  target: string;
  startedAt: string;
  finishedAt: string;
  grade: Grade;
  score: number;
  checks: CheckResult[];
  findings: Finding[];
};

export type Scan = {
  id: string;
  target: string;
  status: "queued" | "running" | "done" | "failed";
  createdAt: string;
  error: string | null;
  report: Report | null;
};

export class ApiError extends Error {}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, init);
  } catch {
    throw new ApiError("Could not reach the SiteShield API. Is it running?");
  }
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(body?.error?.message ?? `The API answered ${res.status}.`);
  return body as T;
}

export function createScan(url: string) {
  return request<{ id: string; target: string }>("/api/scans", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ url }),
  });
}

export function getScan(id: string) {
  return request<Scan>(`/api/scans/${encodeURIComponent(id)}`);
}

export function scanEventsUrl(id: string) {
  return `${API_URL}/api/scans/${encodeURIComponent(id)}/events`;
}
