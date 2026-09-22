import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { Report } from "@siteshield/core";

export type ScanStatus = "queued" | "running" | "done" | "failed";

export type ScanRow = {
  id: string;
  target: string;
  active: boolean;
  status: ScanStatus;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  grade: string | null;
  score: number | null;
  error: string | null;
  report: Report | null;
};

export type VerificationRow = {
  id: string;
  domain: string;
  token: string;
  keyHash: string;
  createdAt: string;
  verifiedAt: string | null;
  method: string | null;
  expiresAt: string | null;
};

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL CHECK (status IN ('queued', 'running', 'done', 'failed')),
    created_at  TEXT NOT NULL,
    started_at  TEXT,
    finished_at TEXT,
    grade       TEXT,
    score       INTEGER,
    error       TEXT,
    report      TEXT
  );

  CREATE TABLE IF NOT EXISTS verifications (
    id          TEXT PRIMARY KEY,
    domain      TEXT NOT NULL,
    token       TEXT NOT NULL,
    key_hash    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    verified_at TEXT,
    method      TEXT,
    expires_at  TEXT
  );
  CREATE INDEX IF NOT EXISTS verifications_domain ON verifications (domain);
`;

type Row = Record<string, unknown>;

const str = (v: unknown) => (v === null || v === undefined ? null : String(v));

function toScan(r: Row): ScanRow {
  return {
    id: String(r.id),
    target: String(r.target),
    active: r.active === 1,
    status: r.status as ScanStatus,
    createdAt: String(r.created_at),
    startedAt: str(r.started_at),
    finishedAt: str(r.finished_at),
    grade: str(r.grade),
    score: r.score === null ? null : Number(r.score),
    error: str(r.error),
    report: r.report ? (JSON.parse(String(r.report)) as Report) : null,
  };
}

function toVerification(r: Row): VerificationRow {
  return {
    id: String(r.id),
    domain: String(r.domain),
    token: String(r.token),
    keyHash: String(r.key_hash),
    createdAt: String(r.created_at),
    verifiedAt: str(r.verified_at),
    method: str(r.method),
    expiresAt: str(r.expires_at),
  };
}

export function openDatabase(path: string) {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
  db.exec(SCHEMA);

  // A scan that was queued or running when the process stopped will never finish.
  db.prepare(
    "UPDATE scans SET status = 'failed', error = 'The server restarted before this scan finished.', finished_at = ? WHERE status IN ('queued', 'running')",
  ).run(new Date().toISOString());

  const q = {
    insertScan: db.prepare("INSERT INTO scans (id, target, active, status, created_at) VALUES (?, ?, ?, 'queued', ?)"),
    getScan: db.prepare("SELECT * FROM scans WHERE id = ?"),
    startScan: db.prepare("UPDATE scans SET status = 'running', started_at = ? WHERE id = ?"),
    finishScan: db.prepare("UPDATE scans SET status = 'done', finished_at = ?, grade = ?, score = ?, report = ? WHERE id = ?"),
    failScan: db.prepare("UPDATE scans SET status = 'failed', finished_at = ?, error = ? WHERE id = ?"),

    insertVerification: db.prepare(
      "INSERT INTO verifications (id, domain, token, key_hash, created_at) VALUES (?, ?, ?, ?, ?)",
    ),
    getVerification: db.prepare("SELECT * FROM verifications WHERE id = ?"),
    markVerified: db.prepare("UPDATE verifications SET verified_at = ?, method = ?, expires_at = ? WHERE id = ?"),
    verifiedForDomain: db.prepare(
      "SELECT * FROM verifications WHERE domain = ? AND verified_at IS NOT NULL AND expires_at > ?",
    ),
  };

  return {
    close: () => db.close(),

    createScan(id: string, target: string, active: boolean) {
      q.insertScan.run(id, target, active ? 1 : 0, new Date().toISOString());
    },
    getScan(id: string): ScanRow | undefined {
      const row = q.getScan.get(id) as Row | undefined;
      return row && toScan(row);
    },
    markRunning(id: string) {
      q.startScan.run(new Date().toISOString(), id);
    },
    markDone(id: string, report: Report) {
      q.finishScan.run(new Date().toISOString(), report.grade, report.score, JSON.stringify(report), id);
    },
    markFailed(id: string, error: string) {
      q.failScan.run(new Date().toISOString(), error, id);
    },

    createVerification(v: Pick<VerificationRow, "id" | "domain" | "token" | "keyHash">) {
      q.insertVerification.run(v.id, v.domain, v.token, v.keyHash, new Date().toISOString());
    },
    getVerification(id: string): VerificationRow | undefined {
      const row = q.getVerification.get(id) as Row | undefined;
      return row && toVerification(row);
    },
    markVerified(id: string, method: string, expiresAt: Date) {
      q.markVerified.run(new Date().toISOString(), method, expiresAt.toISOString(), id);
    },
    activeVerificationsFor(domain: string): VerificationRow[] {
      return (q.verifiedForDomain.all(domain, new Date().toISOString()) as Row[]).map(toVerification);
    },
  };
}

export type Db = ReturnType<typeof openDatabase>;
