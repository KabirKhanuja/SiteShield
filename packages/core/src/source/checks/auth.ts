import type { Finding } from "../../types.ts";
import { findingAt, type SourceCheck, type SourceFile } from "../types.ts";

/**
 * AUT001 - routes that change data without any sign of an authorisation check. This is a
 * heuristic: it flags a mutating route handler when the file around it shows no auth signal
 * at all. It can miss auth done far away, and can flag a route that is deliberately public,
 * so it reports medium and explains what to confirm.
 */

// Anything that reads like "we checked who is asking". Broad on purpose, to avoid noise.
const AUTH_SIGNAL =
  /\b(auth|authN|authZ|authorize|authorise|authenticate|session|getServerSession|getToken|getUser|currentUser|requireUser|requireAuth|ensureAuth|isAuthenticated|verifyToken|verifyJwt|jwt\.verify|req\.user|ctx\.user|passport|withAuth|clerk|supabase|getAuth|protect|guard|middleware|can\(|ability|permission|role)\b/i;

const EXPRESS_MUTATION = /\b(?:app|router|api|server)\.(post|put|patch|delete)\s*\(\s*(['"`])([^'"`]*)\2/gi;
const NEXT_HANDLER = /export\s+(?:async\s+)?(?:function|const)\s+(POST|PUT|PATCH|DELETE)\b/g;

function isRouteFile(path: string): boolean {
  return /(^|\/)route\.(t|j)sx?$/.test(path) || /(^|\/)pages\/api\//.test(path) || /(^|\/)app\/api\//.test(path);
}

export const authCheck: SourceCheck = {
  id: "AUT001",
  run({ files }) {
    const findings: Finding[] = [];

    for (const file of files) {
      if (!/\.(t|j)sx?$/.test(file.path)) continue;
      const hasAuth = AUTH_SIGNAL.test(file.content);
      if (hasAuth) continue;

      // Express style mutating routes.
      EXPRESS_MUTATION.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = EXPRESS_MUTATION.exec(file.content))) {
        findings.push(
          findingAt(file, m.index, {
            checkId: "AUT001",
            severity: "medium",
            title: `${m[1]!.toUpperCase()} ${m[3]} has no visible auth check`,
            detail: `This route changes data but nothing in ${file.path} looks like an authorisation check. If the route is meant to be protected, add the check. If it is deliberately public, you can ignore this finding.`,
            evidence: `${m[1]!.toLowerCase()}("${m[3]}", …)`,
            cwe: "CWE-862",
            owasp: "A01:2021 Broken Access Control",
            cvss: 6.5,
            remediation: [
              {
                stack: "express",
                summary: "Put an auth middleware before the handler.",
                code: `${m[1]!.toLowerCase()}("${m[3]}", requireAuth, handler);`,
              },
            ],
          }),
        );
      }

      // Next.js route handlers and API routes.
      if (isRouteFile(file.path)) {
        NEXT_HANDLER.lastIndex = 0;
        let n: RegExpExecArray | null;
        while ((n = NEXT_HANDLER.exec(file.content))) {
          findings.push(
            findingAt(file, n.index, {
              checkId: "AUT001",
              severity: "medium",
              title: `${n[1]} handler has no visible auth check`,
              detail: `This ${n[1]} handler in ${file.path} changes data, but the file shows no authorisation check. Confirm whether the route should verify the caller.`,
              cwe: "CWE-862",
              owasp: "A01:2021 Broken Access Control",
              cvss: 6.5,
              remediation: [
                {
                  stack: "nextjs",
                  summary: "Check the session at the top of the handler and return 401 when there is none.",
                  code: `const session = await auth();\nif (!session) return new Response("Unauthorized", { status: 401 });`,
                },
              ],
            }),
          );
        }
      }
    }

    return dedupeByLocation(findings);
  },
};

/** One finding per file+line, in case two patterns match the same spot. */
function dedupeByLocation(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = f.location ?? f.title;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export type { SourceFile };
