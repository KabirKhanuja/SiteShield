import type { Finding } from "../../types.ts";
import { findingAt, type SourceCheck } from "../types.ts";

/**
 * RTL002 - authentication routes with no rate limiting anywhere in the file. Login, signup
 * and password-reset endpoints are where credential stuffing and brute force land, so they
 * are the ones that most need a limiter. Pairs with RTL001 on the live side.
 */

const AUTH_ROUTE = /\b(?:app|router|api|server)\.(post|put)\s*\(\s*(['"`])([^'"`]*(?:login|signin|sign-in|signup|sign-up|register|auth|password|reset|forgot|token|otp|verify)[^'"`]*)\2/gi;
const NEXT_AUTH_ROUTE_PATH = /(login|signin|sign-in|signup|sign-up|register|password|reset|forgot|auth|otp)/i;

const LIMITER_SIGNAL =
  /\b(rateLimit|rate-limit|ratelimit|express-rate-limit|rateLimiter|limiter|throttle|slowDown|slow-down|Ratelimit|@upstash\/ratelimit|bottleneck|express-slow-down|rate_limit)\b/i;

export const rateLimitCheck: SourceCheck = {
  id: "RTL002",
  run({ files }) {
    const findings: Finding[] = [];

    for (const file of files) {
      if (!/\.(t|j)sx?$/.test(file.path)) continue;
      if (LIMITER_SIGNAL.test(file.content)) continue;

      AUTH_ROUTE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = AUTH_ROUTE.exec(file.content))) {
        findings.push(
          findingAt(file, m.index, {
            checkId: "RTL002",
            severity: "medium",
            title: `Auth route ${m[3]} has no rate limiter`,
            detail: `${m[3]} handles authentication but no rate limiting is set up in ${file.path}. Without one, an attacker can try passwords or codes as fast as the server answers.`,
            evidence: `${m[1]!.toLowerCase()}("${m[3]}", …)`,
            cwe: "CWE-307",
            owasp: "A07:2021 Identification and Authentication Failures",
            cvss: 5.3,
            remediation: [
              {
                stack: "express",
                summary: "Add express-rate-limit in front of the auth routes.",
                code: `import { rateLimit } from "express-rate-limit";\nconst loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 });\n${m[1]!.toLowerCase()}("${m[3]}", loginLimit, handler);`,
              },
              {
                stack: "nextjs",
                summary: "Limit by IP in the handler, for example with @upstash/ratelimit, before checking the password.",
              },
            ],
          }),
        );
      }

      // Next.js auth route handlers named by path.
      if (/(^|\/)route\.(t|j)sx?$/.test(file.path) && NEXT_AUTH_ROUTE_PATH.test(file.path)) {
        if (/export\s+(?:async\s+)?(?:function|const)\s+POST\b/.test(file.content)) {
          const idx = file.content.search(/export\s+(?:async\s+)?(?:function|const)\s+POST\b/);
          findings.push(
            findingAt(file, Math.max(0, idx), {
              checkId: "RTL002",
              severity: "medium",
              title: `Auth route handler has no rate limiter`,
              detail: `${file.path} looks like an authentication route (by its path) with a POST handler and no rate limiting. Add per-IP limiting before checking credentials.`,
              cwe: "CWE-307",
              owasp: "A07:2021 Identification and Authentication Failures",
              cvss: 5.3,
              remediation: [{ stack: "nextjs", summary: "Rate-limit by IP in the handler, e.g. @upstash/ratelimit, before verifying the password." }],
            }),
          );
        }
      }
    }

    return findings;
  },
};
