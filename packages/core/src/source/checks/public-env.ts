import type { Finding } from "../../types.ts";
import { findingAt, type SourceCheck } from "../types.ts";

/**
 * PUB001 - a secret stored in a build-time public variable. Anything named NEXT_PUBLIC_*,
 * VITE_*, REACT_APP_*, EXPO_PUBLIC_* or PUBLIC_* is inlined into the JavaScript bundle the
 * browser downloads, so if its name says "secret" or "key", that secret ships to every
 * visitor. This is the classic "vibe coded" mistake and pairs with BND001 on the live side.
 */

const PUBLIC_PREFIX = /\b((?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|GATSBY|PUBLIC|VUE_APP|NUXT_PUBLIC)_[A-Z0-9_]*(SECRET|API_?KEY|TOKEN|PASSWORD|PRIVATE|CLIENT_SECRET|ACCESS_KEY)[A-Z0-9_]*)/g;

// "PUBLISHABLE" keys (Stripe pk_, etc.) are designed to be exposed, so a public var holding
// one is fine.
const INTENTIONALLY_PUBLIC = /(PUBLISHABLE|PUBLIC_KEY|ANON_KEY|CLIENT_ID|MEASUREMENT_ID|SENTRY_DSN|GA_|ANALYTICS)/;

export const publicEnvCheck: SourceCheck = {
  id: "PUB001",
  run({ files }) {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const file of files) {
      PUBLIC_PREFIX.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = PUBLIC_PREFIX.exec(file.content))) {
        const varName = m[1]!;
        if (INTENTIONALLY_PUBLIC.test(varName)) continue;
        const key = `${file.path}:${varName}`;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push(
          findingAt(file, m.index, {
            checkId: "PUB001",
            severity: "high",
            title: `Secret in public variable ${varName}`,
            detail: `${varName} is a build-time public variable, so its value is copied into the JavaScript bundle sent to browsers. A name like this suggests a secret, which means it is readable by anyone who opens the site. Public variables are only for values that are safe to expose.`,
            evidence: varName,
            cwe: "CWE-200",
            owasp: "A01:2021 Broken Access Control",
            cvss: 7.5,
            remediation: [
              {
                stack: "nextjs",
                summary: "Drop the NEXT_PUBLIC_ prefix so the value stays on the server, and read it only in server code (route handlers, server components, server actions).",
                code: `// server only\nconst key = process.env.${varName.replace(/^NEXT_PUBLIC_/, "")};`,
              },
              {
                stack: "any",
                summary: "Rename the variable without the public prefix and use it only on the server. Rotate the exposed value.",
              },
            ],
          }),
        );
      }
    }

    return findings;
  },
};
