import type { Finding } from "../../types.ts";
import { findingAt, type SourceCheck } from "../types.ts";

/**
 * COR002 - a CORS config that trusts every origin, or reflects the caller's origin while
 * also allowing credentials. The second one is the dangerous combination: it lets any site
 * make authenticated requests as the logged-in user. Pairs with COR001 on the live side.
 */

export const corsCheck: SourceCheck = {
  id: "COR002",
  run({ files }) {
    const findings: Finding[] = [];

    for (const file of files) {
      if (!/\.(t|j)sx?$|\.(json|conf|config)$/.test(file.path)) continue;
      const credentials = /credentials\s*:\s*true|Access-Control-Allow-Credentials['"]?\s*[:,]\s*['"]?true/i.test(file.content);

      // Wildcard origin.
      for (const re of [
        /\borigin\s*:\s*(['"`])\*\1/gi,
        /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]/gi,
        /cors\s*\(\s*\)/gi, // cors() with no options allows all origins by default
      ]) {
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = re.exec(file.content))) {
          const wildcardWithCreds = credentials && !/cors\s*\(\s*\)/.test(m[0]);
          findings.push(
            findingAt(file, m.index, {
              checkId: "COR002",
              severity: wildcardWithCreds ? "high" : "medium",
              title: wildcardWithCreds ? "CORS allows every origin with credentials" : "CORS allows every origin",
              detail: wildcardWithCreds
                ? "Allowing all origins together with credentials lets any website send authenticated requests as a logged-in user. Browsers actually forbid '*' with credentials, so this often means the origin is being reflected instead, which is the real danger."
                : "This allows any website to read responses from your API. Fine for a fully public API, but not for anything behind a login.",
              evidence: m[0].slice(0, 80),
              cwe: "CWE-942",
              owasp: "A05:2021 Security Misconfiguration",
              cvss: wildcardWithCreds ? 7.5 : 5.3,
              remediation: [
                {
                  stack: "express",
                  summary: "List the exact origins you trust instead of allowing all.",
                  code: `app.use(cors({ origin: ["https://yourapp.com"], credentials: true }));`,
                },
                { stack: "any", summary: "Allow only the specific origins your frontend uses, and never pair a wildcard with credentials." },
              ],
            }),
          );
        }
      }

      // Reflecting the request origin back while allowing credentials.
      const reflect = /Access-Control-Allow-Origin['"]?\s*[:,]\s*(req\.headers\.origin|request\.headers\.get\(['"]origin|origin\b)/i;
      if (credentials && reflect.test(file.content)) {
        const idx = file.content.search(reflect);
        findings.push(
          findingAt(file, Math.max(0, idx), {
            checkId: "COR002",
            severity: "high",
            title: "CORS reflects the request origin with credentials",
            detail: "Echoing back whatever Origin the caller sent, together with credentials, is equivalent to trusting every site. Any page can then make authenticated requests as your users.",
            cwe: "CWE-942",
            owasp: "A05:2021 Security Misconfiguration",
            cvss: 8.1,
            remediation: [{ stack: "any", summary: "Compare the request origin against an allowlist and only echo it back if it is on the list." }],
          }),
        );
      }
    }

    return findings;
  },
};
