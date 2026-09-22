import type { Finding } from "../types.ts";
import { liveFinding, type Check } from "./types.ts";

// Names that usually hold a session or auth token. Those are the cookies where a missing
// HttpOnly flag actually matters, since script can read them after an XSS.
const SESSION_NAME = /sess|sid|auth|token|jwt|login|remember/i;

export const cookiesCheck: Check = {
  id: "CKE001",
  layer: "live",
  mode: "passive",
  async run({ home }) {
    const findings: Finding[] = [];
    const https = home.finalUrl.protocol === "https:";

    for (const raw of home.response.headers.getSetCookie()) {
      const [pair = "", ...attrs] = raw.split(";").map((s) => s.trim());
      const name = pair.split("=")[0] ?? "";
      const flags = new Set(attrs.map((a) => a.split("=")[0]!.toLowerCase()));
      const sameSite = attrs.find((a) => /^samesite=/i.test(a))?.split("=")[1]?.toLowerCase();
      const session = SESSION_NAME.test(name);

      const problems: { short: string; long: string }[] = [];
      if (https && !flags.has("secure")) {
        problems.push({ short: "has no Secure flag", long: "can be sent over plain HTTP because it has no Secure flag" });
      }
      if (session && !flags.has("httponly")) {
        problems.push({ short: "has no HttpOnly flag", long: "is readable by page scripts because it has no HttpOnly flag" });
      }
      if (!sameSite) {
        problems.push({ short: "has no SameSite attribute", long: "is sent on cross site requests by older browsers because it has no SameSite attribute" });
      } else if (sameSite === "none" && !flags.has("secure")) {
        problems.push({ short: "uses SameSite=None without Secure", long: "is rejected by browsers because SameSite=None requires Secure" });
      }
      if (problems.length === 0) continue;

      findings.push(
        liveFinding({
          checkId: "CKE001",
          severity: session && problems.length > 1 ? "medium" : "low",
          title: problems.length > 1 ? `Cookie ${name} is missing several flags` : `Cookie ${name} ${problems[0]!.short}`,
          detail: `The ${name} cookie ${problems.map((p) => p.long).join(", and ")}.`,
          evidence: `set-cookie: ${name}=…; ${attrs.join("; ")}`,
          remediation: [
            {
              stack: "express",
              summary: "Set the flags where the cookie is created.",
              code: `res.cookie("${name}", value, { secure: true, httpOnly: true, sameSite: "lax" });`,
            },
            {
              stack: "nextjs",
              summary: "Set the flags where the cookie is created.",
              code: `(await cookies()).set("${name}", value, { secure: true, httpOnly: true, sameSite: "lax" });`,
            },
          ],
        }),
      );
    }

    return findings;
  },
};
