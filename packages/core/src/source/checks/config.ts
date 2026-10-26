import type { Finding } from "../../types.ts";
import { findingAt, type SourceCheck } from "../types.ts";

/**
 * CFG001 - unsafe security settings: TLS verification switched off, JWTs accepted without
 * verifying the signature, or MD5/SHA1 used to hash passwords. Each one quietly removes a
 * protection, so they are easy to ship and dangerous in production.
 */

type Rule = {
  name: string;
  re: RegExp;
  severity: Finding["severity"];
  cwe: string;
  owasp: string;
  cvss: number;
  detail: string;
  fix: string;
};

const RULES: Rule[] = [
  {
    name: "TLS certificate verification disabled",
    re: /rejectUnauthorized\s*:\s*false/g,
    severity: "high",
    cwe: "CWE-295",
    owasp: "A02:2021 Cryptographic Failures",
    cvss: 7.4,
    detail: "rejectUnauthorized: false turns off certificate checking, so the connection can be intercepted by anyone able to present any certificate. A man-in-the-middle reads and changes the traffic.",
    fix: "Remove it and trust the system CAs. If you need a private CA, pass its certificate with the `ca` option instead of disabling verification.",
  },
  {
    name: "TLS verification disabled globally",
    re: /NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0['"]?/g,
    severity: "high",
    cwe: "CWE-295",
    owasp: "A02:2021 Cryptographic Failures",
    cvss: 7.4,
    detail: "Setting NODE_TLS_REJECT_UNAUTHORIZED to 0 disables certificate verification for every TLS connection the process makes, not just one. Every outgoing HTTPS request is now interceptable.",
    fix: "Never set this in application or production code. Fix the specific certificate problem instead.",
  },
  {
    name: "JWT decoded without verifying",
    re: /\bjwt\.decode\s*\(/g,
    severity: "high",
    cwe: "CWE-347",
    owasp: "A02:2021 Cryptographic Failures",
    cvss: 7.5,
    detail: "jwt.decode reads a token without checking its signature, so a forged token is accepted. If this value is trusted for auth, anyone can mint their own.",
    fix: "Use jwt.verify(token, secret) so a tampered or forged token is rejected. decode is only safe for already-verified tokens.",
  },
  {
    name: "JWT signature verification disabled",
    re: /algorithms?\s*:\s*\[?\s*['"]none['"]/gi,
    severity: "critical",
    cwe: "CWE-347",
    owasp: "A02:2021 Cryptographic Failures",
    cvss: 9.1,
    detail: "Allowing the 'none' algorithm means a token with no signature is accepted as valid. This is a complete authentication bypass.",
    fix: "Pin a real algorithm, for example algorithms: ['HS256'] or ['RS256'], and never allow 'none'.",
  },
  {
    name: "Weak hash for passwords",
    re: /createHash\s*\(\s*['"](md5|sha1)['"]\s*\)/gi,
    severity: "medium",
    cwe: "CWE-916",
    owasp: "A02:2021 Cryptographic Failures",
    cvss: 5.9,
    detail: "MD5 and SHA1 are fast and broken for passwords: they are brute-forced at billions of guesses per second and have known collisions. If this hash protects passwords, it offers little real protection.",
    fix: "Hash passwords with bcrypt, scrypt or argon2, which are deliberately slow. Keep MD5/SHA1 only for non-security checksums.",
  },
  {
    name: "Math.random used for a token or secret",
    re: /(token|secret|password|otp|nonce|salt|apiKey|api_key)\s*[:=][^;\n]*Math\.random\s*\(/gi,
    severity: "medium",
    cwe: "CWE-338",
    owasp: "A02:2021 Cryptographic Failures",
    cvss: 5.3,
    detail: "Math.random is not cryptographically secure and its output can be predicted. A token or secret generated from it can be guessed.",
    fix: "Use crypto.randomBytes or crypto.randomUUID for anything that must be unguessable.",
  },
];

export const configCheck: SourceCheck = {
  id: "CFG001",
  run({ files }) {
    const findings: Finding[] = [];

    for (const file of files) {
      if (!/\.(t|j)sx?|\.mjs|\.cjs|\.env|\.yml|\.yaml|\.json$/.test(file.path)) continue;

      for (const rule of RULES) {
        rule.re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = rule.re.exec(file.content))) {
          findings.push(
            findingAt(file, m.index, {
              checkId: "CFG001",
              severity: rule.severity,
              title: rule.name,
              detail: rule.detail,
              evidence: m[0].slice(0, 120),
              cwe: rule.cwe,
              owasp: rule.owasp,
              cvss: rule.cvss,
              remediation: [{ stack: "any", summary: rule.fix }],
            }),
          );
        }
      }
    }

    return findings;
  },
};
