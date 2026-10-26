import { PROVIDER_PATTERNS, maskSecret } from "../../secret-patterns.ts";
import type { Finding } from "../../types.ts";
import { findingAt, type SourceCheck, type SourceFile } from "../types.ts";

/**
 * SEC001 - secrets written straight into the code or committed in a .env file. A key in the
 * repo is a key anyone with read access (or a leaked clone) already has, so these are high
 * severity even before anyone proves the key still works. The provider patterns are shared
 * with the live bundle check so the same key reports identically on both sides.
 */

// Generic "name = long string literal" assignments where the name suggests a credential.
// Lower confidence, so medium and filtered hard against placeholders.
const GENERIC = /\b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*['"]([^'"\n]{8,})['"]/gi;

// KEY=value lines in a committed .env file.
const ENV_LINE = /^([A-Z][A-Z0-9_]*)=(.+)$/;
const ENV_SECRET_NAME = /(secret|password|passwd|token|api[_-]?key|private[_-]?key|credential|access[_-]?key)/i;

function isPlaceholder(value: string): boolean {
  const v = value.trim();
  if (v.length < 8) return true;
  if (/^(process\.env|import\.meta|os\.environ|env\[)/i.test(v)) return true;
  if (/\$\{|\{\{|<[^>]+>|%[A-Z_]+%/.test(v)) return true; // template or placeholder markers
  if (/^(your|my|the|some|changeme|change[_-]?me|example|placeholder|dummy|fake|test|sample|xxx|todo|redacted|none|null|undefined)/i.test(v)) return true;
  if (/(example|placeholder|dummy|yourkey|your[_-]?key|replace[_-]?me)/i.test(v)) return true;
  if (/^[x*.\-_0]+$/i.test(v)) return true; // xxxx, ****, ----
  if (/^(pk|pub)_(live|test)_/i.test(v)) return true; // publishable keys are meant to ship
  return false;
}

function isExampleEnv(path: string): boolean {
  return /\.(example|sample|template|dist|local\.example)$/i.test(path) || /\.env\.(example|sample|template)/i.test(path);
}

function scanEnvFile(file: SourceFile): Finding[] {
  if (isExampleEnv(file.path)) return [];
  const findings: Finding[] = [];
  let offset = 0;
  for (const line of file.lines) {
    const trimmed = line.trim();
    const m = trimmed.match(ENV_LINE);
    if (m && ENV_SECRET_NAME.test(m[1]!) && !isPlaceholder(m[2]!)) {
      findings.push(
        findingAt(file, offset, {
          checkId: "SEC001",
          severity: "high",
          title: `Secret committed in ${file.path}`,
          detail: `${m[1]} is set to a real looking value in a committed environment file. Anyone who can read the repository has this credential. Even after you remove it, treat it as leaked and rotate it.`,
          evidence: `${m[1]}=${mask(m[2]!)}`,
          cwe: "CWE-798",
          owasp: "A05:2021 Security Misconfiguration",
          cvss: 8.6,
          snippet: `${m[1]}=${mask(m[2]!)}`,
          remediation: [
            {
              stack: "any",
              summary: "Move the value out of the repo into a real secret store, rotate the key, and keep the file out of git.",
              code: `echo "${file.path}" >> .gitignore\n# then rotate ${m[1]} with the provider`,
            },
          ],
        }),
      );
    }
    offset += line.length + 1;
  }
  return findings;
}

const mask = maskSecret;

export const secretsCheck: SourceCheck = {
  id: "SEC001",
  run({ files }) {
    const findings: Finding[] = [];

    for (const file of files) {
      const isEnv = /(^|\/)\.env(\.|$)/.test(file.path);
      if (isEnv) {
        findings.push(...scanEnvFile(file));
        continue;
      }

      for (const pat of PROVIDER_PATTERNS) {
        pat.re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = pat.re.exec(file.content))) {
          findings.push(
            findingAt(file, m.index, {
              checkId: "SEC001",
              severity: pat.severity,
              title: `${pat.name} hardcoded in source`,
              detail: `A ${pat.name.toLowerCase()} appears directly in ${file.path}. Read it from an environment variable or secret manager instead, and rotate this one since it is already in your git history.`,
              evidence: mask(m[0]),
              cwe: pat.cwe,
              owasp: "A05:2021 Security Misconfiguration",
              cvss: pat.severity === "critical" ? 9.1 : pat.severity === "high" ? 7.5 : 5.3,
              remediation: [
                { stack: "any", summary: "Read it from process.env and rotate the exposed key.", code: `const key = process.env.${guessEnvName(pat.name)};` },
              ],
            }),
          );
        }
      }

      GENERIC.lastIndex = 0;
      let g: RegExpExecArray | null;
      while ((g = GENERIC.exec(file.content))) {
        if (isPlaceholder(g[2]!)) continue;
        findings.push(
          findingAt(file, g.index, {
            checkId: "SEC001",
            severity: "medium",
            title: `Possible hardcoded ${g[1]!.toLowerCase()}`,
            detail: `${g[1]} is assigned a literal string in ${file.path}. If this is a real credential, move it to an environment variable and rotate it.`,
            evidence: `${g[1]} = ${mask(g[2]!)}`,
            cwe: "CWE-798",
            owasp: "A05:2021 Security Misconfiguration",
            cvss: 5.3,
            remediation: [{ stack: "any", summary: "Read the value from process.env rather than writing it in the code." }],
          }),
        );
      }
    }

    return findings;
  },
};

function guessEnvName(providerName: string): string {
  return providerName.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/_+$/g, "");
}
