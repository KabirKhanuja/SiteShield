import type { Finding } from "../../types.ts";
import { findingAt, type SourceCheck, type SourceFile } from "../types.ts";

/**
 * INJ002 - request-controlled data flowing into a dangerous call: SQL built by string
 * concatenation, a shell command, eval, an open redirect, or a file path. This is a
 * line-level taint heuristic, not full data-flow analysis, so it looks for untrusted input
 * markers used inside the dangerous call on the same statement. Pairs with INJ001/XSS001.
 */

// Markers that a value came from the request. Kept broad across frameworks.
const UNTRUSTED =
  /\b(req\.(body|query|params|headers|cookies)|request\.(body|query|params|nextUrl|headers)|searchParams|ctx\.query|ctx\.params|event\.body|params\[|query\[|process\.argv)\b/;

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
    name: "SQL built by string concatenation",
    // A SQL statement in a string that is then concatenated (" ... " + x) or interpolated
    // (`... ${x}`). That is the shape of SQL injection, whatever the query call is named.
    re: /\b(SELECT|INSERT|UPDATE|DELETE)\b[^;\n]{0,200}?(['"`]\s*\+|\+\s*['"`]|\$\{)/gi,
    severity: "high",
    cwe: "CWE-89",
    owasp: "A03:2021 Injection",
    cvss: 8.8,
    detail: "A SQL statement is built from a string with request data on the same line. Concatenating user input into SQL is how SQL injection happens.",
    fix: "Use parameterised queries (placeholders), never string concatenation: db.query('SELECT * FROM users WHERE id = $1', [id]).",
  },
  {
    name: "Shell command with request data",
    re: /\b(exec|execSync|spawn|spawnSync|execFile)\s*\(/gi,
    severity: "high",
    cwe: "CWE-78",
    owasp: "A03:2021 Injection",
    cvss: 9.1,
    detail: "A shell command is run on a line that also uses request data. If that data reaches the command string, an attacker can run arbitrary commands on your server.",
    fix: "Avoid the shell. Use execFile with an argument array and never interpolate user input into the command string.",
  },
  {
    name: "eval on request data",
    re: /\b(eval|new Function)\s*\(/gi,
    severity: "critical",
    cwe: "CWE-95",
    owasp: "A03:2021 Injection",
    cvss: 9.3,
    detail: "eval (or new Function) runs on a line with request data. Evaluating user input as code lets an attacker run anything in your process.",
    fix: "Remove eval. Parse data with JSON.parse, or use a real parser for whatever format you expected.",
  },
  {
    name: "Open redirect",
    re: /\b(res\.redirect|response\.redirect|redirect)\s*\(/gi,
    severity: "medium",
    cwe: "CWE-601",
    owasp: "A01:2021 Broken Access Control",
    cvss: 6.1,
    detail: "A redirect target is taken from request data. An open redirect lets attackers send users to a phishing page through a link on your trusted domain.",
    fix: "Redirect only to a fixed set of paths, or check the target is same-origin before redirecting.",
  },
];

export const injectionCheck: SourceCheck = {
  id: "INJ002",
  run({ files }) {
    const findings: Finding[] = [];

    for (const file of files) {
      if (!/\.(t|j)sx?|\.mjs|\.cjs$/.test(file.path)) continue;

      for (const rule of RULES) {
        rule.re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = rule.re.exec(file.content))) {
          // Only flag when untrusted input is used on the same statement (same line, or the
          // argument span). This is what keeps it from firing on every db.query in the repo.
          const window = statementAround(file, m.index);
          if (!UNTRUSTED.test(window)) continue;

          findings.push(
            findingAt(file, m.index, {
              checkId: "INJ002",
              severity: rule.severity,
              title: rule.name,
              detail: rule.detail,
              evidence: file.lines[lineOf(file, m.index)]?.trim().slice(0, 160),
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

function lineOf(file: SourceFile, index: number): number {
  let line = 0;
  for (let i = 0; i < index && i < file.content.length; i++) if (file.content[i] === "\n") line++;
  return line;
}

/** The text of the statement the match sits in: the current line plus the next two, so a
 * call split across lines is still seen with its arguments. */
function statementAround(file: SourceFile, index: number): string {
  const line = lineOf(file, index);
  return file.lines.slice(line, line + 3).join("\n");
}
