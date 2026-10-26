import type { Finding } from "../../types.ts";
import { findingAt, type SourceCheck, type SourceFile } from "../types.ts";

/**
 * XSS001 - raw HTML sinks fed with data that did not go through a sanitiser. React's
 * dangerouslySetInnerHTML and the DOM's innerHTML both render whatever string they are
 * given as live HTML, so a value from the user turns into script execution. Pairs with
 * INJ001 on the live side.
 */

const SANITISER = /\b(DOMPurify|sanitize|sanitizeHtml|sanitise|xss\(|escapeHtml|he\.encode|purify)\b/i;

const SINKS = [
  { name: "dangerouslySetInnerHTML", re: /dangerouslySetInnerHTML\s*=\s*\{\{?\s*__html\s*:\s*([^}]+)\}?\}/g },
  { name: "innerHTML assignment", re: /\.(innerHTML|outerHTML)\s*=\s*([^;\n]+)/g },
  { name: "insertAdjacentHTML", re: /\.insertAdjacentHTML\s*\(\s*[^,]+,\s*([^)]+)\)/g },
  { name: "document.write", re: /document\.write(?:ln)?\s*\(\s*([^)]+)\)/g },
];

// A string literal, or a concatenation of only literals, is static and safe.
function isStaticValue(expr: string): boolean {
  const e = expr.trim();
  if (/^(['"`])[^'"`]*\1$/.test(e)) return true;
  if (!/[a-zA-Z_$]/.test(e.replace(/['"`][^'"`]*['"`]/g, ""))) return true; // only literals and operators
  return false;
}

export const xssCheck: SourceCheck = {
  id: "XSS001",
  run({ files }) {
    const findings: Finding[] = [];

    for (const file of files) {
      if (!/\.(t|j)sx?|\.vue|\.svelte|\.html$/.test(file.path)) continue;

      for (const sink of SINKS) {
        sink.re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = sink.re.exec(file.content))) {
          const expr = (m[2] ?? m[1] ?? "").trim();
          if (isStaticValue(expr)) continue; // constant markup is fine
          if (SANITISER.test(expr)) continue; // value already run through a sanitiser

          findings.push(
            findingAt(file, m.index, {
              checkId: "XSS001",
              severity: "high",
              title: `${sink.name} with unsanitised value`,
              detail: `${sink.name} renders its argument as live HTML. The value here is not a constant and does not appear to be sanitised, so if any of it comes from a user it becomes stored or reflected XSS.`,
              evidence: file.lines[lineOf(file, m.index)]?.trim().slice(0, 160),
              cwe: "CWE-79",
              owasp: "A03:2021 Injection",
              cvss: 6.1,
              remediation: [
                {
                  stack: "any",
                  summary: "Render it as text instead of HTML, or sanitise with DOMPurify first.",
                  code: `import DOMPurify from "dompurify";\nel.innerHTML = DOMPurify.sanitize(value);`,
                },
              ],
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
