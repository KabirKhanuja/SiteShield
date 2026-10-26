import { readLimited, safeFetch } from "../http.ts";
import { PROVIDER_PATTERNS, maskSecret } from "../secret-patterns.ts";
import type { Finding } from "../types.ts";
import { liveFinding, type Check } from "./types.ts";

/**
 * BND001 - secrets inside the JavaScript the site serves to browsers. Everything linked from
 * the homepage is downloaded by every visitor already, so reading it is passive. We fetch a
 * bounded number of same-origin scripts and scan them with the same provider patterns the
 * source secret check uses, which is what lets a key found here pair with SEC001 or PUB001.
 */

const MAX_SCRIPTS = 10;
const MAX_SCRIPT_BYTES = 3 * 1024 * 1024;

function scriptUrls(html: string, pageUrl: URL): URL[] {
  const urls: URL[] = [];
  for (const tag of html.match(/<script\b[^>]*\bsrc\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)[^>]*>/gi) ?? []) {
    const m = tag.match(/\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
    const src = (m?.[1] ?? m?.[2] ?? m?.[3])?.trim();
    if (!src) continue;
    try {
      const url = new URL(src, pageUrl);
      // Only same-origin scripts. A third-party CDN script is not the site owner's to fix,
      // and fetching arbitrary cross-origin URLs would widen what the scanner reaches out to.
      if (url.origin === pageUrl.origin && (url.protocol === "https:" || url.protocol === "http:")) urls.push(url);
    } catch {
      // Ignore a malformed src.
    }
  }
  return [...new Map(urls.map((u) => [u.href, u])).values()].slice(0, MAX_SCRIPTS);
}

function inlineScripts(html: string): string {
  return (html.match(/<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi) ?? []).join("\n");
}

function scanContent(text: string, where: string): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const pat of PROVIDER_PATTERNS) {
    // Publishable/test keys are meant to ship, so skip the ones that are safe in a browser.
    if (pat.name.includes("test secret")) continue;
    pat.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pat.re.exec(text))) {
      const key = `${pat.name}:${m[0]}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(
        liveFinding({
          checkId: "BND001",
          severity: pat.severity,
          title: `${pat.name} exposed in shipped JavaScript`,
          detail: `A ${pat.name.toLowerCase()} is present in ${where}, which is downloaded by every visitor. Anyone who opens the site can read it. Treat it as compromised and rotate it.`,
          evidence: `${maskSecret(m[0])} in ${where}`,
          location: where,
          cwe: pat.cwe,
          owasp: "A01:2021 Broken Access Control",
          cvss: pat.severity === "critical" ? 9.1 : 7.5,
          remediation: [
            { stack: "any", summary: "Keep the secret on the server and never reference it in client code. Rotate the exposed key." },
            { stack: "nextjs", summary: "Only use the value in server components, route handlers or server actions, and drop any NEXT_PUBLIC_ prefix." },
          ],
        }),
      );
    }
  }
  return findings;
}

export const bundleCheck: Check = {
  id: "BND001",
  layer: "live",
  mode: "passive",
  async run({ url, html, signal }) {
    if (!html) return [];
    const findings: Finding[] = [];

    // Inline scripts on the homepage.
    findings.push(...scanContent(inlineScripts(html), `${url.origin}/ (inline script)`));

    // External same-origin scripts, fetched with a cap.
    for (const scriptUrl of scriptUrls(html, url)) {
      signal?.throwIfAborted();
      try {
        const { response } = await safeFetch(scriptUrl, { method: "GET", signal });
        const text = await readLimited(response, MAX_SCRIPT_BYTES);
        const rel = scriptUrl.pathname + scriptUrl.search;
        findings.push(...scanContent(text, rel));
      } catch {
        // A script that 404s or times out: skip it.
      }
    }

    // One finding per distinct key, even if it appears in several files.
    const byKey = new Map<string, Finding>();
    for (const f of findings) if (!byKey.has(f.evidence ?? f.title)) byKey.set(f.evidence ?? f.title, f);
    return [...byKey.values()];
  },
};
