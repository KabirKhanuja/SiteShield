import type { Finding, Severity } from "../types.ts";
import { liveFinding, type Check } from "./types.ts";

/**
 * VER001 - front-end libraries served with a version that has known advisories. We read the
 * versions out of the script URLs and the generator meta tag (both already in the HTML the
 * browser downloads) and look them up in OSV.dev. Pairs with DEP001 in the source scan.
 */

const OSV_BATCH = "https://api.osv.dev/v1/querybatch";

// Libraries whose version commonly sits in the file name or a ?ver= query. Mapped to the
// npm package name OSV knows them by.
const LIBS: { label: string; npm: string; re: RegExp }[] = [
  { label: "jQuery", npm: "jquery", re: /jquery[-.@/]?v?(\d+\.\d+\.\d+)/i },
  { label: "Bootstrap", npm: "bootstrap", re: /bootstrap[-.@/]?v?(\d+\.\d+\.\d+)/i },
  { label: "AngularJS", npm: "angular", re: /angular[-.@/]?v?(\d+\.\d+\.\d+)/i },
  { label: "Vue", npm: "vue", re: /vue[-.@/]?v?(\d+\.\d+\.\d+)/i },
  { label: "React", npm: "react", re: /react[-.@/]?v?(\d+\.\d+\.\d+)/i },
  { label: "Lodash", npm: "lodash", re: /lodash[-.@/]?v?(\d+\.\d+\.\d+)/i },
  { label: "Moment.js", npm: "moment", re: /moment[-.@/]?v?(\d+\.\d+\.\d+)/i },
  { label: "Axios", npm: "axios", re: /axios[-.@/]?v?(\d+\.\d+\.\d+)/i },
  { label: "D3", npm: "d3", re: /d3[-.@/]?v?(\d+\.\d+\.\d+)/i },
];

type Detected = { label: string; npm: string; version: string; where: string };

function detect(html: string): Detected[] {
  const found = new Map<string, Detected>();
  const srcs = (html.match(/\b(?:src|href)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi) ?? []).map((s) =>
    s.replace(/^.*?=\s*['"]/, "").replace(/['"]$/, ""),
  );
  for (const src of srcs) {
    for (const lib of LIBS) {
      const m = src.match(lib.re);
      if (m) {
        const key = `${lib.npm}@${m[1]}`;
        if (!found.has(key)) found.set(key, { label: lib.label, npm: lib.npm, version: m[1]!, where: src });
      }
    }
  }
  return [...found.values()];
}

function generator(html: string): { name: string; version?: string } | null {
  const m = html.match(/<meta[^>]+name\s*=\s*["']generator["'][^>]*content\s*=\s*["']([^"']+)["']/i);
  if (!m) return null;
  const content = m[1]!;
  const v = content.match(/(\d+\.\d+(?:\.\d+)?)/);
  return { name: content.replace(/\s*\d.*$/, "").trim() || content, version: v?.[1] };
}

async function osvLookup(detected: Detected[], signal?: AbortSignal): Promise<Map<string, string[]>> {
  const vulns = new Map<string, string[]>();
  try {
    const res = await fetch(OSV_BATCH, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ queries: detected.map((d) => ({ package: { name: d.npm, ecosystem: "npm" }, version: d.version })) }),
      signal: signal ?? AbortSignal.timeout(15_000),
    });
    if (!res.ok) return vulns;
    const results = ((await res.json()) as { results?: { vulns?: { id: string }[] }[] }).results ?? [];
    results.forEach((r, i) => {
      if (r.vulns?.length) vulns.set(`${detected[i]!.npm}@${detected[i]!.version}`, r.vulns.map((v) => v.id));
    });
  } catch {
    // Network failure: report nothing rather than guessing.
  }
  return vulns;
}

export const versionCheck: Check = {
  id: "VER001",
  layer: "live",
  mode: "passive",
  async run({ html, url, signal }) {
    if (!html) return [];
    const findings: Finding[] = [];

    const detected = detect(html);
    if (detected.length > 0) {
      const vulns = await osvLookup(detected, signal);
      for (const d of detected) {
        const ids = vulns.get(`${d.npm}@${d.version}`);
        if (!ids) continue;
        const severity: Severity = ids.length > 2 ? "high" : "medium";
        findings.push(
          liveFinding({
            checkId: "VER001",
            severity,
            title: `${d.label} ${d.version} has known vulnerabilities`,
            detail: `The site loads ${d.label} ${d.version}, which has ${ids.length} published ${ids.length === 1 ? "advisory" : "advisories"} (${ids.slice(0, 4).join(", ")}${ids.length > 4 ? ", …" : ""}). Front-end library CVEs are often XSS or prototype pollution that run in your users' browsers.`,
            evidence: `${d.where} → ${d.label} ${d.version}`,
            location: url.href,
            cwe: "CWE-1035",
            owasp: "A06:2021 Vulnerable and Outdated Components",
            remediation: [{ stack: "any", summary: `Upgrade ${d.label} to a current release and redeploy.` }],
          }),
        );
      }
    }

    const gen = generator(html);
    if (gen && gen.version) {
      findings.push(
        liveFinding({
          checkId: "VER001",
          severity: "info",
          title: `Site reports ${gen.name} ${gen.version}`,
          detail: `The generator meta tag announces ${gen.name} ${gen.version}. This tells an attacker exactly which version's CVEs to try. Check that this version is current and remove the tag if you do not need it.`,
          evidence: `<meta name="generator" content="${gen.name} ${gen.version}">`,
          location: url.href,
          owasp: "A06:2021 Vulnerable and Outdated Components",
          remediation: [{ stack: "any", summary: "Keep the CMS or framework patched, and remove the generator meta tag to avoid advertising the version." }],
        }),
      );
    }

    return findings;
  },
};
