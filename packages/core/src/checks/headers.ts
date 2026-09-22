import type { Remediation } from "../types.ts";
import { liveFinding, type Check } from "./types.ts";

function headerFix(name: string, value: string): Remediation[] {
  return [
    {
      stack: "nextjs",
      summary: `Add ${name} to the headers() list in next.config.ts.`,
      file: "next.config.ts",
      code: `{ key: "${name}", value: "${value}" }`,
    },
    {
      stack: "express",
      summary: "helmet sets this with sensible defaults.",
      file: "server.ts",
      code: `import helmet from "helmet";\napp.use(helmet());`,
    },
    {
      stack: "nginx",
      summary: "Add it to the server block.",
      file: "nginx.conf",
      code: `add_header ${name} "${value}" always;`,
    },
    {
      stack: "vercel",
      summary: "Add it under headers in vercel.json.",
      file: "vercel.json",
      code: `{ "source": "/(.*)", "headers": [{ "key": "${name}", "value": "${value}" }] }`,
    },
  ];
}

export const headersCheck: Check = {
  id: "HDR001",
  layer: "live",
  mode: "passive",
  async run({ home }) {
    const h = home.response.headers;
    const findings = [];

    const csp = h.get("content-security-policy");
    if (!csp) {
      findings.push(
        liveFinding({
          checkId: "HDR001",
          severity: "medium",
          title: "No Content Security Policy",
          detail:
            "Without a CSP, any script that gets injected into the page runs with full access. A CSP is the main thing that turns an XSS bug into a non event.",
          remediation: headerFix("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        }),
      );
    } else if (/script-src[^;]*'unsafe-inline'|default-src[^;]*'unsafe-inline'/.test(csp) && !/'nonce-|'sha256-/.test(csp)) {
      findings.push(
        liveFinding({
          checkId: "HDR001",
          severity: "low",
          title: "Content Security Policy allows inline scripts",
          detail: "'unsafe-inline' for scripts without a nonce or hash lets injected inline scripts run, which removes most of the protection.",
          evidence: `content-security-policy: ${csp}`,
          remediation: [{ stack: "any", summary: "Use nonces or hashes for inline scripts and drop 'unsafe-inline' from script-src." }],
        }),
      );
    }

    const framing = h.get("x-frame-options") ?? "";
    if (!/deny|sameorigin/i.test(framing) && !/frame-ancestors/i.test(csp ?? "")) {
      findings.push(
        liveFinding({
          checkId: "HDR001",
          severity: "medium",
          title: "Pages can be embedded in other sites",
          detail: "With no X-Frame-Options or frame-ancestors rule, another site can load yours in a hidden frame and trick users into clicking (clickjacking).",
          remediation: headerFix("X-Frame-Options", "DENY"),
        }),
      );
    }

    if (!/nosniff/i.test(h.get("x-content-type-options") ?? "")) {
      findings.push(
        liveFinding({
          checkId: "HDR001",
          severity: "low",
          title: "X-Content-Type-Options is not set to nosniff",
          detail: "Browsers may guess content types, which can make an uploaded text file execute as script.",
          remediation: headerFix("X-Content-Type-Options", "nosniff"),
        }),
      );
    }

    if (!h.get("referrer-policy")) {
      findings.push(
        liveFinding({
          checkId: "HDR001",
          severity: "low",
          title: "No Referrer-Policy",
          detail: "Full URLs, including tokens in query strings, can leak to other sites through the Referer header.",
          remediation: headerFix("Referrer-Policy", "strict-origin-when-cross-origin"),
        }),
      );
    }

    if (!h.get("permissions-policy")) {
      findings.push(
        liveFinding({
          checkId: "HDR001",
          severity: "info",
          title: "No Permissions-Policy",
          detail: "Not a vulnerability on its own, but it lets you switch off camera, microphone and location for any third party script.",
          remediation: headerFix("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
        }),
      );
    }

    const powered = h.get("x-powered-by");
    if (powered) {
      findings.push(
        liveFinding({
          checkId: "HDR001",
          severity: "info",
          title: "Server announces its framework",
          detail: "X-Powered-By tells attackers exactly which framework to look up CVEs for.",
          evidence: `x-powered-by: ${powered}`,
          remediation: [
            { stack: "express", summary: "Turn it off.", file: "server.ts", code: `app.disable("x-powered-by");` },
            { stack: "nextjs", summary: "Turn it off.", file: "next.config.ts", code: `export default { poweredByHeader: false };` },
          ],
        }),
      );
    }

    return findings;
  },
};
