import { safeFetch } from "../http.ts";
import type { Finding } from "../types.ts";
import { liveFinding, type Check } from "./types.ts";

/**
 * COR001 - what the live site's CORS policy actually is. We send one ordinary GET with an
 * Origin header this scanner picks, and read what comes back. A site that echoes any origin
 * and allows credentials is trusting every website on the internet. Pairs with COR002 in
 * the source scan. This only reads a response, it changes nothing.
 */

const PROBE_ORIGIN = "https://siteshield-cors-probe.example";

export const corsLiveCheck: Check = {
  id: "COR001",
  layer: "live",
  mode: "passive",
  async run({ url, signal }) {
    const findings: Finding[] = [];

    let allowOrigin: string | null;
    let allowCreds: string | null;
    try {
      const { response } = await safeFetch(url, { method: "GET", signal, headers: { origin: PROBE_ORIGIN } });
      await response.body?.cancel();
      allowOrigin = response.headers.get("access-control-allow-origin");
      allowCreds = response.headers.get("access-control-allow-credentials");
    } catch {
      return findings; // Could not re-fetch; nothing to say about CORS.
    }

    if (!allowOrigin) return findings; // No CORS headers: the site does not opt other origins in.

    const credentials = allowCreds?.toLowerCase() === "true";
    const reflects = allowOrigin === PROBE_ORIGIN;
    const wildcard = allowOrigin === "*";

    if (reflects && credentials) {
      findings.push(
        liveFinding({
          checkId: "COR001",
          severity: "high",
          title: "Live CORS reflects any origin with credentials",
          detail: "The server echoed back an origin this scanner invented and set Access-Control-Allow-Credentials: true. That means any website can make authenticated requests to this API as a logged-in user and read the response.",
          evidence: `access-control-allow-origin: ${allowOrigin}; access-control-allow-credentials: true`,
          location: url.href,
          cwe: "CWE-942",
          owasp: "A05:2021 Security Misconfiguration",
          cvss: 8.1,
          remediation: [
            { stack: "express", summary: "Replace the reflected origin with an allowlist.", code: `app.use(cors({ origin: ["https://yourapp.com"], credentials: true }));` },
            { stack: "any", summary: "Only echo the origin back when it is on a list of sites you trust." },
          ],
        }),
      );
    } else if (reflects) {
      findings.push(
        liveFinding({
          checkId: "COR001",
          severity: "medium",
          title: "Live CORS reflects any origin",
          detail: "The server echoed back an origin this scanner invented. Any website can read responses from this endpoint. That is fine for a fully public API, but not for anything user-specific.",
          evidence: `access-control-allow-origin: ${allowOrigin}`,
          location: url.href,
          cwe: "CWE-942",
          owasp: "A05:2021 Security Misconfiguration",
          cvss: 5.3,
          remediation: [{ stack: "any", summary: "Return a fixed allowlist of trusted origins instead of echoing the request origin." }],
        }),
      );
    } else if (wildcard && credentials) {
      // Browsers reject this combination, but seeing it means the config is confused.
      findings.push(
        liveFinding({
          checkId: "COR001",
          severity: "low",
          title: "CORS sends * together with credentials",
          detail: "Access-Control-Allow-Origin: * with Allow-Credentials: true is rejected by browsers, so credentialed cross-origin requests will fail. The config is contradictory and should be fixed.",
          evidence: "access-control-allow-origin: *; access-control-allow-credentials: true",
          location: url.href,
          cwe: "CWE-942",
          owasp: "A05:2021 Security Misconfiguration",
          remediation: [{ stack: "any", summary: "Decide whether the endpoint is public (keep *, drop credentials) or private (use an allowlist with credentials)." }],
        }),
      );
    }

    return findings;
  },
};
