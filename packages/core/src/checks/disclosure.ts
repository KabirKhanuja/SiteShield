import { readLimited, safeFetch } from "../http.ts";
import type { Finding } from "../types.ts";
import { liveFinding, type Check } from "./types.ts";

/**
 * DSC001 - whether the site publishes a security.txt. It is a small file at a well-known
 * path (RFC 9116) that tells security researchers how to report a vulnerability. Having one
 * is a responsible-disclosure best practice; this only reads a public file.
 */

const PATHS = ["/.well-known/security.txt", "/security.txt"];

export const disclosureCheck: Check = {
  id: "DSC001",
  layer: "live",
  mode: "passive",
  async run({ url, signal }) {
    for (const path of PATHS) {
      try {
        const { response } = await safeFetch(new URL(path, url), { method: "GET", signal });
        if (response.ok) {
          const body = (await readLimited(response, 4096)).toLowerCase();
          if (body.includes("contact:")) return []; // A valid-looking security.txt exists.
        } else {
          await response.body?.cancel();
        }
      } catch {
        // Keep trying the next path.
      }
    }

    return [
      liveFinding({
        checkId: "DSC001",
        severity: "info",
        title: "No security.txt for reporting vulnerabilities",
        detail: "The site has no /.well-known/security.txt. That file gives researchers a clear, standard way to report a security problem to you (RFC 9116). It does not fix a vulnerability, but it shortens the path to hearing about one.",
        location: new URL("/.well-known/security.txt", url).href,
        owasp: "A05:2021 Security Misconfiguration",
        remediation: [
          {
            stack: "any",
            summary: "Publish a security.txt at /.well-known/security.txt with a contact and an expiry date.",
            code: `Contact: mailto:security@${url.hostname.replace(/^www\./, "")}\nExpires: 2027-01-01T00:00:00Z`,
          },
        ],
      }),
    ];
  },
};
