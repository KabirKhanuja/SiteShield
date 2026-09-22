import { randomBytes } from "node:crypto";
import { resolveTxt } from "node:dns/promises";
import { readLimited, safeFetch } from "./http.ts";

/**
 * Ownership proof, the same idea search consoles and certificate authorities use: we hand
 * out a random token, and only someone who controls the domain can publish it.
 */

export const TXT_PREFIX = "siteshield-verify=";
export const WELL_KNOWN_PATH = "/.well-known/siteshield.txt";

export function createVerificationToken(): string {
  return randomBytes(16).toString("hex");
}

export function verificationInstructions(domain: string, token: string) {
  return {
    dns: { name: `_siteshield.${domain}`, type: "TXT", value: `${TXT_PREFIX}${token}` },
    http: { url: `https://${domain}${WELL_KNOWN_PATH}`, contents: token },
  };
}

export type OwnershipResult = { verified: true; method: "dns" | "http" } | { verified: false; reason: string };

export async function checkOwnership(domain: string, token: string, signal?: AbortSignal): Promise<OwnershipResult> {
  try {
    const records = (await resolveTxt(`_siteshield.${domain}`)).map((r) => r.join("").trim());
    if (records.includes(`${TXT_PREFIX}${token}`)) return { verified: true, method: "dns" };
  } catch {
    // No record yet. Fall through to the HTTP method.
  }

  try {
    const { response } = await safeFetch(new URL(`https://${domain}${WELL_KNOWN_PATH}`), { signal });
    if (response.ok) {
      // The file only needs to hold a 32 character token. Never read an unbounded body.
      const body = await readLimited(response, 1024);
      if (body.split(/\s+/).includes(token)) return { verified: true, method: "http" };
    } else {
      await response.body?.cancel();
    }
  } catch {
    // Unreachable over HTTPS. Report the generic reason below.
  }

  return {
    verified: false,
    reason: `Did not find the token in a TXT record at _siteshield.${domain} or at https://${domain}${WELL_KNOWN_PATH}. DNS changes can take a few minutes to show up.`,
  };
}
