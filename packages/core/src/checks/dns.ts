import { resolveTxt } from "node:dns/promises";
import { domainOf } from "../target.ts";
import type { Finding } from "../types.ts";
import { liveFinding, type Check } from "./types.ts";

// DKIM keys live under a selector the sender picks, and DNS cannot list them. These are
// the selectors the big mail providers use, which covers most small sites.
const COMMON_DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "k1", "mail", "dkim", "s1", "s2"];

async function txt(name: string): Promise<string[]> {
  try {
    return (await resolveTxt(name)).map((chunks) => chunks.join(""));
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENODATA" || code === "ENOTFOUND") return [];
    throw err;
  }
}

export const dnsCheck: Check = {
  id: "DNS001",
  layer: "live",
  mode: "passive",
  async run({ url }) {
    const domain = domainOf(url);
    const findings: Finding[] = [];

    const [root, dmarcRecords, ...dkim] = await Promise.all([
      txt(domain),
      txt(`_dmarc.${domain}`),
      ...COMMON_DKIM_SELECTORS.map((s) => txt(`${s}._domainkey.${domain}`)),
    ]);

    const spf = root!.find((r) => r.toLowerCase().startsWith("v=spf1"));
    if (!spf) {
      findings.push(
        liveFinding({
          checkId: "DNS001",
          severity: "medium",
          title: "No SPF record",
          detail: `Nothing tells mail servers which hosts may send mail for ${domain}, so forged mail is harder to reject. Even a domain that sends no mail should say so.`,
          remediation: [
            {
              stack: "any",
              summary: "If the domain never sends mail, publish a record that rejects everything. Otherwise list your provider, for example include:_spf.google.com.",
              code: `${domain}.  TXT  "v=spf1 -all"`,
            },
          ],
        }),
      );
    } else if (/\+all\b/.test(spf)) {
      findings.push(
        liveFinding({
          checkId: "DNS001",
          severity: "high",
          title: "SPF allows every server on the internet",
          detail: "+all means any host may send mail as your domain, which is worse than having no SPF at all.",
          evidence: spf,
          remediation: [{ stack: "any", summary: "End the record with -all or ~all instead of +all." }],
        }),
      );
    }

    const dmarc = dmarcRecords!.find((r) => r.toLowerCase().startsWith("v=dmarc1"));
    const policy = dmarc?.match(/\bp=(\w+)/i)?.[1]?.toLowerCase();
    if (!dmarc) {
      findings.push(
        liveFinding({
          checkId: "DNS001",
          severity: "medium",
          title: "No DMARC record",
          detail: "Without DMARC, receiving servers have no instruction for mail that fails SPF and DKIM, so spoofed mail from your domain often lands in inboxes.",
          remediation: [
            {
              stack: "any",
              summary: "Start with quarantine and a reporting address, then move to reject once reports look clean.",
              code: `_dmarc.${domain}.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@${domain}"`,
            },
          ],
        }),
      );
    } else if (policy === "none") {
      findings.push(
        liveFinding({
          checkId: "DNS001",
          severity: "low",
          title: "DMARC policy is p=none",
          detail: "The record exists but only monitors. Spoofed mail still gets delivered.",
          evidence: dmarc,
          remediation: [{ stack: "any", summary: "Move to p=quarantine, then p=reject, once your reports show legitimate mail passing." }],
        }),
      );
    }

    if (!dkim.some((records) => records.some((r) => /v=dkim1|k=rsa|p=/i.test(r)))) {
      findings.push(
        liveFinding({
          checkId: "DNS001",
          severity: "info",
          title: "No DKIM key found under common selectors",
          detail: `Checked ${COMMON_DKIM_SELECTORS.join(", ")}. Your provider may use a different selector, so this is a hint rather than a finding.`,
          remediation: [{ stack: "any", summary: "Turn on DKIM signing in your mail provider and publish the key it gives you." }],
        }),
      );
    }

    return findings;
  },
};
