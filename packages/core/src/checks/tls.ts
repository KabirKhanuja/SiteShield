import { lookup as dnsLookup } from "node:dns";
import { connect, type PeerCertificate } from "node:tls";
import { safeFetch } from "../http.ts";
import { TargetError, isPublicAddress } from "../target.ts";
import type { Finding } from "../types.ts";
import { liveFinding, type Check } from "./types.ts";

const DAY = 24 * 60 * 60 * 1000;
const HSTS_MIN_SECONDS = 180 * 24 * 60 * 60;

type Handshake = { authorized: boolean; error?: string; cert: PeerCertificate; protocol: string | null };

function handshake(host: string, port: number, signal?: AbortSignal): Promise<Handshake> {
  return new Promise((resolve, reject) => {
    const socket = connect({
      host,
      port,
      servername: host,
      // We want to inspect a bad certificate, not fail on it. Nothing is sent over this socket.
      rejectUnauthorized: false,
      timeout: 10_000,
      lookup: (hostname, options, cb) =>
        dnsLookup(hostname, options, (err, address, family) => {
          if (err) return cb(err, address, family);
          const list = Array.isArray(address) ? address : [{ address, family }];
          if (list.some((a) => !isPublicAddress(a.address))) {
            return cb(new TargetError(`${hostname} resolves to a private or reserved address.`), address, family);
          }
          cb(null, address, family);
        }),
    });
    const fail = (err: Error) => {
      socket.destroy();
      reject(err);
    };
    signal?.addEventListener("abort", () => fail(new Error("Scan cancelled.")), { once: true });
    socket.once("timeout", () => fail(new Error("TLS handshake timed out.")));
    socket.once("error", fail);
    socket.once("secureConnect", () => {
      const result: Handshake = {
        authorized: socket.authorized,
        error: socket.authorizationError?.toString(),
        cert: socket.getPeerCertificate(),
        protocol: socket.getProtocol(),
      };
      socket.end();
      resolve(result);
    });
  });
}

export const tlsCheck: Check = {
  id: "TLS001",
  layer: "live",
  mode: "passive",
  async run({ url, home, signal }) {
    const findings: Finding[] = [];

    if (home.finalUrl.protocol !== "https:") {
      findings.push(
        liveFinding({
          checkId: "TLS001",
          severity: "high",
          title: "Site is served over plain HTTP",
          detail: "Everything, including logins and cookies, travels unencrypted and can be read or changed by anyone on the network path.",
          evidence: `Final URL: ${home.finalUrl.href}`,
          remediation: [
            { stack: "vercel", summary: "Vercel serves HTTPS automatically once the domain is added to the project." },
            {
              stack: "nginx",
              summary: "Get a free certificate from Let's Encrypt and redirect port 80.",
              code: "sudo certbot --nginx -d yoursite.com",
            },
          ],
        }),
      );
      return findings;
    }

    const host = home.finalUrl.hostname;
    const hs = await handshake(host, Number(home.finalUrl.port) || 443, signal);

    if (!hs.authorized) {
      findings.push(
        liveFinding({
          checkId: "TLS001",
          severity: "high",
          title: "Certificate is not trusted",
          detail: "Browsers show a full page warning, and users who click through are open to interception.",
          evidence: hs.error,
          remediation: [{ stack: "any", summary: "Serve a certificate from a public CA (Let's Encrypt is free) that covers this hostname, with the full chain." }],
        }),
      );
    }

    if (hs.cert.valid_to) {
      const daysLeft = Math.floor((Date.parse(hs.cert.valid_to) - Date.now()) / DAY);
      if (daysLeft < 0) {
        findings.push(
          liveFinding({
            checkId: "TLS001",
            severity: "high",
            title: "Certificate has expired",
            detail: `It expired ${-daysLeft} days ago.`,
            evidence: `valid_to: ${hs.cert.valid_to}`,
            remediation: [{ stack: "any", summary: "Renew it, and set up automatic renewal so this does not happen again." }],
          }),
        );
      } else if (daysLeft < 14) {
        findings.push(
          liveFinding({
            checkId: "TLS001",
            severity: "medium",
            title: `Certificate expires in ${daysLeft} days`,
            detail: "If renewal is automatic it should have happened by now, which suggests it is failing.",
            evidence: `valid_to: ${hs.cert.valid_to}`,
            remediation: [{ stack: "any", summary: "Check your renewal job (certbot renew --dry-run) or your host's certificate settings." }],
          }),
        );
      }
    }

    if (hs.protocol === "TLSv1" || hs.protocol === "TLSv1.1") {
      findings.push(
        liveFinding({
          checkId: "TLS001",
          severity: "high",
          title: `Server negotiated ${hs.protocol}`,
          detail: "TLS 1.0 and 1.1 are deprecated and have known weaknesses. Modern clients expect 1.2 or 1.3.",
          remediation: [{ stack: "nginx", summary: "Allow only modern protocols.", code: "ssl_protocols TLSv1.2 TLSv1.3;" }],
        }),
      );
    }

    const hsts = home.response.headers.get("strict-transport-security");
    const maxAge = Number(hsts?.match(/max-age=(\d+)/i)?.[1] ?? 0);
    if (!hsts) {
      findings.push(
        liveFinding({
          checkId: "TLS001",
          severity: "medium",
          title: "No HSTS header",
          detail: "Browsers will still try plain HTTP first, which gives an attacker on the network a window to downgrade the connection.",
          remediation: [
            {
              stack: "nextjs",
              summary: "Add it to the headers() list in next.config.ts.",
              code: `{ key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" }`,
            },
            { stack: "nginx", summary: "Add it to the server block.", code: `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;` },
          ],
        }),
      );
    } else if (maxAge < HSTS_MIN_SECONDS) {
      findings.push(
        liveFinding({
          checkId: "TLS001",
          severity: "low",
          title: "HSTS max-age is short",
          detail: "A max-age under six months gives little protection between visits.",
          evidence: `strict-transport-security: ${hsts}`,
          remediation: [{ stack: "any", summary: "Use max-age=63072000 (two years) once HTTPS is stable." }],
        }),
      );
    }

    // Does plain HTTP send people to HTTPS?
    try {
      const plain = new URL(url.href);
      plain.protocol = "http:";
      plain.port = "";
      const { response, finalUrl } = await safeFetch(plain, { method: "HEAD", signal });
      await response.body?.cancel();
      if (finalUrl.protocol !== "https:") {
        findings.push(
          liveFinding({
            checkId: "TLS001",
            severity: "medium",
            title: "HTTP does not redirect to HTTPS",
            detail: "Visitors who type the address without https stay on an unencrypted page.",
            evidence: `${plain.href} answered ${response.status} without redirecting`,
            remediation: [
              { stack: "nginx", summary: "Redirect everything on port 80.", code: "server { listen 80; return 301 https://$host$request_uri; }" },
            ],
          }),
        );
      }
    } catch {
      // Port 80 closed entirely is fine: nothing is served in the clear.
    }

    return findings;
  },
};
