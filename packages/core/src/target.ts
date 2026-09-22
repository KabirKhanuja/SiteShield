import { BlockList, isIP } from "node:net";

/**
 * A scanner that fetches whatever URL it is given is a textbook SSRF tool: point it at
 * 127.0.0.1, 169.254.169.254 or a LAN address and it will happily read internal services.
 * Everything that leaves this process for a user supplied host goes through these checks.
 */

// Two lists on purpose: BlockList also tests IPv4 addresses against IPv6 rules (as
// ::ffff:a.b.c.d), so the IPv4 mapped rule below would block every IPv4 address.
const blockedV4 = new BlockList();
const blockedV6 = new BlockList();

for (const [net, prefix] of [
  ["0.0.0.0", 8], // "this" network
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // carrier grade NAT
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link local, includes cloud metadata endpoints
  ["172.16.0.0", 12], // private
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // documentation
  ["192.88.99.0", 24], // 6to4 relay anycast
  ["192.168.0.0", 16], // private
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // documentation
  ["203.0.113.0", 24], // documentation
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved and broadcast
] as const) {
  blockedV4.addSubnet(net, prefix, "ipv4");
}

for (const [net, prefix] of [
  ["::", 128], // unspecified
  ["::1", 128], // loopback
  ["::ffff:0:0", 96], // IPv4 mapped, would smuggle any IPv4 address past the list above
  ["64:ff9b::", 96], // NAT64, same problem
  ["100::", 64], // discard only
  ["2001::", 32], // Teredo
  ["2001:db8::", 32], // documentation
  ["2002::", 16], // 6to4, embeds IPv4
  ["fc00::", 7], // unique local
  ["fe80::", 10], // link local
  ["ff00::", 8], // multicast
] as const) {
  blockedV6.addSubnet(net, prefix, "ipv6");
}

const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".home.arpa", ".lan"];
const ALLOWED_PORTS = new Set(["", "80", "443", "8080", "8443"]);

export class TargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TargetError";
  }
}

export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 0) return false;
  return family === 4 ? !blockedV4.check(address, "ipv4") : !blockedV6.check(address, "ipv6");
}

/** Throws unless the URL is http(s), on a normal port, and not obviously internal. */
export function assertAllowedUrl(url: URL): void {
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new TargetError("Only http and https URLs can be scanned.");
  }
  if (url.username || url.password) {
    throw new TargetError("URLs with credentials in them are not accepted.");
  }
  if (!ALLOWED_PORTS.has(url.port)) {
    throw new TargetError("Only ports 80, 443, 8080 and 8443 can be scanned.");
  }

  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) {
    throw new TargetError("Local and internal hostnames cannot be scanned.");
  }
  // A literal IP never goes through DNS lookup, so the connect time check below would not
  // see it. Check it here instead.
  if (isIP(host) !== 0 && !isPublicAddress(host)) {
    throw new TargetError("Private, loopback and reserved addresses cannot be scanned.");
  }
  if (isIP(host) === 0 && !host.includes(".")) {
    throw new TargetError("Use a full domain name, for example example.com.");
  }
}

/** Accepts "example.com", "https://example.com/path" and so on. Returns the site origin. */
export function normalizeTarget(input: string): URL {
  const trimmed = input.trim();
  if (!trimmed) throw new TargetError("Enter a URL to scan.");

  let url: URL;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
  } catch {
    throw new TargetError("That does not look like a valid URL.");
  }
  assertAllowedUrl(url);
  return new URL(url.origin);
}

/** The registrable part we verify ownership for. Keeps it simple: the hostname without www. */
export function domainOf(url: URL): string {
  return url.hostname.toLowerCase().replace(/^www\./, "");
}
