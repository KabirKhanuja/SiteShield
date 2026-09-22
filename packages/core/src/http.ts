import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { Agent, fetch, type Response } from "undici";
import { TargetError, assertAllowedUrl, isPublicAddress } from "./target.ts";

export const USER_AGENT = "SiteShield/0.1 (+https://github.com/KabirKhanuja/SiteShield)";

const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 10_000;

type LookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string | LookupAddress[],
  family?: number,
) => void;

/**
 * Resolves like dns.lookup, then refuses to connect if any address is internal. Running
 * the check at connect time (instead of resolving once up front) also covers redirects
 * and DNS rebinding, where a name resolves to a public IP first and a private one later.
 */
function guardedLookup(hostname: string, options: { all?: boolean; family?: number }, callback: LookupCallback) {
  dnsLookup(hostname, { family: options.family ?? 0, all: true }, (err, addresses) => {
    if (err) return callback(err, []);
    const bad = addresses.find((a) => !isPublicAddress(a.address));
    if (bad || addresses.length === 0) {
      return callback(new TargetError(`${hostname} resolves to a private or reserved address.`), []);
    }
    if (options.all) return callback(null, addresses);
    const first = addresses[0]!;
    callback(null, first.address, first.family);
  });
}

const agent = new Agent({
  connect: { lookup: guardedLookup as never, timeout: TIMEOUT_MS },
  headersTimeout: TIMEOUT_MS,
  bodyTimeout: TIMEOUT_MS,
});

export type SafeResponse = {
  response: Response;
  finalUrl: URL;
  redirects: URL[];
};

/** fetch for user supplied targets: guarded DNS, manual redirects, each hop re-checked. */
export async function safeFetch(
  input: URL,
  init: { method?: "GET" | "HEAD"; signal?: AbortSignal } = {},
): Promise<SafeResponse> {
  const signal = init.signal
    ? AbortSignal.any([init.signal, AbortSignal.timeout(TIMEOUT_MS)])
    : AbortSignal.timeout(TIMEOUT_MS);

  let url = input;
  const redirects: URL[] = [];

  for (let hop = 0; ; hop++) {
    assertAllowedUrl(url);
    const response = await fetch(url, {
      method: init.method ?? "GET",
      redirect: "manual",
      dispatcher: agent,
      signal,
      headers: { "user-agent": USER_AGENT, accept: "text/html,*/*;q=0.8" },
    });

    const location = response.headers.get("location");
    if (response.status >= 300 && response.status < 400 && location) {
      await response.body?.cancel();
      if (hop >= MAX_REDIRECTS) throw new TargetError("Too many redirects.");
      url = new URL(location, url);
      redirects.push(url);
      continue;
    }
    return { response, finalUrl: url, redirects };
  }
}

/** Reads at most maxBytes of a body and cancels the rest, so a huge response cannot eat memory. */
export async function readLimited(response: Response, maxBytes: number): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (total < maxBytes) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.byteLength;
  }
  await reader.cancel().catch(() => {});
  return new TextDecoder().decode(Buffer.concat(chunks).subarray(0, maxBytes));
}
