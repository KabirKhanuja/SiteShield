import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { Db } from "./db.ts";

/**
 * The verification token is published in DNS, so anyone can read it and it cannot be the
 * thing that grants access. Instead each verification also gets a private key, returned
 * once, that the owner sends back as X-Ownership-Key. We only store its hash.
 */

export const OWNERSHIP_HEADER = "x-ownership-key";
export const VERIFICATION_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;

export function newOwnershipKey(): { key: string; hash: string } {
  const key = randomBytes(24).toString("base64url");
  return { key, hash: hashKey(key) };
}

export function hashKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

export function keyMatches(key: string | undefined, hash: string): boolean {
  if (!key) return false;
  const a = Buffer.from(hashKey(key), "hex");
  const b = Buffer.from(hash, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

/** True when this key belongs to a current, verified claim on the domain. */
export function holdsVerifiedDomain(db: Db, domain: string, key: string | undefined): boolean {
  return db.activeVerificationsFor(domain).some((v) => keyMatches(key, v.keyHash));
}
