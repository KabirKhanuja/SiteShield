import type { Severity } from "./types.ts";

/**
 * Shared secret patterns, used by the source secret check (SEC001) and the live "secrets in
 * shipped JavaScript" check (BND001). Keeping one list means a key caught in the code and
 * the same key caught in the bundle report identically, which is what lets them be paired.
 */

export type SecretPattern = { name: string; re: RegExp; severity: Severity; cwe: string };

export const PROVIDER_PATTERNS: SecretPattern[] = [
  { name: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/g, severity: "high", cwe: "CWE-798" },
  { name: "AWS secret access key", re: /\baws_secret_access_key\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/gi, severity: "critical", cwe: "CWE-798" },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_\-]{35}\b/g, severity: "high", cwe: "CWE-798" },
  { name: "Stripe secret key", re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/g, severity: "critical", cwe: "CWE-798" },
  { name: "Stripe test secret key", re: /\b(?:sk|rk)_test_[0-9a-zA-Z]{20,}\b/g, severity: "medium", cwe: "CWE-798" },
  { name: "GitHub token", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b/g, severity: "high", cwe: "CWE-798" },
  { name: "GitHub fine-grained token", re: /\bgithub_pat_[0-9A-Za-z_]{82}\b/g, severity: "high", cwe: "CWE-798" },
  { name: "Slack token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, severity: "high", cwe: "CWE-798" },
  { name: "SendGrid API key", re: /\bSG\.[\w-]{22}\.[\w-]{43}\b/g, severity: "high", cwe: "CWE-798" },
  { name: "Twilio account SID", re: /\bAC[0-9a-f]{32}\b/g, severity: "medium", cwe: "CWE-798" },
  { name: "npm access token", re: /\bnpm_[0-9A-Za-z]{36}\b/g, severity: "high", cwe: "CWE-798" },
  { name: "OpenAI API key", re: /\bsk-(?:proj-)?[0-9A-Za-z_\-]{20,}\b/g, severity: "high", cwe: "CWE-798" },
  { name: "Private key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, severity: "critical", cwe: "CWE-798" },
];

export function maskSecret(value: string): string {
  const v = value.trim().replace(/^['"]|['"]$/g, "");
  if (v.length <= 8) return "********";
  return v.slice(0, 4) + "…" + v.slice(-2);
}
