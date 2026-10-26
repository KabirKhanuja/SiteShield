export { scan, liveChecks } from "./scan.ts";
export { scoreFindings, SEVERITY_POINTS, CONFIRMED_MULTIPLIER } from "./scoring.ts";
export { correlate, diffReports, fingerprint } from "./correlate.ts";
export { scanSource, sourceChecks } from "./source/index.ts";
export type { SourceScanResult, SourceScanOptions } from "./source/index.ts";
export { detectStacks } from "./source/stack.ts";
export { walkSource } from "./source/walk.ts";
export { PROVIDER_PATTERNS, maskSecret } from "./secret-patterns.ts";
export { normalizeTarget, domainOf, isPublicAddress, assertAllowedUrl, TargetError } from "./target.ts";
export {
  checkOwnership,
  createVerificationToken,
  verificationInstructions,
  TXT_PREFIX,
  WELL_KNOWN_PATH,
  type OwnershipResult,
} from "./verify.ts";
export type * from "./types.ts";
