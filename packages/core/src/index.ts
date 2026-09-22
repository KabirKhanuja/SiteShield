export { scan, liveChecks } from "./scan.ts";
export { scoreFindings, SEVERITY_POINTS, CONFIRMED_MULTIPLIER } from "./scoring.ts";
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
