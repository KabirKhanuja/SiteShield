import { randomUUID } from "node:crypto";
import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import { checkOwnership, createVerificationToken, domainOf, normalizeTarget, verificationInstructions } from "@siteshield/core";
import { z } from "zod";
import type { Db, VerificationRow } from "../db.ts";
import { HttpError } from "../errors.ts";
import { OWNERSHIP_HEADER, VERIFICATION_LIFETIME_MS, keyMatches, newOwnershipKey } from "../ownership.ts";

const createBody = z.object({ domain: z.string().min(1).max(253) });
const idParam = z.object({ id: z.uuid() });

function publicView(v: VerificationRow) {
  return {
    id: v.id,
    domain: v.domain,
    verified: v.verifiedAt !== null && v.expiresAt !== null && v.expiresAt > new Date().toISOString(),
    method: v.method,
    verifiedAt: v.verifiedAt,
    expiresAt: v.expiresAt,
    instructions: verificationInstructions(v.domain, v.token),
  };
}

export function verificationsRouter(db: Db) {
  const router = Router();

  const limit = rateLimit({
    windowMs: 10 * 60 * 1000,
    limit: 30,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { error: { code: "rate_limited", message: "Too many verification requests. Try again in a few minutes." } },
  });
  router.use(limit);

  router.post("/", (req, res) => {
    const { domain: input } = createBody.parse(req.body);
    // Same validation as scan targets, so nobody can verify "localhost" or an internal name.
    const domain = domainOf(normalizeTarget(input));
    const id = randomUUID();
    const token = createVerificationToken();
    const { key, hash } = newOwnershipKey();
    db.createVerification({ id, domain, token, keyHash: hash });

    res.status(201).json({
      ...publicView(db.getVerification(id)!),
      key,
      note: "Publish the token with either method below, then call the check endpoint. Keep the key private: it is shown once and you need it for active scans.",
    });
  });

  function load(id: string, key: string | undefined): VerificationRow {
    const v = db.getVerification(id);
    // Same answer for "no such id" and "wrong key", so ids cannot be probed.
    if (!v || !keyMatches(key, v.keyHash)) throw new HttpError(404, "not_found", "No verification with that id and key.");
    return v;
  }

  router.get("/:id", (req, res) => {
    const { id } = idParam.parse(req.params);
    res.json(publicView(load(id, req.get(OWNERSHIP_HEADER))));
  });

  router.post("/:id/check", async (req, res) => {
    const { id } = idParam.parse(req.params);
    const v = load(id, req.get(OWNERSHIP_HEADER));

    const result = await checkOwnership(v.domain, v.token, AbortSignal.timeout(15_000));
    if (!result.verified) {
      res.status(409).json({ ...publicView(v), error: { code: "not_verified", message: result.reason } });
      return;
    }
    db.markVerified(id, result.method, new Date(Date.now() + VERIFICATION_LIFETIME_MS));
    res.json(publicView(db.getVerification(id)!));
  });

  return router;
}
