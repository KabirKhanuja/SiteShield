import { scan, sourceFilesFromUploads } from "@siteshield/core";
import express, { Router } from "express";
import { rateLimit } from "express-rate-limit";
import { z } from "zod";
import { HttpError } from "../errors.ts";

// A single file we will accept from the browser. Content is capped so one giant generated
// file cannot blow past the body limit on its own.
const fileSchema = z.object({
  path: z.string().min(1).max(1024),
  content: z.string().max(1_000_000),
});

const createBody = z.object({
  files: z.array(fileSchema).min(1).max(3000),
  // Off by default so the dependency check can look versions up on OSV.dev for the demo.
  offline: z.boolean().default(false),
});

/**
 * Scans source code uploaded from the browser. Unlike the live scan this is stateless and
 * synchronous: the code never touches disk and nothing is stored, so there is no scan id.
 */
export function sourceScansRouter(scansPerWindow: number) {
  const router = Router();

  const createLimit = rateLimit({
    windowMs: 10 * 60 * 1000,
    limit: scansPerWindow,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { error: { code: "rate_limited", message: "Too many scans from this address. Try again in a few minutes." } },
  });

  // Source payloads are larger than the live-scan JSON, so this route gets its own body limit.
  router.post("/", createLimit, express.json({ limit: "12mb" }), async (req, res) => {
    const body = createBody.parse(req.body);
    const files = sourceFilesFromUploads(body.files);
    if (files.length === 0) {
      throw new HttpError(
        400,
        "no_source",
        "None of the uploaded files could be scanned. They were all skipped as dependencies, build output, binaries, or unsupported file types.",
      );
    }

    const report = await scan({ srcFiles: files, offline: body.offline });
    res.json({ report, scanned: files.length });
  });

  return router;
}
