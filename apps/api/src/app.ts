import cors from "cors";
import express from "express";
import { rateLimit } from "express-rate-limit";
import helmet from "helmet";
import type { Config } from "./config.ts";
import type { Db } from "./db.ts";
import { errorHandler, notFound } from "./errors.ts";
import type { ScanQueue } from "./jobs.ts";
import { OWNERSHIP_HEADER } from "./ownership.ts";
import { scansRouter } from "./routes/scans.ts";
import { verificationsRouter } from "./routes/verifications.ts";

export function createApp(config: Config, db: Db, queue: ScanQueue) {
  const app = express();

  // Only trust X-Forwarded-For from proxies we know about, or anyone could fake their IP
  // and walk straight past the rate limits.
  app.set("trust proxy", config.TRUST_PROXY);

  // A security tool should pass its own scan: helmet sets the headers HDR001 looks for.
  app.use(helmet());
  app.use(
    cors({
      origin: config.WEB_ORIGINS,
      methods: ["GET", "POST"],
      allowedHeaders: ["content-type", OWNERSHIP_HEADER],
      maxAge: 600,
    }),
  );
  app.use(express.json({ limit: "10kb" }));
  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000,
      limit: 300,
      standardHeaders: "draft-8",
      legacyHeaders: false,
      message: { error: { code: "rate_limited", message: "Too many requests. Slow down a little." } },
    }),
  );

  app.get("/health", (_req, res) => {
    res.json({ ok: true });
  });
  app.use("/api/scans", scansRouter(db, queue, config.SCANS_PER_10_MIN));
  app.use("/api/verifications", verificationsRouter(db));

  app.use(notFound);
  app.use(errorHandler);
  return app;
}
