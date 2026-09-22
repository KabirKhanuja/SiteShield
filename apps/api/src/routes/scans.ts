import { randomUUID } from "node:crypto";
import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import { domainOf, normalizeTarget } from "@siteshield/core";
import { z } from "zod";
import type { Db } from "../db.ts";
import { HttpError } from "../errors.ts";
import type { JobEvent, ScanQueue } from "../jobs.ts";
import { OWNERSHIP_HEADER, holdsVerifiedDomain } from "../ownership.ts";

const createBody = z.object({
  url: z.string().min(1).max(2048),
  active: z.boolean().default(false),
});

const idParam = z.object({ id: z.uuid() });

export function scansRouter(db: Db, queue: ScanQueue, scansPerWindow: number) {
  const router = Router();

  // Every scan makes real requests to someone's server, so this is the endpoint worth
  // protecting most. Ten per ten minutes (the default) is plenty for a person and useless for abuse.
  const createLimit = rateLimit({
    windowMs: 10 * 60 * 1000,
    limit: scansPerWindow,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { error: { code: "rate_limited", message: "Too many scans from this address. Try again in a few minutes." } },
  });

  router.post("/", createLimit, (req, res) => {
    const body = createBody.parse(req.body);
    const target = normalizeTarget(body.url);

    if (body.active && !holdsVerifiedDomain(db, domainOf(target), req.get(OWNERSHIP_HEADER))) {
      throw new HttpError(
        403,
        "ownership_required",
        `Active checks need a verified claim on ${domainOf(target)}. Verify ownership first and send the key in the X-Ownership-Key header.`,
      );
    }

    const id = randomUUID();
    db.createScan(id, target.origin, body.active);
    queue.enqueue(id, { url: target.origin, active: body.active });

    res
      .status(202)
      .location(`/api/scans/${id}`)
      .json({ id, target: target.origin, status: "queued", links: { self: `/api/scans/${id}`, events: `/api/scans/${id}/events` } });
  });

  // Scan ids are random UUIDs and there is no endpoint that lists them, so knowing the id is
  // what lets you read a report. Nobody can browse other people's targets.
  router.get("/:id", (req, res) => {
    const { id } = idParam.parse(req.params);
    const scan = db.getScan(id);
    if (!scan) throw new HttpError(404, "not_found", "No scan with that id.");
    res.json(scan);
  });

  router.get("/:id/events", (req, res) => {
    const { id } = idParam.parse(req.params);
    const scan = db.getScan(id);
    if (!scan) throw new HttpError(404, "not_found", "No scan with that id.");

    res.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    });
    const send = (e: JobEvent) => res.write(`event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`);

    if (scan.status === "done") {
      send({ type: "done", grade: scan.grade!, score: scan.score! });
      res.end();
      return;
    }
    if (scan.status === "failed") {
      send({ type: "failed", error: scan.error ?? "The scan failed." });
      res.end();
      return;
    }

    send({ type: "status", status: scan.status });
    const heartbeat = setInterval(() => res.write(": keepalive\n\n"), 15_000);
    const unsubscribe = queue.subscribe(id, (e) => {
      send(e);
      if (e.type === "done" || e.type === "failed") close();
    });
    function close() {
      clearInterval(heartbeat);
      unsubscribe();
      res.end();
    }
    req.on("close", close);
  });

  return router;
}
