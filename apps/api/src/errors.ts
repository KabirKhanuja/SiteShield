import type { ErrorRequestHandler, RequestHandler } from "express";
import { TargetError } from "@siteshield/core";
import { ZodError } from "zod";

export class QueueFullError extends Error {}

/** Errors we mean to show the caller. Anything else becomes a generic 500. */
export class HttpError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

/** Turns low level network errors into something a person can act on. */
export function describeScanError(err: unknown): string {
  const e = err as Error & { cause?: { code?: string; message?: string } };
  if (e.name === "TimeoutError") return "The scan took longer than 90 seconds and was stopped.";
  if (e instanceof TargetError) return e.message;
  const code = e.cause?.code;
  if (code === "ENOTFOUND") return "That domain does not resolve. Check the spelling.";
  if (code === "ECONNREFUSED") return "The site refused the connection.";
  if (code === "UND_ERR_CONNECT_TIMEOUT") return "The site did not answer in time.";
  if (e.cause instanceof TargetError) return (e.cause as Error).message;
  return e.cause?.message ?? e.message ?? "The scan failed.";
}

export const notFound: RequestHandler = (_req, res) => {
  res.status(404).json({ error: { code: "not_found", message: "No such endpoint." } });
};

export const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
  if (err instanceof ZodError) {
    res.status(400).json({
      error: {
        code: "invalid_request",
        message: err.issues.map((i) => `${i.path.join(".") || "body"}: ${i.message}`).join("; "),
      },
    });
    return;
  }
  if (err instanceof TargetError) {
    res.status(400).json({ error: { code: "invalid_target", message: err.message } });
    return;
  }
  if (err instanceof QueueFullError) {
    res.status(503).set("retry-after", "60").json({ error: { code: "busy", message: err.message } });
    return;
  }
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: { code: err.code, message: err.message } });
    return;
  }
  // express.json() rejects bad or oversized bodies with a status on the error.
  const status = (err as { status?: number }).status;
  if (status && status >= 400 && status < 500) {
    res.status(status).json({ error: { code: "bad_request", message: "The request body could not be read." } });
    return;
  }
  console.error(err);
  res.status(500).json({ error: { code: "internal", message: "Something went wrong on our side." } });
};
