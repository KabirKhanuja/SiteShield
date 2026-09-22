import { EventEmitter } from "node:events";
import { scan as defaultScan, type Report, type ScanEvent, type ScanOptions } from "@siteshield/core";
import type { Db } from "./db.ts";
import { QueueFullError, describeScanError } from "./errors.ts";

export type JobEvent =
  | ScanEvent
  | { type: "status"; status: "queued" | "running" }
  | { type: "done"; grade: string; score: number }
  | { type: "failed"; error: string };

type Job = { id: string; options: ScanOptions };

const SCAN_TIMEOUT_MS = 90_000;
const MAX_QUEUED = 50;

/**
 * Scans take tens of seconds, far longer than a request should stay open. So a POST only
 * queues the job, and this runs a few at a time in the background. Progress goes out as
 * events that the SSE endpoint forwards to the browser.
 */
export class ScanQueue {
  private waiting: Job[] = [];
  private running = 0;
  private events = new EventEmitter();

  constructor(
    private db: Db,
    private concurrency: number,
    private runScan: typeof defaultScan = defaultScan,
  ) {
    // One listener per open SSE connection, keyed by scan id. Many tabs is fine.
    this.events.setMaxListeners(0);
  }

  enqueue(id: string, options: ScanOptions) {
    if (this.waiting.length >= MAX_QUEUED) throw new QueueFullError("Too many scans are waiting. Try again in a minute.");
    this.waiting.push({ id, options });
    this.emit(id, { type: "status", status: "queued" });
    this.drain();
  }

  subscribe(id: string, listener: (e: JobEvent) => void): () => void {
    this.events.on(id, listener);
    return () => this.events.off(id, listener);
  }

  /** Resolves once nothing is queued or running. Used by tests and graceful shutdown. */
  async idle(): Promise<void> {
    while (this.running > 0 || this.waiting.length > 0) {
      await new Promise((r) => setTimeout(r, 20));
    }
  }

  private emit(id: string, e: JobEvent) {
    this.events.emit(id, e);
  }

  private drain() {
    while (this.running < this.concurrency && this.waiting.length > 0) {
      const job = this.waiting.shift()!;
      this.running++;
      void this.run(job).finally(() => {
        this.running--;
        this.drain();
      });
    }
  }

  private async run({ id, options }: Job) {
    this.db.markRunning(id);
    this.emit(id, { type: "status", status: "running" });
    try {
      const report: Report = await this.runScan(
        { ...options, signal: AbortSignal.timeout(SCAN_TIMEOUT_MS) },
        (e) => this.emit(id, e),
      );
      this.db.markDone(id, report);
      this.emit(id, { type: "done", grade: report.grade, score: report.score });
    } catch (err) {
      const message = describeScanError(err);
      this.db.markFailed(id, message);
      this.emit(id, { type: "failed", error: message });
    }
  }
}
