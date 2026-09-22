import { loadConfig } from "./config.ts";
import { openDatabase } from "./db.ts";
import { createApp } from "./app.ts";
import { ScanQueue } from "./jobs.ts";

const config = loadConfig();
const db = openDatabase(config.DATABASE_PATH);
const queue = new ScanQueue(db, config.SCAN_CONCURRENCY);
const app = createApp(config, db, queue);

const server = app.listen(config.PORT, config.HOST, () => {
  console.log(`SiteShield API listening on http://${config.HOST}:${config.PORT}`);
});

function shutdown() {
  console.log("Shutting down, waiting for running scans to finish");
  server.close();
  void queue.idle().then(() => {
    db.close();
    process.exit(0);
  });
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
