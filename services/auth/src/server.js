import { app } from "./app.js";
import { pool, migrate } from "./db.js";
import { loadConfig } from "./config.js";

const config = loadConfig();
let server;

async function start() {
  let lastError;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try { await migrate(); lastError = null; break; }
    catch (error) {
      lastError = error;
      if (attempt === 19) throw lastError;
      await new Promise((resolve) => setTimeout(resolve, Math.min(500 * (attempt + 1), 5000)));
    }
  }
  if (!config.databaseUrl) throw new Error("DATABASE_URL is required in production");
  server = app.listen(config.port, config.host, () => process.stdout.write(`PrivacyLint auth listening on ${config.host}:${config.port}\n`));
}

async function stop() {
  if (server) await new Promise((resolve) => server.close(resolve));
  await pool.end();
}

process.once("SIGINT", () => stop().finally(() => process.exit(0)));
process.once("SIGTERM", () => stop().finally(() => process.exit(0)));
start().catch(() => { process.stderr.write("Auth service could not start. Check database connectivity and configuration.\n"); process.exit(1); });

