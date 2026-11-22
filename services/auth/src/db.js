import pg from "pg";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { loadConfig } from "./config.js";

const config = loadConfig();
const usePglite = process.env.USE_PGLITE === "true" && config.nodeEnv !== "production";
let embeddedDb = null;
let pgPool = null;

if (usePglite) {
  const { PGlite } = await import("@electric-sql/pglite");
  const dataDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../.local-db");
  embeddedDb = await PGlite.create(dataDir);
} else {
  pgPool = new pg.Pool({ connectionString: config.databaseUrl, max: 15, idleTimeoutMillis: 30_000 });
}

export const pool = usePglite
  ? { query: (sql, params) => embeddedDb.query(sql, params), end: () => embeddedDb.close() }
  : pgPool;

export async function migrate() {
  const filename = fileURLToPath(new URL("../migrations/001_init.sql", import.meta.url));
  const schema = await readFile(filename, "utf8");
  if (usePglite) await embeddedDb.exec(schema);
  else await pool.query(schema);
}

export async function withTransaction(fn) {
  if (usePglite) return embeddedDb.transaction((tx) => fn({ query: (sql, params) => tx.query(sql, params) }));
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally { client.release(); }
}

