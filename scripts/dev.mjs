import concurrently from "concurrently";
import { loadRootEnv } from "./env.mjs";

loadRootEnv();
process.env.USE_PGLITE ??= "true";
process.env.AUTH_HOST ??= "127.0.0.1";
const authPort = process.env.AUTH_PORT || "4000";
const enginePort = process.env.ENGINE_PORT || "8000";
const webPort = process.env.WEB_PORT || "5173";
process.env.VITE_AUTH_URL ??= `http://localhost:${authPort}`;
process.env.VITE_ENGINE_URL ??= `http://localhost:${enginePort}`;
if (process.env.NODE_ENV !== "production") {
  const allowedOrigins = (process.env.WEB_ORIGIN || "").split(",").map((origin) => origin.trim()).filter(Boolean);
  for (const host of ["localhost", "127.0.0.1"]) allowedOrigins.push(`http://${host}:${webPort}`);
  process.env.WEB_ORIGIN = [...new Set(allowedOrigins)].join(",");
}

const { result } = concurrently([
  { command: "npm --prefix services/auth run dev", name: "auth", prefixColor: "cyan" },
  { command: "node scripts/engine.mjs dev", name: "engine", prefixColor: "magenta" },
  { command: "npm --prefix apps/web run dev", name: "web", prefixColor: "green" },
], { prefix: "name", killOthers: ["failure"], restartTries: 0 });

result.then(() => process.exit(0)).catch(() => process.exit(1));
