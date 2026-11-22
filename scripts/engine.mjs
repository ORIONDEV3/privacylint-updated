import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadRootEnv } from "./env.mjs";

loadRootEnv();
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const python = path.join(root, "services", "engine", ".venv", process.platform === "win32" ? "Scripts" : "bin", process.platform === "win32" ? "python.exe" : "python");
const mode = process.argv[2];

if (!existsSync(python)) {
  process.stderr.write("Engine venv is missing. Create it and install services/engine/requirements-dev.txt first.\n");
  process.exit(2);
}

const args = mode === "dev"
  ? ["-m", "uvicorn", "app.main:app", "--app-dir", "services/engine", "--host", "127.0.0.1", "--port", process.env.ENGINE_PORT || "8000"]
  : mode === "test"
    ? ["-m", "pytest", "services/engine/tests", "-q"]
    : null;

if (!args) {
  process.stderr.write("Usage: node scripts/engine.mjs <dev|test>\n");
  process.exit(2);
}

const child = spawn(python, args, { cwd: root, stdio: "inherit", windowsHide: true });
child.on("error", () => process.exit(1));
child.on("exit", (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
