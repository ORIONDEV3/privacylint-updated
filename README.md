# PrivacyLint

PrivacyLint is a DPDP Act 2023 privacy code-analysis platform for finding personal-data exposure in software, tracing data flows, and verifying fixes. This repository is being built in phases from the supplied product brief.

## Current build status

The local app includes email/password auth with SMTP OTP, password reset, a deterministic ZIP/GitHub scanner, findings and lineage views, inventory, verified-fix workflow, regression-test generation, and browser-side report exports. Gemini is called only by the server-side fixer and every proposed patch still has to pass a deterministic sandbox rescan. The UI has a working offline fallback.

Known limits: GitHub ingestion has not been live-tested against GitHub; PR creation is a clearly marked, unconnected panel; report exports are generated in the browser (there is no PDF or persisted report API); the security page does not expose the auth audit log; and the Google OAuth client still needs its local callback added in Google Cloud Console. This app is a local development build, not a deployed production service.

## Run locally

Requirements: Node.js 20+, npm, and Python 3.11+. `npm run dev` starts a persistent local PGlite database, auth API, and web client without Docker. Docker Compose is optional for the PostgreSQL/Neo4j/Redis/MailHog stack.

1. Install dependencies with `npm install`, then run `npm run dev`. The script starts the web, auth, and analysis services and uses on-disk local databases.
2. Open the web app at `http://localhost:5173` (or the configured `WEB_PORT`). The default auth and analysis ports are 4000 and 8000; all three can be changed in `.env`.
3. Without SMTP credentials, local development uses password-only sign-in and does not show an OTP screen. With `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, and `SMTP_PASS` set and `AUTH_OTP_MODE=email`, the server sends a real email before the verification screen opens. The UI never displays the code.
4. Copy `.env.example` to `.env` only when starting a fresh setup. Keep `.env` private and out of source control. Gemini and Google OAuth secrets are read by the backend and are never bundled into the web app.
5. To use Docker Compose, configure `.env` and run `docker compose up --build`. Compose uses PostgreSQL/Neo4j/Redis/MailHog. MailHog captures mail locally; it does not deliver to a real inbox.

The current local setup verifies SMTP credentials without sending a test message. Google sign-in stays disabled until the exact callback `http://localhost:4100/api/v1/auth/google/callback` is added to the OAuth client's authorized redirect URIs and `GOOGLE_OAUTH_ENABLED=true` is set. The supplied OAuth file did not include any authorized origins or redirect URIs.

## Analysis engine

The scanner parses supported source files with Tree-sitter, runs deterministic YAML-backed checks, and never executes uploaded code. ZIPs are limited to 50 MB, 5,000 entries, and 200 MB expanded source. Source bytes are analyzed in memory and are not persisted; only redacted findings and scan metadata are stored. Local scans use SQLite under `.local-db`; Compose uses PostgreSQL. GitHub PATs are used for the API request only and are not stored. The engine enforces the same signed session cookie and CSRF token as the auth service when `REQUIRE_AUTH=true` (enabled by default in Compose).

The analyzer's taint tracking is line-based. JavaScript/TypeScript Express route-to-controller association is name-based and cross-file; other languages use file and line-level category propagation. Treat results as deterministic code indicators for review, not a legal conclusion or proof of compliance.

Lineage data is scoped to the scan ID. Neo4j is used when configured and reachable; the offline fallback builds a NetworkX graph from the persisted findings. `GET /api/v1/scans/{id}/graph` returns JSON by default and accepts `format=graphml`, `format=svg`, or `format=png`. The inventory endpoint reports discovered dependency names, outbound hostnames (without URL paths or query strings), and file-level erasure coverage estimates.

```powershell
python -m venv services/engine/.venv
services/engine/.venv/Scripts/python.exe -m pip install -r services/engine/requirements-dev.txt
npm run dev:engine
services/engine/.venv/Scripts/python.exe -m app.cli scan .\demo-repo --format sarif
```

The CLI can compare or update a baseline with `--baseline .privacylint-baseline.json` and `--update-baseline`. A CI step can fail on new high or critical findings with the default `--fail-on high` behavior.

## Security notes

- OTPs are six-digit cryptographically generated values stored only as HMAC-SHA256 digests, expire after ten minutes, and are locked for 15 minutes after five incorrect attempts.
- Passwords use per-user salted scrypt. Session values are signed, stored server-side as hashes, rotated after OTP verification, and sent in HttpOnly, SameSite=Lax cookies. Google ID tokens are verified server-side before an existing account is linked.
- Authenticated state-changing requests require a session-bound CSRF header. CORS and write-request origin checks use the configured web origin allowlist.
- Audit metadata intentionally excludes email addresses, OTPs, passwords, tokens, and request bodies.
- Email sends use a serialized in-process queue with bounded exponential retry. The queue is not durable across process restarts; use a durable queue before horizontal production deployment.
- Email-based resend throttling is process-local. Deployments with multiple auth replicas should move rate-limit state to Redis before production.
- Production deployment still needs HTTPS, managed secret storage, database backup/restore procedures, monitoring, and a reviewed operational runbook.

## Workspace

```text
apps/web                 React + Vite + TypeScript auth interface
services/auth            Express auth and email service
services/engine          FastAPI API, Tree-sitter scanner, CLI, tests
rules/                   YAML DPDP analysis rules
templates/               Patch, test, and report templates (later phase)
demo-repo/               Vulnerable demonstration app (later phase)
docs/                    Architecture and API notes
```

## Checks

Run `npm test`, `npm run test:engine`, and `npm run build` from the repository root. Phase acceptance criteria are tracked in [CHECKLIST.md](CHECKLIST.md); an item is complete only after its corresponding check passes. Docker Compose has not been verified on this machine because Docker is not installed.

