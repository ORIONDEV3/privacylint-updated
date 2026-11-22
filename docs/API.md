# API reference (Phase 1)

Base URL: `http://localhost:4000/api/v1/auth`

| Method | Path | Purpose |
|---|---|---|
| POST | `/register` | Create an account and send verification OTP |
| POST | `/verify-otp` | Consume registration or login OTP |
| POST | `/resend-otp` | Request another registration, login, or reset OTP |
| POST | `/login` | Verify password and start the OTP step |
| POST | `/forgot-password` | Request a reset OTP with an enumeration-safe response |
| POST | `/reset-password` | Consume reset OTP and replace password |
| POST | `/logout` | Revoke current server-side session |
| GET | `/me` | Return the current verified user |
| GET | `/csrf` | Return a session-bound CSRF value |

State-changing requests require an allowlisted `Origin`. Authenticated state-changing requests additionally require `X-CSRF-Token` from `/csrf` and the HttpOnly `pl_session` cookie. The API returns generic errors and never includes OTP or token values.

## Analysis engine

Base URL: `http://127.0.0.1:8000/api/v1`. Compose requires a valid auth session and CSRF header for scan operations. Local development binds to loopback and does not require a session.

| Method | Path | Purpose |
|---|---|---|
| GET | `/rules` | Return validated YAML rule metadata |
| POST | `/scans/upload` | Scan a multipart ZIP upload; optional `rules=PL001,PL002` field |
| POST | `/scans/github` | Scan `{owner,repo,ref?,token?}` from GitHub; token is not stored |
| GET | `/scans` | List recent scans for the current account |
| GET | `/scans/{id}` | Return a scan and redacted findings |
| GET | `/scans/{id}/sarif` | Export SARIF 2.1.0 |
| GET | `/scans/{id}/graph?format=json|graphml|svg|png` | Return or export scan-scoped lineage graph |
| GET | `/scans/{id}/inventory` | Return SDK, outbound-host, and erasure coverage metadata |
| POST | `/scans/{id}/tests` | Generate framework-aware regression test files for sandbox-verified findings only |
| GET | `/badge/{owner}/{repo}.svg` | Public cached score badge for GitHub scans |

ZIP ingestion rejects absolute/traversal paths, symlinks, encrypted entries, oversized archives, too many files, and extreme compression ratios. Archives are read without extraction and source code is never executed. Supported extensions include JavaScript, TypeScript, TSX, Python, Java, C/C++, and SQL; individual source files are limited to 1 MB.

