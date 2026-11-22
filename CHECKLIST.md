# Phase checklist

Acceptance items remain unchecked until the listed behavior has been verified by automated tests or a working end-to-end run.

## Phase 1 — Auth, OTP, password reset, email

- [ ] Monorepo and Compose stack build and start cleanly.
- [ ] Registration validates input, stores a scrypt password hash, and sends a verification OTP.
- [ ] OTP expiry, one-time use, five-attempt lockout, and resend cooldown/rate limits work.
- [ ] Login requires password plus OTP before issuing a session.
- [ ] Forgot-password response does not reveal whether an account exists.
- [ ] Password reset invalidates every active session.
- [ ] Session cookies, CSRF, CORS, rate limits, and RBAC are enforced.
- [ ] Auth events are audited without credentials or PII in logs.
- [ ] Email retry and all required email templates are available.
- [ ] Auth UI is responsive, keyboard accessible, and covers loading/error/empty states.

## Phase 2 — Analysis Engine

- [x] ZIP size/count/expansion limits and zip-slip defense (pytest archive tests).
- [ ] GitHub PAT ingestion, rate-limit handling, and private repository flow (live GitHub integration not verified).
- [x] Deterministic Tree-sitter/YAML scanner and checksum/keyword PII detectors (pytest vulnerable and safe fixtures).
- [x] Line-level taint evidence and DPDP mappings for all 12 rules (pytest fixture).
- [x] Deterministic risk score, badge, SARIF, CLI, and baseline support (pytest/API tests).

## Phase 3 — Lineage graph

- [x] Scan-scoped Source/Route/Controller/Store/Sink/Finding graph and FLOWS_TO edges.
- [x] NetworkX fallback and JSON, GraphML, SVG, and PNG exports (pytest/API checks).
- [x] SDK/outbound-host inventory and per-file erasure coverage estimate (pytest).
- [ ] Neo4j persistence against a live service (Docker/Neo4j not available for this run).

## Phase 4 — Privacy unit test generator

- [x] Jinja templates cover all 12 rules and detect Jest, Mocha, node:test, pytest, and JUnit 5.
- [x] Generated static regression assertions fail on vulnerable fixture and pass on protected fixture for log, response, storage, route-auth, and weak-hash rules.
- [x] API refuses to generate tests for unverified findings; integration with sandbox-verified output follows Phase 5.

## Phase 5 — AI fixer

- [ ] Offline Tier-0 patch path and fail-closed Gemini validation gate.

## Phase 6 — PR bot

- [ ] Verified patch bundles and GitHub PR flow.

## Phase 7 — Reports

- [ ] Deterministic JSON/HTML/SARIF/Markdown/PDF reports with RBAC.

## Phase 8 — Full frontend

- [ ] Dashboard, scan, graph, fix, tests, PR, reports, badge, security, rules, and settings pages.

## Phase 9 — Demo and end-to-end flow

- [ ] Vulnerable demo repo and complete offline demo script.

