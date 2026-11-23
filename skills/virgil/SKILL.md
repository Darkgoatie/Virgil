---
name: virgil
description: Use when auditing a repository for vulnerabilities, reviewing code or configs for security flaws, hardening websites, APIs, secrets, databases, CI/CD, containers, or AI agents, or verifying a project before deployment.
---

# Virgil

## Overview and Modes

Virgil is a fail-closed repository security auditor and hardening baseline grounded in OWASP Top 10:2025, ASVS v5.0, OWASP API Top 10, NIST SP 800-series, SLSA, CIS Benchmarks, MITRE CWE/ATLAS, and MCP security specifications.

- **Audit Mode (default on repo reviews, checks, or security audits):** Map the attack surface, execute the deterministic pre-scanner, read only relevant domain references, inspect code semantically across trust boundaries, and emit the exact `[RED]` / `[YELLOW]` vulnerability report.
- **Hardening / Build Mode (when writing or modifying code/configs):** Enforce every `[RED]` rule as a hard block before writing code, load the matching `references/*.md` files, and verify fixes with real test or scanner output before claiming completion.

---

## Severity Classification

### `[RED]` — Serious (Directly Exploitable or High-Impact)
- **Exposed Secrets & Client-End Key Leaks:** Hardcoded API keys, tokens, private keys, or inline DB passwords in source, tracked `.env`/key files, public frontend env vars (`NEXT_PUBLIC_*`, `VITE_*`, `EXPO_PUBLIC_*`, `REACT_APP_*`, `NUXT_PUBLIC_*`) holding privileged credentials, compiled frontend bundles (`dist/`, `.next/`, `build/`, `out/`), web-root `.env`/`.git` exposure, or client-side Supabase `anon` / Firebase config lacking strict RLS or Security Rules.
- **Broken Access Control:** Missing object-level ownership checks (`BOLA`/`IDOR`), missing function/admin/verb checks (`BFLA`), trusting client-supplied `X-Tenant-ID`/`org_id`, missing `FORCE ROW LEVEL SECURITY` in multi-tenant tables, or mass assignment binding raw `req.body` directly to ORM models (`BOPLA`).
- **Injection & Execution Sinks:** SQL injection (string concatenation/interpolation or `*Unsafe` ORM calls), NoSQL operator injection (`$where`, unvalidated MongoDB filter objects), LDAP/Search injection, SSTI, XSS (`dangerouslySetInnerHTML`, `v-html`, unescaped DOM sinks), `eval()`/`new Function()`, shell injection (`shell=True`), unsafe deserialization (`pickle.loads`, unguarded `yaml.load`), prototype pollution, path traversal, or unvalidated executable/SVG file uploads.
- **Broken Auth, Crypto & Transport:** `jwt.decode()` without signature verification, `alg: "none"`, `HS256`/`RS256` algorithm confusion, disabled TLS verification (`verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`), `sslmode=disable|allow|prefer|require` instead of `verify-full`, `MD5`/`SHA-1` password hashing, `AES-ECB` or static IVs, CORS wildcard/`Origin` reflection paired with `credentials: true`, or missing raw-body constant-time webhook HMAC validation.
- **Critical Infra, CI/CD & Client Runtime Exposure:** `0.0.0.0/0` DB/SSH/admin ingress, public object-storage buckets, privileged/UID-0 containers or `/var/run/docker.sock` mounts, GitHub Actions `pull_request_target` checking out PR head code or `${{ github.event.* }}` inside `run:`, IMDSv1 (`HttpTokens: optional`), Electron `nodeIntegration: true` / `contextIsolation: false` / `webSecurity: false`, or unverified/hallucinated packages (slopsquatting).
- **High-Impact AI Agent Flaws:** Untrusted external data reaching state-mutating or code-executing tools without IFC/HITL isolation, MCP token passthrough or missing `aud`/RFC 8707 checks, raw host credentials inside sandbox `env`, or unsanitized LLM output flowing into HTML/SQL/shell sinks.

### `[YELLOW]` — Less Serious (Hardening & Defense-in-Depth)
- **Browser, Header & Client Hygiene:** Missing or weak nonce CSP (`'unsafe-inline'`/`'unsafe-eval'`), HSTS, `X-Content-Type-Options: nosniff`, `frame-ancestors` / `X-Frame-Options`, COOP/COEP/CORP, `Referrer-Policy`, `Permissions-Policy`, missing `__Host-`/cookie hardening or Fetch Metadata checks, or publicly shipped `.js.map`/`.css.map` source maps.
- **API & Protocol Hardening:** Missing IP/tenant rate limits, unbounded pagination, missing GraphQL depth/complexity/batch caps, enabled prod GraphQL introspection or gRPC reflection, missing webhook timestamp tolerance (`<=5m`) or `event_id` idempotency.
- **CI/CD, Supply Chain & Container Hygiene:** Unpinned GitHub Actions (`@v4`/`@main` instead of 40-char commit SHA), missing top-level `permissions:` on `GITHUB_TOKEN`, mutable `:latest` container tags, missing non-root `USER`, missing `npm ci` / `--frozen-lockfile` / `--ignore-scripts`, missing SBOM/SAST CI gates, or `DEBUG=true` in prod/Docker configs.
- **Crypto, Observability & Ops Hygiene:** Weak password-hashing parameters (`Argon2id` below OWASP floor, unguarded 72-byte `bcrypt`), non-AEAD TLS 1.2 ciphers, `MD5`/`SHA-1` in non-password hashes, verbose client errors instead of RFC 7807, unredacted structured logs, missing `pgAudit`/DDL `lock_timeout`/restore drills, missing `SECURITY.md`/`security.txt`, or missing agent step/budget caps and off-sandbox OTel audit logs.

---

## Audit Procedure (Execute in Order)

### Step 0: Check for Skill Updates (Non-Blocking)
Run the read-only update check against `Darkgoatie/Virgil` on GitHub. It never downloads or executes remote code and always exits `0`, so offline audits are not blocked:

```bash
python3 scripts/check_update.py
pwsh -NoProfile -File scripts/check_update.ps1
```

If the output starts with `[UPDATE AVAILABLE]`, add one `Update notice` bullet to the report `Summary` with the printed upgrade command. Never update the skill yourself during an audit.

### Step 1: Map the Attack Surface
Inventory frameworks, entrypoints/routes, frontend public folders and compiled build outputs (`dist/`, `.next/`, `build/`, `out/`), auth/session modules, DB/ORM/cache/bucket configs, Docker/K8s/Terraform manifests, `.github/workflows/`, and LLM/MCP tool integrations.

### Step 2: Run the Bundled Pre-Scanner
Invoke the pre-scanner via its explicit interpreter from the skill directory (never rely on bare executable bits):

```bash
# Python 3 (Linux / macOS / Windows)
python3 scripts/scan.py <target-repo>

# PowerShell (Windows)
pwsh -NoProfile -File scripts/scan.ps1 -Path <target-repo>
```

Use `--format json` (`-Format json`) for structured parsing. Also run repo-native tools already available in the environment (`gitleaks`, `semgrep`, `npm audit`, `actionlint`, `pip-audit`) when present. Report only checks actually executed.

### Step 3: Load Only Matching Domain References
Read the `references/*.md` files corresponding to technologies detected in Step 1:
- [references/web-browser.md](references/web-browser.md) — web apps, SPAs, SSR, headers, cookies, uploads, Electron/webviews
- [references/api-auth.md](references/api-auth.md) — REST, GraphQL, gRPC, WebSockets, OAuth 2.1, OIDC, JWT, webhooks, RBAC/ABAC/ReBAC
- [references/secrets-crypto.md](references/secrets-crypto.md) — secret storage, public frontend key checks, OIDC federation, cryptography, logs/errors
- [references/db-storage.md](references/db-storage.md) — SQL/NoSQL/LDAP injection, Postgres/MySQL/MongoDB, RLS, Redis/Memcached, S3/GCS/R2/Blob
- [references/infra-cicd-supply.md](references/infra-cicd-supply.md) — Docker, K8s, Cloud IAM/IMDSv2, GitHub Actions, SLSA/lockfiles/SBOM, SecOps
- [references/ai-agent-mcp.md](references/ai-agent-mcp.md) — OWASP LLM/Agentic Top 10, prompt injection/CaMeL, MCP security, sandboxing, RAG, agent code checks

### Step 4: Semantic Code & Config Audit
Regex scanning never suffices alone. Manually verify every applicable control:
1. **Route & Resolver Authz:** Confirm every non-public route/mutation enforces authentication, function/role permissions, and object ownership scoped to server-derived `principal_id`/`tenant_id`.
2. **Client-Side Public Keys & Built Assets:** Check `.env*`, frontend source, and `dist/`/`.next/`/`build/` outputs. Flag any privileged credential (`SECRET`, `SERVICE_ROLE`, `sk_live_`, LLM keys) as `[RED]`; if intentional public keys exist (Supabase `anon`, Firebase), verify strict backend RLS/Security Rules in repo or flag the gap.
3. **Data & Query Boundaries:** Trace dynamic SQL/NoSQL/template/shell/path inputs from HTTP/tool boundaries to sinks for parameterization and canonical allowlisting.
4. **Webhooks, Auth & Crypto:** Confirm raw-body constant-time HMAC verification, strict `jwt.verify` algorithm pinning (`iss`/`aud`/`exp`), and absence of disabled TLS checks.
5. **CI/CD & Runtime Config:** Check `.github/workflows/` triggers, `GITHUB_TOKEN` scopes, Action SHAs, Dockerfiles, IaC network rules, and AI agent tool/MCP boundaries.

### Step 5: Emit the Required Report
Output your findings using the exact structure below. Never print raw unredacted secrets (`sk_****1234` only).

---

## Required Report Format

```markdown
# Security Audit Report: <repo-name>

## Summary
- **Scope inspected:** <directories, stacks, build outputs reviewed>
- **Checks executed:** <exact scanner/CLI commands run and exit results, or manual-only note>
- **Counts:** <N> Red, <M> Yellow
- **Update notice:** <only when check_update reports [UPDATE AVAILABLE]; otherwise omit>

## Red Vulnerabilities
1. **[RED] `<RULE-ID>` — <Short Vulnerability Title>**
   - **Standard:** <OWASP / CWE / RFC / CIS ID>
   - **Location:** `<path/to/file>:<line>`
   - **Evidence:** <concise code/config fact with secrets redacted>
   - **Impact:** <concrete exploit scenario>
   - **Remediation:** <exact minimal fix>
(Or `None found in inspected scope.`)

## Yellow Vulnerabilities
1. **[YELLOW] `<RULE-ID>` — <Short Hardening Gap Title>**
   - **Standard:** <OWASP / CWE / RFC / CIS ID>
   - **Location:** `<path/to/file>:<line>`
   - **Evidence:** <concise fact>
   - **Remediation:** <exact baseline control>
(Or `None found in inspected scope.`)

## Unverified / Out-of-Repo Gaps
- <Runtime hosting/cloud console settings, external Supabase/Firebase rules, live TLS/header probes, or business-logic race conditions not verifiable from static repo files.>
```

---

## Non-Negotiable Rules & Anti-Rationalization

| Excuse | Reality |
|---|---|
| "It is just an MVP / vibecoded prototype." | Prototypes deployed publicly leak keys and DBs identically to production apps. Apply full `[RED]`/`[YELLOW]` grading. |
| "The scanner passed, so the repo is clean." | Regex cannot prove missing BOLA/IDOR, broken business logic, or missing Supabase RLS. Complete Step 4 manually. |
| "`NEXT_PUBLIC_` / `VITE_` vars are harmless client config." | Build tools inline every `NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_` variable into public JS bundles; privileged keys there are `[RED]`. |
| "Auth checks exist in the React/frontend router." | Client checks are trivially bypassed with `curl`. Server routes and DB policies must enforce authz. |
| "No scanner script ran, I just eyeballed the files." | Never fabricate or omit check status. Run `scan.py`/`scan.ps1` or explicitly list unrun checks under Summary/Unverified Gaps. |
| "I should summarize generally instead of listing every issue." | Repo audits MUST return the structured `Red Vulnerabilities` and `Yellow Vulnerabilities` lists with exact `file:line` locations. |
