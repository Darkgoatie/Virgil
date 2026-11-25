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
- **Exposed Secrets & Client-End Key Leaks:** Hardcoded API keys, tokens, private keys, default/seed credentials (`admin`/`changeme`), or inline DB passwords in source, tracked `.env`/key/`*.tfstate` files, public frontend env vars (`NEXT_PUBLIC_*`, `VITE_*`, `EXPO_PUBLIC_*`, `REACT_APP_*`, `NUXT_PUBLIC_*`) holding privileged credentials, compiled frontend bundles (`dist/`, `.next/`, `build/`, `out/`), web-root `.env`/`.git`/`.bak`/`.sql` dump exposure, or client-side Supabase `anon` / Firebase config lacking strict RLS or Security Rules.
- **Broken Access Control, BaaS, Payments & Concurrency:** Missing object-level ownership checks (`BOLA`/`IDOR`, including cross-tenant webhook subscriptions), missing function/admin/verb checks (`BFLA`), unallowlisted `?fields=`/`?include=` expansion or hidden-field `sort=` oracles, shared caching (`Cache-Control` missing `private, no-store`) on authenticated responses, trusting client-supplied `X-Tenant-ID`/`org_id`, superuser app DB roles, DB-to-host execution (`xp_cmdshell`, `COPY ... PROGRAM`, `dblink`/FDWs), missing `FORCE ROW LEVEL SECURITY`, Supabase `SECURITY DEFINER` missing `SET search_path = ''`, column-level `is_admin`/`raw_user_meta_data` escalation, Firebase `request.auth != null` without ownership, mass assignment (`req.body`), Next.js RSC / `__NEXT_DATA__` raw DB model or preloaded gated/paywall serialization, unauthenticated `'use server'` actions, client-side crypto shipping decryption keys, raw card PAN/CVV on app servers, client-trusted pricing/state transitions, or TOCTOU/double-spend races lacking atomic DB locks.
- **Injection, Files, Memory & Execution Sinks:** SQL injection (including second-order SQLi & dynamic stored-procedure SQL), NoSQL operator injection (`$where`), LDAP/Search injection, SSTI & client-side template injection (CSTI), XSS (`dangerouslySetInnerHTML`, `v-html`), `window.postMessage` missing `event.origin` / wildcard `*` leaks, `eval()`/`new Function()`, shell injection (`shell=True`), unsafe deserialization (`pickle.loads`, unguarded `yaml.load`, .NET `BinaryFormatter`/Remoting, Java `ObjectInputStream`/`XMLDecoder`), prototype pollution, path traversal / Zip Slip (`extractall`), XXE, SSRF (including DNS rebinding, redirect hops, alternate IP encodings & PDF-renderer SSRF), unvalidated executable/SVG uploads, Trojan Source bidi control chars, unbounded C string functions (`gets`/`strcpy`/`sprintf`), or catastrophic ReDoS / Chromium Memory-Safety "Rule of 2" violations.
- **Broken Auth, Crypto & Transport:** `jwt.decode()` without verify, `alg: "none"`, `HS256`/`RS256` confusion, weak/shared `HS256` signing secrets, OAuth unverified-email linking (`email_verified != true`), OAuth Login CSRF / missing RFC 9207 `iss` checks, OAuth issuer code reuse / refresh scope widening / unenforced API `scope` / open client registration / unguarded RFC 8628 device-code grants / app `keyCredentials` (Shadow Credentials) escalation, email canonicalization collisions, `Host`/`X-Forwarded-Host` reset-link poisoning, session fixation, MFA step-skipping / missing OTP brute-force caps, missing global revocation (sessions, PATs, OAuth grants, trusted devices) on password/email change, account-deletion re-registration tombstones, SAML inline `KeyInfo` trust / unsigned assertions / unsafe JIT role overwrites, disabled TLS (`verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`), `sslmode=disable|allow|prefer|require`, Cloudflare `Flexible` TLS or unauthenticated direct-to-origin IP bypass behind a CDN/WAF, `MD5`/`SHA-1` password hashing, `AES-ECB`/static IVs, CORS wildcard/`Origin` reflection with `credentials: true`, or missing raw-body constant-time webhook HMAC.
- **Critical Infra, CI/CD, Mobile & Runtime Exposure:** `0.0.0.0/0` DB/SSH/admin ingress or unloopbacked container DB ports (`5432:5432`), unauthenticated/plaintext Kafka/RabbitMQ/MQTT/ActiveMQ/Pulsar/ZooKeeper/JMX/Connect brokers or hardcoded Erlang cluster cookies, `X-Forwarded-For` / `trust proxy: true` IP spoofing, public object buckets, exposed Spring Boot `/actuator/*`, `phpMyAdmin`/`Adminer`/`pgAdmin`, or debug profilers (`/debug/pprof`), unfirewalled WebRTC TURN relays, dangling DNS/subdomain takeovers, privileged/UID-0 containers, `docker.sock` mounts, or Kubernetes RBAC escalation verbs (`bind`/`escalate`/`impersonate`/`pods/exec`/`nodes/proxy`), GitHub Actions `pull_request_target` checking out PR head code, `${{ github.event.* }}` inside `run:`, or PR/fork CI cache/artifact poisoning into release jobs, IMDSv1 (`HttpTokens: optional`), Electron `nodeIntegration: true` / `contextIsolation: false` / `webSecurity: false`, unauthenticated local IPC sockets/Named Pipes/XPC/D-Bus helpers, iOS ATS `NSAllowsArbitraryLoads`, Android cleartext/`exported="true"` without permissions, unsafe WebView JS bridges/file access, client-only biometrics, dependency confusion (`--extra-index-url` / unscoped private packages), or unverified/hallucinated packages.
- **High-Impact AI Agent Flaws:** Violating the "Rule of Two" (private data + untrusted inputs + external mutation/exfil without HITL/IFC), missing action-confirmation binding (mutated arguments/retries after approval) or tool-schema vs. handler canonicalization drift, inter-agent trust exploitation (`ASI07`), unisolated browser/computer-use sessions, MCP token passthrough, missing `aud`/RFC 8707 checks, or unauthenticated MCP tool/request-ID routing, raw host credentials inside sandbox `env`, or unsanitized LLM output flowing into HTML/SQL/shell sinks.

### `[YELLOW]` — Less Serious (Hardening & Defense-in-Depth)
- **Browser, SSR, Email & Client Hygiene:** Missing or weak nonce CSP (`'unsafe-inline'`/`'unsafe-eval'`), missing SRI (`integrity=`) or unvetted tag managers/widgets on auth/checkout pages, HSTS, `X-Content-Type-Options: nosniff`, `frame-ancestors` / `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, exposed `X-Powered-By`/`Server` headers, enabled directory listings (`autoindex on`), unpatched CMS/plugin exposure, missing `__Host-`/cookie hardening, parent-domain `Domain=.` cookies, unhashed/non-rotating remember-me tokens, missing Fetch Metadata / XS-Leak checks, missing `import 'server-only'` on Next.js DAL modules, CSV formula injection (`=`, `+`, `-`, `@`), missing SPF/DKIM/DMARC (`p=reject`), or publicly shipped `.js.map`/`.css.map` source maps.
- **API, Payments, Queues & Protocol Hardening:** Missing IP/tenant rate limits, unbounded pagination, missing nested GraphQL per-field authz or depth/complexity/batch caps, enabled prod GraphQL introspection, Swagger/OpenAPI UI, `/metrics`, or gRPC reflection, committed Postman/Insomnia collections, exposed gateway admin or unauthenticated direct backend calls, missing single-use TOTP replay tracking or MFA push number-matching, missing webhook replay/idempotency checks, floating-point money math, missing payment idempotency keys/3DS velocity controls/ERP Segregation-of-Duties, missing Kafka/SQS/Pulsar ACLs/vhosts/DLQ caps/offset restrictions, or delayed jobs failing to re-check current permissions.
- **CI/CD, Supply Chain, Media & Mobile Hygiene:** Unpinned GitHub Actions (`@v4`/`@main`), missing `GITHUB_TOKEN` `permissions:`, CI shell trace/env dumps (`set -x`, `printenv`) risking log secret leaks, mutable `:latest` container tags, missing non-root `USER`, missing `npm ci` / `--frozen-lockfile` / `--ignore-scripts` / OIDC Trusted Publishing, missing SBOM/SAST CI gates, un-sandboxed ImageMagick/FFmpeg/Ghostscript parsers (`nsjail`), `android:allowBackup="true"` or missing iOS Keychain `ThisDeviceOnly` + fresh-install cleanup, or `DEBUG=true` in prod/Docker configs.
- **Crypto, Privacy & Ops Hygiene:** Weak password-hashing params (`Argon2id` below OWASP floor, unguarded 72-byte `bcrypt`), unhashed/reusable reset, magic-link, or MFA recovery tokens, deprecated KBA security questions, non-AEAD TLS 1.2 ciphers, `MD5`/`SHA-1` in non-password hashes, verbose client errors instead of RFC 7807, unredacted structured logs, raw prod PII in staging/eval DBs, unencrypted cloud DB snapshots or exposed SQLite/BI copies, missing LLM zero-data-retention (ZDR) checks, missing `pgAudit`/DDL `lock_timeout`/`statement_timeout`/restore drills, unescaped `LIKE`/`ILIKE` wildcards, missing soft-delete `deleted_at IS NULL` filters/partial unique indexes, missing `SECURITY.md`/`security.txt`, or missing agent step/budget caps and off-sandbox OTel audit logs.

### `[OPTIONAL]` — Advisory & Enterprise-Scale Recommendations (Not Vulnerabilities)
Exclude `[OPTIONAL]` items from vulnerability counts and `--exit-code`; list them only under `## Optional Recommendations` when relevant:
- Multi-account cloud isolation (`dev`/`staging`/`prod`/`security`), immutable Security Zones, JIT break-glass access + device-posture Zero Trust (`BeyondCorp`), VPC Service Controls, Confidential Computing, and IaC drift detection.
- Deploy-time Binary Authorization, CNCF OPA Gatekeeper / Kyverno admission controllers, Layer-7 service meshes, OAuth 2.0 Pushed Authorization Requests (`RFC 9126`), and eBPF/Falco syscall runtime detection.
- Post-Quantum Cryptography readiness (CBOM, hybrid `X25519+ML-KEM` FIPS 203, FIPS 204/205 roadmaps), formal NIST SP 800-88r2 sanitization, and automated multi-store DSR erasure orchestration.
- Native compiler hardening (`PIE`/`FORTIFY_SOURCE`/RELRO), C++ Core Guidelines (`gsl::span`/`not_null`), AWS `s2n-tls` safety macros, Kani Rust Verifier, Meta `Infer`/`Pysa`, `TigerStyle`/NASA JPL `Power of 10` bounds, `ASan`/`UBSan`, continuous fuzzing (`OSS-Fuzz`/`OneFuzz`), Rust `unsafe // SAFETY:` annotations, and Git commit signing (`gitsign`).
- DNSSEC, CAA records, enterprise DDoS/Bot Management, COOP/COEP cross-origin isolation, proxy HTTP request smuggling/cache deception audits, PCI-DSS v4.0 CSP script-monitoring telemetry, and mobile SPKI pinning / Secure Enclave / StrongBox hardware binding.

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

Use `--format json` (`-Format json`) for structured parsing, and `--include-optional` (`-IncludeOptional`) if you want advisory `[OPTIONAL]` items listed separately. Also run repo-native tools already available in the environment (`gitleaks`, `semgrep`, `npm audit`, `actionlint`, `pip-audit`) when present. Report only checks actually executed.

### Step 3: Load Only Matching Domain References
Read the `references/*.md` files corresponding to technologies detected in Step 1:
- [references/web-browser.md](references/web-browser.md) — web apps, SPAs, SSR, headers, cookies, uploads, Electron/webviews
- [references/api-auth.md](references/api-auth.md) — REST, GraphQL, gRPC, WebSockets, OAuth 2.1/OIDC/SAML/SCIM, account recovery/deletion, JWT, webhooks, RBAC/ABAC/ReBAC
- [references/secrets-crypto.md](references/secrets-crypto.md) — secret storage, public frontend key checks, OIDC federation, cryptography, logs/errors
- [references/db-storage.md](references/db-storage.md) — SQL/NoSQL/LDAP injection, Postgres/MySQL/MongoDB, RLS, Redis/Memcached, S3/GCS/R2/Blob
- [references/infra-cicd-supply.md](references/infra-cicd-supply.md) — Docker, K8s, Cloud IAM/IMDSv2, multi-account isolation, GitHub Actions, SLSA/lockfiles/SBOM, memory/fuzzing, SecOps
- [references/ai-agent-mcp.md](references/ai-agent-mcp.md) — OWASP LLM/Agentic Top 10, prompt injection/CaMeL, MCP security, sandboxing, RAG, privacy/ZDR, agent code checks
- [references/mobile-apps.md](references/mobile-apps.md) — iOS ATS/Keychain/Secure Enclave, Android cleartext/exported components, biometrics, OWASP MASVS
- [references/payments-business-logic.md](references/payments-business-logic.md) — Stripe/PCI-DSS v4.0, server pricing, TOCTOU race conditions, atomic DB locks, state machines

### Step 4: Semantic Code & Config Audit
Regex scanning never suffices alone. Manually verify every applicable control:
1. **Route & Resolver Authz:** Confirm every non-public route/mutation enforces authentication, function/role permissions, and object ownership scoped to server-derived `principal_id`/`tenant_id`.
2. **Client-Side Public Keys & Built Assets:** Check `.env*`, frontend source, and `dist/`/`.next/`/`build/` outputs. Flag any privileged credential (`SECRET`, `SERVICE_ROLE`, `sk_live_`, LLM keys) as `[RED]`; if intentional public keys exist (Supabase `anon`, Firebase), verify strict backend RLS/Security Rules in repo or flag the gap.
3. **Data & Query Boundaries:** Trace dynamic SQL/NoSQL/template/shell/path inputs from HTTP/tool boundaries to sinks for parameterization, implicit type-coercion guards (MySQL/JS array coercion), canonical allowlisting, statement timeouts, `LIKE` wildcard escaping, and `deleted_at IS NULL` soft-delete enforcement.
4. **Payments, Concurrency & State:** Confirm server-side price/total calculation, atomic DB locks/unique constraints preventing double-spend, and zero raw PAN/CVV handling.
5. **Webhooks, Auth & Account Lifecycle:** Confirm raw-body constant-time HMAC verification, strict `jwt.verify` algorithm pinning (`iss`/`aud`/`exp`), OAuth `email_verified` linking guards + session-bound `state` + `iss`, safe reset URL origins, global session revocation on credential/email change, deletion tombstones, and absence of disabled TLS checks.
6. **CI/CD, Mobile, Local IPC & Runtime Config:** Check `.github/workflows/` triggers, `GITHUB_TOKEN` scopes, Action SHAs, cache/artifact trust boundaries, Dockerfiles, IaC network rules, mobile/desktop ATS/Keychain/exported manifests/WebView bridges/local IPC peer credentials, FFI/binary-loader paths, and AI agent tool/action-binding/MCP boundaries.
7. **Adversarial Verification, Variant Sweep & Source-Visibility Gate (Cloudflare Security-Audit Discipline):** Before reporting any `[RED]` finding, trace the complete `entrypoint -> propagation -> sink` path and actively try to refute it against existing framework/middleware/ORM/upstream guards. Confirm a real trust boundary is crossed (exclude self-impact or intended same-principal actions), sweep parallel/sibling routes (REST vs. gRPC, batch, retry, legacy, restore/undelete) for the same root cause, recommend the smallest effective source fix at the last trusted decision point, and place any lead that depends on an unobserved deployment/proxy/IdP/cloud fact under `## Unverified / Out-of-Repo Gaps` rather than guessing live behavior.

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

## Optional Recommendations
*(Advisory / enterprise-scale hardening only; not counted as vulnerabilities.)*
- **[OPTIONAL] `<Title>`:** <concise architecture/ops recommendation tailored to this repo's stack, or omit section if none apply.>

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
