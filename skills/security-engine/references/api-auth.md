# API Security, Authentication & Authorization (IAM)

## 1. OWASP API Security Top 10 (2023 Baseline)
- `[RED]` **API1 BOLA / IDOR (`CWE-639`):** Never trust client-supplied object IDs alone (even UUIDv4/v7). Scope every DB read/update/delete by server-derived `principal_id` and `tenant_id` (`WHERE id = $1 AND tenant_id = $2`).
- `[RED]` **API3 BOPLA / Mass Assignment (`CWE-915`, `CWE-285`):** Never pass raw `req.body` into `ORM.create()`, `ORM.update()`, or `Object.assign()`. Use explicit per-endpoint input DTOs (allowlisted writable fields) and response serializers (allowlisted readable fields).
- `[RED]` **API5 BFLA (`CWE-285`):** Enforce role/permission checks centrally across every route, resolver, HTTP verb (`GET`/`POST`/`PUT`/`PATCH`/`DELETE`), and legacy version (`/api/v1/*`).
- `[YELLOW]` **API4 Unrestricted Resource Consumption (`CWE-770`):** Enforce request body size limits (e.g., `1 MB` JSON), pagination caps (`default=20`, `max=100`), request timeouts, and cost/rate budgets on metered endpoints (OTP/SMS/email/LLM inference).
- `[RED]` **API7 SSRF & API10 Unsafe Upstream Consumption (`CWE-918`):** Validate/sanitize third-party API payloads with strict schemas, set outbound timeouts, disable unsafe HTTP redirects, and block private/metadata IP resolution.
- `[YELLOW]` **API9 Improper Inventory Management:** Maintain an up-to-date OpenAPI/AsyncAPI/Protobuf route inventory in CI and decommission shadow/zombie endpoints.

## 2. Authentication Standards (OAuth 2.1, OIDC, WebAuthn, NIST SP 800-63B-4)
- `[RED]` **Legacy OAuth Grants & Wildcard Redirects (OAuth 2.1 / RFC 9700, `CWE-287`, `CWE-294`):** Eliminate Implicit (`response_type=token`) and ROPC (`grant_type=password`) grants. Use **Authorization Code Flow + PKCE (RFC 7636)** with `code_challenge_method=S256` mandatory (forbid `plain`) for both public and confidential clients. Enforce **exact string matching** on `redirect_uri` (no wildcards/prefixes). Never pass bearer tokens in URL query strings. Bind CSRF `state` and validate OIDC `nonce`, `iss`, `aud`, `exp`, and `iat`.
- `[RED]` **Broken WebAuthn / FIDO2 Verification (W3C WebAuthn Level 3):** Verify single-use cryptographic challenges, exact `rpIdHash`/`origin`, and `UP`/`UV` flags server-side. Support phishing-resistant passkeys/FIDO2 for AAL2+ and hardware/device-bound authenticators for AAL3 admin roles (NIST SP 800-63B-4).
- `[YELLOW]` **Password Policy & Anti-Automation (`CWE-307`):** Per NIST SP 800-63B-4, enforce >=15-char minimum for single-factor passwords (allow >=64 chars + spaces/Unicode), check breached-password blocklists, forbid arbitrary periodic rotation without breach, and hash with Argon2id. Enforce sliding-window per-IP + per-account rate limits and identical login failure messages (no user enumeration).

## 3. Token & Credential Security (JWT, API Keys, mTLS)
- `[RED]` **JWT Forgery & Confusion (RFC 8725, `CWE-347`):** Always call `jwt.verify()` (never `jwt.decode()`). Pin an explicit server-side algorithm allowlist (`ES256`, `RS256`, or `EdDSA`); reject `alg: "none"` and never mix symmetric (`HS*`) and asymmetric (`RS*`/`ES*`) algorithms on one verifier. Enforce `exp` (<=30–60s clock skew), `nbf`, exact `iss`, and exact `aud`. Reject inline untrusted `jwk`/`x5c` headers, allowlist `jku` to trusted IdP HTTPS URLs, and validate `kid` strictly against UUID/alphanumeric regex + JWKS map (no file-path or SQL interpolation).
- `[YELLOW]` **Long-Lived Tokens & Missing Reuse Detection:** Keep access token TTL short (5–15 min); store rotating refresh tokens server-side with **token-family reuse detection** or sender-constraint binding (**DPoP RFC 9449** / **mTLS RFC 8705**). Never embed secrets/PII in unencrypted JWS payloads.
- `[RED]` **Plaintext API Keys:** Generate >=256 bits CSPRNG entropy with identifiable non-secret prefix (`ak_live_<keyid>_<secret>`); store only cryptographic SHA-256 / HMAC-SHA256 hashes at rest and compare in constant time.
- `[YELLOW]` **Static Service-to-Service Secrets:** Prefer **mTLS** with short-lived automated X.509 workload certificates (SPIFFE IDs in URI SANs) and peer SAN verification over static inter-service keys (CISA ZTMM v2.0).

## 4. Webhook & Integration Security
- `[RED]` **Forged Inbound Webhooks (`CWE-347`):** Verify **HMAC-SHA256** (or Ed25519) over **raw unparsed HTTP request body bytes** paired with the signed timestamp (`"{ts}.{raw_body}"`), using constant-time comparison (`crypto.timingSafeEqual`, `hmac.compare_digest`, `subtle.ConstantTimeCompare`). Never hash re-serialized JSON (`JSON.stringify(req.body)`).
- `[YELLOW]` **Replay & Duplicate Execution (`CWE-294`):** Enforce tight signed timestamp tolerance (<=3–5 minutes UTC) and atomic `event_id` deduplication (`INSERT ... ON CONFLICT DO NOTHING` or Redis `SET NX`) before async execution.
- `[RED]` **Outbound Webhook SSRF (`CWE-918`):** Allow `https://` only; resolve DNS at connect time via a custom dialer denying loopback, `169.254.0.0/16`, RFC 1918, ULA, and `::ffff:127.0.0.1` and connect directly to the validated IP; disable HTTP redirects.

## 5. Authorization Models & Multi-Tenant Enforcement
- `[RED]` **Fail-Open Authz & Client-Trusted Tenant Headers (`CWE-285`, `CWE-639`):** Enforce deny-by-default (`403`/`401`) at centralized middleware/PEP; maintain an explicit reviewed allowlist of public routes. Derive `actor_id` and `tenant_id` solely from verified session/token claims (never trust `X-Tenant-ID` or body `org_id` without validating authorized membership). Enforce tenant isolation at both application authz and DB layers (e.g., PostgreSQL RLS).
- `[YELLOW]` **Model Fit:** Use RBAC for coarse functional roles (never object ownership), ABAC for contextual/tenant attributes, and ReBAC for collaborative hierarchy graphs.

## 6. Protocol-Specific Hardening (REST, GraphQL, gRPC, WebSockets)
- `[RED]` **Permissive REST Schemas & CSWSH:** Reject unknown JSON fields (`additionalProperties: false`, Zod `.strict()`, Pydantic `extra="forbid"`). For WebSockets, mandate `wss://`, verify exact `Origin` equality on upgrade, require explicit single-use auth tickets/tokens (never rely on ambient cookies alone), and enforce per-message authorization on long-lived connections.
- `[YELLOW]` **GraphQL, gRPC & Rate Limits:** Disable GraphQL **introspection** and field suggestions in prod; enforce max depth (<=7–10), cost/complexity limits, execution timeouts, alias/batch caps, and per-request `DataLoader` isolation. Disable **gRPC Server Reflection** in prod, pass auth tokens in gRPC metadata headers, and enforce message sizes, RPC deadlines, and per-stream message rate limits. Layer IP + `principal_id`/`tenant_id` token-bucket limits (`429` + `Retry-After`).

## Verification Checklist
- Run negative BOLA/BFLA cross-tenant CRUD tests across all HTTP methods and mass-assignment tests injecting `role`/`tenant_id`.
- Test JWT verifier against `alg: "none"`, `HS256` with public key, expired `exp`, wrong `aud`/`iss`, and `kid: "../../etc/passwd"`.
- Test webhook signature failure on altered whitespace, expired timestamps (>5 min), duplicate `event_id`, and `169.254.169.254` outbound URLs.
- Probe GraphQL `__schema` / depth-20 / alias batches, `grpcurl list` reflection, and cross-origin WebSocket upgrades.

## Authoritative Sources
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/) | [OWASP ASVS 5.0](https://asvs.owasp.org/)
- [IETF RFC 9700 (OAuth BCP)](https://www.rfc-editor.org/info/rfc9700) | [RFC 8725 (JWT BCP)](https://www.rfc-editor.org/info/rfc8725) | [RFC 7636 (PKCE)](https://www.rfc-editor.org/info/rfc7636) | [RFC 9449 (DPoP)](https://www.rfc-editor.org/info/rfc9449) | [RFC 8705 (mTLS)](https://www.rfc-editor.org/info/rfc8705)
- [NIST SP 800-63-4](https://csrc.nist.gov/pubs/sp/800/63/4/) | [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) | [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | [CISA Zero Trust Maturity Model v2.0](https://www.cisa.gov/zero-trust-maturity-model)
- [OWASP Cheat Sheets: Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) | [JWT](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html) | [Webhook](https://cheatsheetseries.owasp.org/cheatsheets/Webhook_Security_Cheat_Sheet.html) | [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) | [REST](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | [GraphQL](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html) | [gRPC](https://cheatsheetseries.owasp.org/cheatsheets/gRPC_Security_Cheat_Sheet.html) | [WebSockets](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
