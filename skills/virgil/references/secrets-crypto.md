# Secrets Management, Cryptography & Data Protection

## 1. Secrets Classification & Public Frontend Leaks
- `[RED]` **Hardcoded Credentials & Tracked Secret Files (`CWE-798`, `CWE-312`, `A04:2025`):** Never commit API keys, DB passwords, private keys (`*.pem`, `*.key`, `id_rsa`), service-account JSONs, or real `.env` files (`.env`, `.env.local`, `.env.production`). Only `.env.example` templates with obvious placeholders belong in VCS.
- `[RED]` **Privileged Keys in Public Client Scope:** Distinguish intentionally public client keys from privileged secrets:
  - **Forbidden in client JS / `NEXT_PUBLIC_*` / `VITE_*` / `EXPO_PUBLIC_*` / `REACT_APP_*`:** Stripe `sk_*`/`rk_*`, Supabase `service_role`, OpenAI/Anthropic/Gemini/LLM keys, AWS IAM keys, DB connection strings, JWT signing secrets, webhook secrets.
  - **Public-by-design keys requiring server guards:** Stripe `pk_*`, Firebase client config, Supabase `anon` key. Whenever client-side `anon`/Firebase keys exist, verify strict database Row-Level Security or Security Rules are enforced.
- `[RED]` **Leaked Built Bundles & Env Dumps:** Never print `process.env` or Vault responses to CI/runtime stdout, and always inspect compiled `dist/`, `.next/`, `build/`, and `out/` bundles for inlined secret patterns.

## 2. Secrets Lifecycle & Workload Identity Federation
- `[RED]` **Broad OIDC Federation Trust Policies:** Replace static cloud keys and SA JSON files with short-lived OIDC token exchange. Grant `id-token: write` strictly at the job level (isolated from untrusted PR code) and pin exact `iss`, `aud`, and repo/branch/env `sub` (`token.actions.githubusercontent.com:sub`) or GCP `attribute_condition` claims. Never leave wildcard OIDC trust conditions.
- `[YELLOW]` **Secret Manager Hygiene & Rotation:** Use HashiCorp Vault dynamic secrets engines (minute/hour TTLs), Vault Agent, single-use `secret_id_num_uses` or OIDC auth, >=2 audit backends, and immediate root-token revocation. On AWS/GCP Secret Manager, encrypt with CMKs/CMEK, pass encryption context, enable rotation, and pin explicit secret versions in prod (avoid `latest`). For GitOps files, use **SOPS** with **age** or KMS/Vault `transit` (`aes256-gcm`).

## 3. Leak Prevention & Exposure Incident Response
- `[YELLOW]` **Missing Pre-Commit & CI Secret Scanning:** Configure `.pre-commit-config.yaml` with **Gitleaks** or **TruffleHog**, enable **GitHub Secret Scanning + Push Protection + Delegated Bypass + Validity Checks**, and run CI full-history scans (`fetch-depth: 0` on `actions/checkout`).
- `[RED]` **Unrevoked Exposed Secrets (Mandatory IR Order):** On any committed secret:
  1. **Revoke and rotate at the provider first** (including active leased/federated tokens if trust policy was exposed). A `git rm` commit or history rewrite alone does NOT neutralize an exposed key.
  2. Scrub Git history on a `git clone --mirror` with **`git-filter-repo`** (never deprecated `git filter-branch`) and force-push all branches/tags.
  3. Update `.gitignore`, force collaborators to re-clone fresh, and purge cached PR views via platform support.

## 4. Modern Cryptography Baselines
- `[RED]` **Broken Encryption Modes, Nonce Reuse & Weak PRNGs (`CWE-327`, `CWE-330`):** Ban `ECB`, unauthenticated `AES-CBC`, `RC4`, `DES`/`3DES`, static IVs/nonce reuse, `Math.random()`/`rand()` for security values, and custom crypto. Mandate **AEAD**: **`AES-256-GCM`** (unique 96-bit nonce per encryption; rotate before $2^{32}$ random-IV encryptions) or **`ChaCha20-Poly1305`**. Use platform CSPRNGs (`secrets`, `crypto.randomBytes()`, `SecureRandom`).
- `[RED]` **Weak Password Hashing (`CWE-916`, `CWE-328`):** Ban `MD5`, `SHA-1`, plain `SHA-256`, or unsalted hashes for passwords.
  - `[YELLOW]` **Sub-Baseline Hashing Params:** Mandate **`Argon2id`** with OWASP minimums (>=**19 MiB** / 19,456 KiB memory, >=**2** iterations, parallelism **1**, per-password CSPRNG salt). Fallbacks: `scrypt` ($N \ge 2^{17}, r \ge 8, p=1$), legacy `bcrypt` (cost >=10, guard 72-byte truncation), or `PBKDF2-HMAC-SHA256` (>=600,000 iterations for FIPS-140).
- `[RED]` **Timing Side-Channels (`CWE-208`) & Broken Signatures:** Compare MACs, webhook signatures, and API tokens strictly with constant-time functions (`crypto.timingSafeEqual`, `hmac.compare_digest`, `subtle.ConstantTimeCompare`). Use **`Ed25519`**, **`ECDSA` P-256** (deterministic RFC 6979), or **`RSA`** (>=2048–3072 bits) with **`RSASSA-PSS`** and **`RSAES-OAEP`**.
- `[RED]` / `[YELLOW]` **TLS & KMS Envelope Separation:** Disable SSLv2/v3 and TLS 1.0/1.1 (`[RED]`); default to **TLS 1.3** and restrict TLS 1.2 strictly to **ECDHE + AEAD** per NIST SP 800-52 Rev. 2 (`[YELLOW]`). Separate **DEK** and KMS/HSM **KEK** with explicit encryption context; KEK rotation re-wraps DEKs without resetting DEK cryptoperiods.

## 5. Safe Observability, Errors, Privacy & Data Sanitization
- `[YELLOW]` **Log & Error Leakage (`CWE-532`, `CWE-209`):** Emit structured JSON logs scrubbed at centralized middleware/serializers to drop `Authorization`, cookies, session IDs, passwords, keys, and PII (including inside exception objects). Return generic **RFC 7807** Problem Details with opaque correlation IDs; keep `DEBUG=false` and traces strictly server-side.
- `[YELLOW]` **Privacy Engineering & Data Lifecycle (Microsoft SDL Privacy / Google):** Enforce data minimization, explicit consent/purpose binding, automated retention TTLs, and end-to-end DSR (Data Subject Request) export/erasure propagation across primary DBs, caches, backups, logs, and vector/RAG indices.
- `[YELLOW]` **Data Sanitization (NIST SP 800-88 Rev. 2):** Encrypt backups/snapshots with separated KMS keys and align decommissioning with **Purge** (Block Erase / Cryptographic Erase with zero unencrypted copies and full key destruction) or **Destroy**.

## Verification Checklist
- Run `scan.py`/`scan.ps1` and `gitleaks`/`trufflehog` (`fetch-depth: 0`) across repo history and built client bundles; ensure zero raw credentials appear in output.
- Audit code for `ECB`, `MD5`, `SHA-1`, `Math.random`, `===` digest comparisons, and `DEBUG=true`.
- Replay canary PII/tokens through error and auth flows to verify log redaction and RFC 7807 error responses.

## Authoritative Sources
- [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | [Workload Identity Federation](https://cheatsheetseries.owasp.org/cheatsheets/Workload_Identity_Federation_Cheat_Sheet.html) | [Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | [Key Management](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html) | [Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | [Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [NIST SP 800-57 Pt 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) | [SP 800-131A Rev. 2](https://csrc.nist.gov/pubs/sp/800/131a/r2/final) | [SP 800-52 Rev. 2](https://csrc.nist.gov/pubs/sp/800/52/r2/final) | [SP 800-88 Rev. 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final)
- [GitHub Push Protection](https://docs.github.com/en/code-security/secret-scanning/push-protection/about-push-protection) | [Removing Sensitive Data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository) | [HashiCorp Vault](https://developer.hashicorp.com/vault/docs) | [SOPS](https://getsops.io)
