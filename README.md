<div align="center">

<img src="skills/virgil/assets/icon.svg" alt="Virgil Security Skill Icon" width="112" height="112" />

# virgil

**Portable security auditing and hardening skill for AI coding agents.**

[![Version](https://img.shields.io/badge/version-1.15.0-2AB985?style=flat-square)](skills/virgil/VERSION)
[![Spec](https://img.shields.io/badge/spec-Agent_Skills_(SKILL.md)-1F2937?style=flat-square)](https://agentskills.io/specification)
[![Controls](https://img.shields.io/badge/controls-164_semantic_%7C_51_static_rules-1F2937?style=flat-square)](#severity-model)
[![Scanners](https://img.shields.io/badge/scanners-Python_%7C_PowerShell-1F2937?style=flat-square)](#running-a-security-audit)
[![License](https://img.shields.io/badge/license-MIT-1F2937?style=flat-square)](LICENSE)

[Quick Install](#quick-install) · [Running an Audit](#running-a-security-audit) · [Severity Model](#severity-model) · [Skill Layout](#skill-layout) · [Authoritative Sources](#authoritative-standards--aaa-codebase-safety-sources) · [Agent Skills Ecosystem](#agent-skills-ecosystem) · [License & Copyright](#license-copyright--third-party-attribution-notice)

</div>

---

Virgil teaches coding agents how to run structured repository security audits built on the open [Agent Skills (`SKILL.md`) specification](https://agentskills.io/specification). It pairs zero-dependency Python and PowerShell static pre-scanners (**51 deterministic rules**: `32` `[RED]`, `18` `[YELLOW]`, `1` `[OPTIONAL]`) with **164 classified semantic controls** across 8 progressive-disclosure reference guides covering web/SSR/CMS/DNS, API/OAuth-issuer/OIDC/SAML/account-lifecycle auth, secrets/Vault/KMS/cryptography/safe-logging, databases/BaaS/message brokers/network shares, containers/CI-CD/supply-chain/directory-services/PKI/VPN/remote-admin/native-memory safety, AI-agent/MCP boundaries, mobile/desktop local IPC, and payment/ERP state machines.

## Quick Install

### Cross-Agent CLI (`vercel-labs/skills`)

Install `virgil` directly into any supported agent harness via the [`npx skills`](https://github.com/vercel-labs/skills) package manager:

```bash
# Interactive install or targeted agent install
npx skills add Darkgoatie/Virgil --skill virgil
npx skills add Darkgoatie/Virgil --skill virgil -a claude-code cursor -g
```

### Windows (PowerShell)

```powershell
# Auto-detect installed agents on this machine and install globally
.\install.ps1

# Install for specific agents (claude, gemini, antigravity, hermes, codex, cursor, agents)
.\install.ps1 -Agent gemini,claude,hermes,codex

# Install globally for all supported agents (or symlink with -Link)
.\install.ps1 -Agent all
.\install.ps1 -Agent all -Link

# Install into a specific project repository
.\install.ps1 -Scope project -TargetRepo C:\path\to\repo -Agent claude,gemini

# Preview or remove
.\install.ps1 -Agent all -DryRun
.\install.ps1 -Agent all -Uninstall
```

### macOS / Linux (Bash)

```bash
chmod +x install.sh

# Auto-detect installed agents on this machine and install globally
./install.sh

# Install for specific agents
./install.sh --agent gemini,claude,hermes,codex

# Install globally for all supported agents (or symlink with --link)
./install.sh --agent all
./install.sh --agent all --link

# Install into a specific project repository
./install.sh --scope project --target /path/to/repo --agent all

# Preview or remove
./install.sh --agent all --dry-run
./install.sh --agent all --uninstall
```

### Supported Agent Paths

Every installer target copies or links the self-contained `skills/virgil/` package:

| Agent | Global Install Path | Project-Scoped Path | Discovery Notes |
|---|---|---|---|
| **Claude Code** | `~/.claude/skills/virgil` | `.claude/skills/virgil` | Discovers `SKILL.md` automatically at global or repo scope. |
| **Gemini CLI** | `~/.gemini/skills/virgil` | `.gemini/skills/virgil` | Also reads `~/.agents/skills/`; supports `gemini skills install <git-url> --consent`. |
| **Antigravity** | `~/.gemini/config/skills/virgil` | `.agents/skills/virgil` | Traverses `.agents/skills/` up to the repository root. |
| **Hermes Agent** | `~/.hermes/skills/virgil` | `.hermes/skills/virgil` | Verify with `hermes skills list`. |
| **OpenAI Codex CLI** | `~/.codex/skills/virgil` | `.codex/skills/virgil` | Also reads `~/.claude/skills/` and `~/.agents/skills/`. |
| **Cursor** | `~/.cursor/skills/virgil` | `.cursor/skills/virgil` | Discovers `SKILL.md` directories in `.cursor/skills/` and `.agents/skills/`. |
| **Cross-Agent Standard** | `~/.agents/skills/virgil` | `.agents/skills/virgil` | Shared convention supported by Codex CLI, Gemini CLI, Copilot CLI, and Antigravity. |

---

## Running a Security Audit

Prompt any installed coding agent inside a target repository:

```text
Run virgil on this repository and give me the Red and Yellow vulnerability report.
```

You can also invoke the bundled static pre-scanners directly with zero third-party dependencies:

```bash
# Python 3 (Linux / macOS / Windows)
python3 skills/virgil/scripts/scan.py /path/to/repo
python3 skills/virgil/scripts/scan.py /path/to/repo --format json --exit-code --include-optional

# PowerShell (Windows)
pwsh -NoProfile -File skills/virgil/scripts/scan.ps1 -Path C:\path\to\repo
pwsh -NoProfile -File skills/virgil/scripts/scan.ps1 -Path C:\path\to\repo -Format json -ExitCode -IncludeOptional
```

- **Exit codes (`--exit-code` / `-ExitCode`):** `2` if `[RED]` findings exist, `1` if only `[YELLOW]` findings exist, `0` when clean.
- **Advisory filtering (`--include-optional` / `-IncludeOptional`):** Prints `[OPTIONAL]` recommendations under a separate heading without affecting vulnerability counts or non-zero exit codes.
- **Secret redaction:** Matched credentials are always masked (`sk_l****abcd`) in both text and JSON output.

### Checking for Updates

At Step 0 of every audit, Virgil runs a read-only GitHub check against `Darkgoatie/Virgil` (4-second timeout, never downloads remote code, always exits `0` offline):

```bash
python3 skills/virgil/scripts/check_update.py
pwsh -NoProfile -File skills/virgil/scripts/check_update.ps1 -Format json
```

Copy installs record the source commit in `.installed-commit`. Pull and re-run the installer to upgrade:

```bash
git pull && ./install.sh --agent all
```

```powershell
git pull; .\install.ps1 -Agent all
```

---

## Severity Model

| Tag | Meaning | CI Exit Code (`--exit-code`) | Examples |
|---|---|---|---|
| **`[RED]`** | Serious, directly exploitable or high-impact vulnerability | `2` | Exposed secrets/public privileged env keys/`*.tfstate`, missing BOLA/BFLA or Supabase RLS, SQL/shell/template injection, unsafe .NET/Java/Python deserialization, unbounded C string functions (`gets`/`strcpy`/`sprintf`) & Chromium Rule-of-2 violations, disabled TLS or CDN origin-IP bypass, OAuth unverified-email linking & issuer flaws, `Host`-header reset poisoning, unauthenticated Server Actions, unauthenticated/plaintext message brokers, unsafe Android WebView bridges, GitHub Actions `pull_request_target`, Rule-of-Two AI agent leaks |
| **`[YELLOW]`** | Defense-in-depth hardening or operational hygiene gap | `1` | Missing nonce CSP/SRI/HSTS, parent-domain `Domain=.` cookies, directory listings/CMS editor exposure, unpinned `@v4` Actions or CI `set -x` log leaks, missing rate limits/GraphQL caps/`statement_timeout`, soft-delete filters, unhashed reset/recovery tokens, deprecated KBA security questions, mutable Android `PendingIntent`, missing `SECURITY.md` or source-map leaks |
| **`[OPTIONAL]`** | Advisory / enterprise-scale recommendation (not counted as a vulnerability) | `0` | Multi-account cloud SCPs & immutable Security Zones, Binary Authorization & OPA Gatekeeper/Kyverno, OAuth 2.0 PAR (`RFC 9126`), hybrid PQC readiness (`ML-KEM`), eBPF/Falco runtime detection, OpenSSF C/C++ compiler hardening (`PIE`/`FORTIFY_SOURCE`/RELRO), C++ GSL, AWS `s2n-tls` macros, Kani Rust Verifier, Meta `Infer`/`Pysa`, `TigerStyle` / NASA JPL `Power of 10` bounds |

---

## Skill Layout

```text
Virgil/
├── LICENSE
├── README.md
├── install.ps1
├── install.sh
└── skills/
    └── virgil/
        ├── SKILL.md                           # Severity rubric, Step 0-5 audit workflow, report contract
        ├── VERSION                            # Semantic version (1.15.0)
        ├── assets/
        │   └── icon.svg                       # Vector skill emblem
        ├── references/
        │   ├── web-browser.md                 # Web, SPAs, SSR/Next.js, CMS, DNS/DMARC, headers, cookies, SRI, CDN mTLS
        │   ├── api-auth.md                    # OWASP API Top 10, OAuth 2.1 client/issuer, OIDC, SAML, recovery, JWT, RBAC
        │   ├── secrets-crypto.md              # Secrets lifecycle, Vault/KMS policy, tfstate, OIDC federation, AEAD/Argon2id
        │   ├── db-storage.md                  # SQL/NoSQL injection, stored procs, RLS, Redis, Kafka/RabbitMQ, SMB/NFS/S3
        │   ├── infra-cicd-supply.md           # Docker, K8s, IAM, AD/Kerberos/PKI, VPN/SSH/RDP, GitHub Actions, SLSA, Rule of 2
        │   ├── ai-agent-mcp.md                # OWASP LLM/Agentic Top 10, CaMeL, MCP auth, sandboxing, RAG, ZDR
        │   ├── mobile-apps.md                 # iOS ATS/Keychain/Enclave, Android WebViews/PendingIntents, BYOD, MASVS
        │   └── payments-business-logic.md     # Stripe/PCI-DSS v4.0, race conditions, atomic locks, ERP Segregation of Duties
        └── scripts/
            ├── scan.py                        # Stdlib Python static pre-scanner (51 rules, parity with scan.ps1)
            ├── scan.ps1                       # Native PowerShell static pre-scanner (51 rules, parity with scan.py)
            ├── check_update.py                # Read-only GitHub update check
            └── check_update.ps1               # Read-only GitHub update check (PowerShell)
```

---

## Example Report Output

```markdown
# Security Audit Report: example-app

## Summary
- **Scope inspected:** src/, dist/, .github/workflows/, Dockerfile
- **Checks executed:** python3 scripts/scan.py . (2 Red, 2 Yellow) + manual route/RLS audit
- **Counts:** 2 Red, 2 Yellow

## Red Vulnerabilities
1. **[RED] `SEC-RED-002` — Privileged credential exposed via public frontend env prefix**
   - **Standard:** OWASP A04:2025 / CWE-798 / CWE-312
   - **Location:** `src/lib/stripe.ts:4`
   - **Evidence:** `const key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;`
   - **Impact:** Build inlines the privileged secret key into public client JavaScript bundles.
   - **Remediation:** Move Stripe secret operations to server-side routes using `STRIPE_SECRET_KEY` without `NEXT_PUBLIC_`.

## Yellow Vulnerabilities
1. **[YELLOW] `SEC-YEL-001` — Third-party GitHub Action not pinned to full 40-char commit SHA**
   - **Standard:** OWASP CICD-SEC-2 / CWE-829
   - **Location:** `.github/workflows/ci.yml:12`
   - **Evidence:** `uses: actions/checkout@v4`
   - **Remediation:** Pin to the immutable 40-character commit SHA with a version comment.

## Optional Recommendations
*(Advisory / enterprise-scale hardening only; not counted as vulnerabilities.)*
- **[OPTIONAL] Multi-Account Isolation:** Separate staging and production cloud accounts with SCP guardrails when scaling past single-project environments.

## Unverified / Out-of-Repo Gaps
- Live Supabase RLS policies and S3 Block Public Access account settings reside outside this repository.
```

---

## Authoritative Standards & AAA Codebase Safety Sources

Virgil's audit rubrics, pre-scanner rules, and domain reference guides synthesize primary-source engineering and security standards from leading engineering organizations and standards bodies:

| Organization | Primary Guides & Standards Credited | Source Licenses | Core Controls Incorporated |
|---|---|---|---|
| **Google** | [Chromium Rule of 2](https://chromium.googlesource.com/chromium/src/+/main/docs/security/rule-of-2.md) · [Chromium Memory Safety](https://www.chromium.org/Home/chromium-security/memory-safety/) · [Google Style Guides (C++, Rust, Go, Java)](https://github.com/google/styleguide) · [Engineering Practices Code Review](https://github.com/google/eng-practices) | `BSD-3-Clause` / `CC-BY-3.0` | Rule-of-2 native/parser containment, small/encapsulated/documented Rust `unsafe` blocks, BeyondCorp/BeyondProd mTLS & Binary Authorization. |
| **Microsoft** | [Microsoft SDL Practices](https://www.microsoft.com/en-us/securityengineering/sdl/practices) · [.NET Secure Coding Guidelines](https://raw.githubusercontent.com/dotnet/docs/main/docs/standard/security/secure-coding-guidelines.md) · [C++ Core Guidelines](https://github.com/isocpp/CppCoreGuidelines) · [Microsoft GSL](https://github.com/microsoft/GSL) · [Engineering Playbook (Security & C#)](https://github.com/microsoft/code-with-engineering-playbook) | `MIT` / `CC-BY-4.0` | Banning `BinaryFormatter`/.NET Remoting/DCOM/CAS, `gsl::span`/`not_null` bounds & lifetime safety, STRIDE threat modeling, SFI identity & secret rules. |
| **Amazon / AWS** | [AWS Well-Architected Security Pillar](https://d1.awsstatic.com/whitepapers/architecture/AWS-Security-Pillar.pdf) · [AWS `s2n-tls` Development Guide](https://raw.githubusercontent.com/aws/s2n-tls/main/docs/DEVELOPMENT-GUIDE.md) & [Safety Macros](https://raw.githubusercontent.com/aws/s2n-tls/main/docs/SAFETY-MACROS.md) · [Kani Rust Verifier](https://github.com/model-checking/kani) | `Apache-2.0` / AWS Docs | `RESULT_ENSURE*` / `RESULT_CHECKED_MEMCPY` bounds macros, non-swappable zeroed secret buffers, Kani bit-precise Rust verification, IMDSv2, IAM Access Analyzer, SCPs. |
| **Oracle** | [Secure Coding Guidelines for Java SE](https://www.oracle.com/java/technologies/javase/seccodeguide.html) | Oracle Proprietary Docs | Untrusted Java deserialization (`ObjectInputStream`/`XMLDecoder`), JNI buffer bounds, defensive copying of mutable state, finalizer-attack prevention, DoS resource caps. |
| **Palantir** | [Palantir `safe-logging`](https://github.com/palantir/safe-logging) · [Palantir `gradle-baseline`](https://github.com/palantir/gradle-baseline) · [Palantir `policy-bot`](https://github.com/palantir/policy-bot) | `Apache-2.0` | Compile-time `SafeArg` vs `UnsafeArg` PII log separation, exact dependency & classpath uniqueness locks, reproducible archives, sensitive-path PR approval policies. |
| **Cloudflare** | [`cloudflare/security-audit-skill`](https://github.com/cloudflare/security-audit-skill) · [Cloudflare `pingora`](https://github.com/cloudflare/pingora) · [Cloudflare `quiche`](https://github.com/cloudflare/quiche) · [Cloudflare `foundations`](https://github.com/cloudflare/foundations) | `MIT` / `Apache-2.0` / `BSD-2-Clause` / `BSD-3-Clause` | Adversarial candidate refutation, source-visibility (`Unverified`) gate, local IPC/privileged-helper & FFI/binary-loader/double-fetch checks, AI action-binding, memory-safe Rust parsers, `seccomp` sandboxing, and Authenticated Origin Pulls (mTLS). |
| **Meta** | [Facebook `Infer` Static Analyzer](https://github.com/facebook/infer) · [Pyre / `Pysa` Taint Analyzer](https://github.com/facebook/pyre-check) · [Facebook `Folly`](https://github.com/facebook/folly) | `MIT` / `Apache-2.0` | Compositional static analysis for null/memory/concurrency bugs, source-to-sink Python taint tracking, and AI Agent "Rule of Two" guardrails. |
| **Apple, Uber, TigerBeetle & NASA JPL** | [Apple Secure Coding Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Introduction.html) · [Uber Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md) · [TigerBeetle `TigerStyle`](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md) · [NASA JPL Power of 10](https://web.eecs.umich.edu/~imarkov/10rules.pdf) | `Apache-2.0` / U.S. Gov / Apple Docs | Apple ATS/Keychain/Secure Enclave, Go goroutine/slice safety, bounded non-recursive loops/queues, explicit-width integers, paired assertions, zeroed buffer padding. |
| **OWASP, OpenSSF, MITRE, NIST, CISA & IETF** | [OWASP Top 10:2025](https://top10.owasp.org/2025/) · [ASVS 5.0](https://asvs.owasp.org/) · [API Top 10](https://owasp.org/API-Security/) · [MASVS](https://mas.owasp.org/MASVS/) · [CI/CD Top 10](https://owasp.org/www-project-top-10-ci-cd-security-risks/) · [Secure Coding Checklist](https://raw.githubusercontent.com/OWASP/www-project-secure-coding-practices-quick-reference-guide/master/stable-en/02-checklist/05-checklist.md) · [OpenSSF Compiler Hardening Guide](https://raw.githubusercontent.com/ossf/wg-best-practices-os-developers/main/docs/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C%2B%2B.md) · [`mukul975/Anthropic-Cybersecurity-Skills`](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) (MITRE ATT&CK, ATLAS, D3FEND, Fight Fraud F3) · [CISA Memory Safety Roadmaps](https://www.cisa.gov/sites/default/files/2023-12/The-Case-for-Memory-Safe-Roadmaps-508c.pdf) · [NIST SP 800-63-4](https://csrc.nist.gov/pubs/sp/800/63/4/) & [SP 800-218 SSDF](https://csrc.nist.gov/publications/detail/sp/800-218/final) · [IETF RFC 9700](https://www.rfc-editor.org/info/rfc9700) / [RFC 8725](https://www.rfc-editor.org/info/rfc8725) | `CC-BY-SA-4.0` / `Apache-2.0` / U.S. Public Domain / IETF Trust | Full web/API/mobile/CI-CD/LLM baselines, OAuth RFC 8628 device-code & Shadow Credentials defenses, K8s RBAC escalation verbs, MITRE F3 anti-fraud positioning/monetization checks, vector embedding inversion & CI LLM red-teaming (`promptfoo`/`garak`/`PyRIT`), `in-toto`/`Tetragon`, GCC/Clang/MSVC binary hardening flags, and PQC roadmaps. |

---

## Agent Skills Ecosystem

Virgil adheres to the portable `SKILL.md` format used across major open-source skill repositories and tooling on GitHub:

| Repository | Maintainer | License | Focus & Ecosystem Role |
|---|---|---|---|
| [`anthropics/skills`](https://github.com/anthropics/skills) | Anthropic | Apache-2.0 / Source-Available | Official reference implementation of the `SKILL.md` standard, skill-authoring workflows, and document/testing skills. |
| [`obra/superpowers`](https://github.com/obra/superpowers) | Jesse Vincent (`obra`) | `MIT` | Structured engineering workflow skills covering brainstorming, planning, TDD, subagent execution, and code review. |
| [`vercel-labs/skills`](https://github.com/vercel-labs/skills) | Vercel Labs | `MIT` | Open `npx skills` CLI package manager and multi-harness skill installer (`claude-code`, `cursor`, `codex`, `gemini-cli`). |
| [`vercel-labs/agent-skills`](https://github.com/vercel-labs/agent-skills) | Vercel Labs | `MIT` / Source-Available | Production React, Next.js, web design, and deployment best-practice skills. |
| [`openai/skills`](https://github.com/openai/skills) | OpenAI | `Apache-2.0` / `MIT` | Official skill catalog for Codex CLI and coding workflows. |
| [`trailofbits/skills`](https://github.com/trailofbits/skills) | Trail of Bits | `CC-BY-SA-4.0` | Deep security engineering, threat modeling, and specialized vulnerability/auditing skills. |
| [`cloudflare/security-audit-skill`](https://github.com/cloudflare/security-audit-skill) | Cloudflare | `MIT` | Multi-phase security audit skill with adversarial candidate verification, coverage ledgers, and domain hunting companions. |
| [`mukul975/Anthropic-Cybersecurity-Skills`](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | Mukul (`mukul975`) & Contributors | `Apache-2.0` | 810+ cybersecurity skills mapped across MITRE ATT&CK, NIST CSF 2.0, MITRE ATLAS, D3FEND, NIST AI RMF, and MITRE Fight Fraud (F3). |
| [`ComposioHQ/awesome-claude-skills`](https://github.com/ComposioHQ/awesome-claude-skills) | Composio | Community Index | Community-curated directory of Claude and cross-agent skills. |
| [`VoltAgent/awesome-agent-skills`](https://github.com/VoltAgent/awesome-agent-skills) | VoltAgent | `MIT` | Broad open collection of agent skills compatible across coding assistants. |
| [`sickn33/agentic-awesome-skills`](https://github.com/sickn33/agentic-awesome-skills) | Community | `MIT` | Curated multi-agent skill directory spanning Antigravity, Cursor, Codex, and Claude Code. |

---

## License, Copyright & Third-Party Attribution Notice

- **Virgil License:** All source code, scripts (`scan.py`, `scan.ps1`, `check_update.py`, `check_update.ps1`, `install.ps1`, `install.sh`), vector assets (`icon.svg`), and documentation (`SKILL.md`, `references/*.md`, `README.md`) in this repository are **independently authored original works** licensed under the [MIT License](LICENSE) (`Copyright (c) 2026 Darkgoatie`).
- **No Verbatim Third-Party Content Copied:** Virgil does not copy, redistribute, or bundle verbatim source code or copyrighted prose from any external skill repository, proprietary vendor manual, or `CC-BY-SA-4.0` specification. Security concepts, CWE/CVE identifiers, RFC numbers, compiler flags, and architectural principles are synthesized in original technical language and linked to their upstream primary sources.
- **Upstream Licenses & Copyrights:**
  - `cloudflare/security-audit-skill` (`MIT`, Copyright Cloudflare, Inc.), `cloudflare/pingora` (`Apache-2.0`), `cloudflare/quiche` (`BSD-2-Clause`), `cloudflare/foundations` (`BSD-3-Clause`).
  - `mukul975/Anthropic-Cybersecurity-Skills` (`Apache-2.0`, Copyright Mukul & Contributors).
  - `trailofbits/skills` (`CC-BY-SA-4.0`, Copyright Trail of Bits — cited as an external ecosystem reference only).
  - `aws/s2n-tls` & `model-checking/kani` (`Apache-2.0`, Copyright Amazon.com, Inc. or its affiliates).
  - `palantir/safe-logging`, `palantir/gradle-baseline`, `palantir/policy-bot` (`Apache-2.0`, Copyright Palantir Technologies Inc.).
  - `facebook/infer` & `facebook/pyre-check` (`MIT`), `facebook/folly` (`Apache-2.0`, Copyright Meta Platforms, Inc.).
  - `microsoft/GSL` (`MIT`, Copyright Microsoft Corporation), `isocpp/CppCoreGuidelines` (Standard C++ Foundation), Microsoft `.NET` & Engineering Playbook documentation (`CC-BY-4.0` / `MIT`).
  - `google/styleguide` & `google/eng-practices` (`CC-BY-3.0`), Chromium documentation (`BSD-3-Clause`, Copyright The Chromium Authors).
  - `uber-go/guide` (`Apache-2.0`, Copyright Uber Technologies, Inc.), `tigerbeetle/tigerbeetle` (`Apache-2.0`, Copyright CoilHQ / TigerBeetle), `ossf/wg-best-practices-os-developers` (`Apache-2.0`, OpenSSF / Linux Foundation).
  - OWASP Top 10, ASVS, MASVS, Cheat Sheet Series, and GenAI/LLM Top 10 (`CC-BY-SA-4.0`, OWASP Foundation — referenced by standard identifier and hyperlink).
  - NIST Special Publications and CISA/NSA guidance (U.S. Federal Government Public Domain); IETF RFCs (IETF Trust).
- **Trademarks:** All organization, product, and framework names (`Oracle`, `Java`, `Microsoft`, `.NET`, `Palantir`, `Google`, `Chromium`, `Cloudflare`, `Amazon`, `AWS`, `Meta`, `Apple`, `Uber`, `TigerBeetle`, `Anthropic`, `OpenAI`, `Vercel`, `Trail of Bits`, `MITRE ATT&CK`, `ATLAS`, `D3FEND`, `Fight Fraud F3`, `OWASP`, `OpenSSF`) are trademarks or registered trademarks of their respective owners. Reference to them in Virgil is purely nominative and implies no endorsement or affiliation.
