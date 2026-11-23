# virgil

Portable security auditing and hardening skill for AI coding agents built on the open [Agent Skills (`SKILL.md`) specification](https://agentskills.io/specification). Audits repositories and returns a structured `[RED]` / `[YELLOW]` vulnerability report backed by deterministic pre-scanners and progressive-disclosure references across web, API/auth, secrets/crypto, databases/storage, containers/CI-CD/supply chain, and AI-agent/MCP security.

---

## Quick Setup

### Windows (PowerShell)

```powershell
# Auto-detect installed agents on this machine and install globally
.\install.ps1

# Install for specific agents (gemini, claude, hermes, codex, antigravity, cursor, agents)
.\install.ps1 -Agent gemini,claude,hermes,codex

# Install for all supported agents globally (or symlink with -Link)
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

# Install for all supported agents globally (or symlink with --link)
./install.sh --agent all
./install.sh --agent all --link

# Install into a specific project repository
./install.sh --scope project --target /path/to/repo --agent all

# Preview or remove
./install.sh --agent all --dry-run
./install.sh --agent all --uninstall
```

---

## Agent Paths & Native CLI Setups

Every target installs the identical `skills/virgil/` folder.

| Agent | Global Install Path | Project-Scoped Path | Native CLI / Cross-Agent Notes |
|---|---|---|---|
| **Claude Code** | `~/.claude/skills/virgil` | `.claude/skills/virgil` | Discovers `SKILL.md` automatically at global or repo scope. |
| **Gemini CLI** | `~/.gemini/skills/virgil` | `.gemini/skills/virgil` | Also recognizes `~/.agents/skills/`; supports `gemini skills install <git-url> --consent`. |
| **Antigravity** | `~/.gemini/config/skills/virgil` | `.agents/skills/virgil` | Project discovery also traverses `.agents/skills/` to the repo root. |
| **Hermes Agent** | `~/.hermes/skills/virgil` | `.hermes/skills/virgil` | Verify installation with `hermes skills list`. |
| **OpenAI Codex CLI** | `~/.codex/skills/virgil` | `.codex/skills/virgil` | Also reads `~/.claude/skills/` and `~/.agents/skills/`. |
| **Cursor** | `~/.cursor/skills/virgil` | `.cursor/skills/virgil` | Discovers `SKILL.md` directories in `.cursor/skills/` and `.agents/skills/`. |
| **Cross-Agent Standard** | `~/.agents/skills/virgil` | `.agents/skills/virgil` | Shared fallback path read by Codex CLI, Gemini CLI, Copilot CLI, and Antigravity. |

If you host this repository on Git, cross-agent install tools also support:

```bash
npx skills install Darkgoatie/Virgil -a claude,cursor
```

---

## Running a Security Audit

Once installed, prompt any supported agent inside a repository:

```text
Run virgil on this repository and give me the Red and Yellow vulnerability report.
```

You can also run the bundled pre-scanners directly from the skill directory (zero third-party dependencies):

```bash
# Python 3 (Linux / macOS / Windows)
python3 skills/virgil/scripts/scan.py /path/to/repo
python3 skills/virgil/scripts/scan.py /path/to/repo --format json --exit-code

# PowerShell (Windows)
pwsh -NoProfile -File skills/virgil/scripts/scan.ps1 -Path C:\path\to\repo
pwsh -NoProfile -File skills/virgil/scripts/scan.ps1 -Path C:\path\to\repo -Format json -ExitCode
```

With `--exit-code` (`-ExitCode`), the scanner exits `2` when `[RED]` findings exist, `1` when only `[YELLOW]` findings exist, and `0` when clean. Pass `--include-optional` (`-IncludeOptional`) to print advisory `[OPTIONAL]` recommendations separately without counting them as vulnerabilities. Matched secrets are always masked (`sk_l****abcd`).

---

## Checking for Updates

The skill checks `Darkgoatie/Virgil` on GitHub at the start of each audit. The check is read-only, times out after 4 seconds, never downloads or runs remote code, and never blocks an offline audit. Run it manually:

```bash
python3 skills/virgil/scripts/check_update.py
pwsh -NoProfile -File skills/virgil/scripts/check_update.ps1 -Format json
```

Copy installs record the source commit in `.installed-commit`. To upgrade, pull the clone and reinstall:

```bash
git pull && ./install.sh --agent all
```

```powershell
git pull; .\install.ps1 -Agent all
```

---

## Skill Structure

```text
Virgil/
├── README.md
├── install.ps1
├── install.sh
└── skills/
    └── virgil/
        ├── SKILL.md                      # Core severity rubric, workflow, report contract
        ├── VERSION                       # Skill semantic version
        ├── references/
        │   ├── web-browser.md            # Web, bundles, headers, cookies, DNS/email/SRI
        │   ├── api-auth.md               # OWASP API Top 10, OAuth 2.1, JWT, webhooks, RBAC
        │   ├── secrets-crypto.md         # Secrets lifecycle, client-key rules, crypto, privacy
        │   ├── db-storage.md             # SQL/NoSQL injection, RLS, Redis, S3/GCS/R2/Blob
        │   ├── infra-cicd-supply.md      # Docker, K8s, multi-account cloud, CI/CD, memory/fuzz
        │   ├── ai-agent-mcp.md           # LLM/Agentic Top 10, CaMeL, MCP auth, sandboxing
        │   ├── mobile-apps.md            # iOS ATS/Keychain/Enclave, Android, OWASP MASVS
        │   └── payments-business-logic.md # Stripe/PCI v4.0, race conditions, state machines
        └── scripts/
            ├── scan.py                   # Stdlib Python static pre-scanner
            ├── scan.ps1                  # Native PowerShell static pre-scanner
            ├── check_update.py           # Read-only GitHub update check
            └── check_update.ps1          # Read-only GitHub update check (PowerShell)
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
