#!/usr/bin/env python3
"""Regression and parity test suite for scan.py and scan.ps1."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_PY = REPO_ROOT / "skills" / "virgil" / "scripts" / "scan.py"
SCAN_PS1 = REPO_ROOT / "skills" / "virgil" / "scripts" / "scan.ps1"
PWSH = shutil.which("pwsh")


def run_py(target: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCAN_PY), str(target), *extra],
        capture_output=True,
        text=True,
        check=False,
    )


def run_ps1(target: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    assert PWSH is not None, "pwsh is required for parity tests"
    return subprocess.run(
        [PWSH, "-NoProfile", "-File", str(SCAN_PS1), "-Path", str(target), *extra],
        capture_output=True,
        text=True,
        check=False,
    )


def write_fixture(root: Path, rel: str, content: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8", newline="\n")
    return p


class ScannerTests(unittest.TestCase):
    def _build_corpus(self, root: Path) -> None:
        write_fixture(root, "SECURITY.md", "# Security Policy\n")

        # 1. Multi-line Terraform CIDR lookbehind (SEC-RED-009) + IMDSv1 + public S3 (SEC-RED-035)
        write_fixture(
            root,
            "infra/main.tf",
            (
                'resource "aws_security_group" "db" {\n'
                "  ingress {\n"
                "    from_port   = 5432\n"
                "    to_port     = 5432\n"
                '    protocol    = "tcp"\n'
                '    cidr_blocks = ["0.0.0.0/0"]\n'
                "  }\n"
                "}\n"
                'resource "aws_instance" "web" {\n'
                "  metadata_options {\n"
                '    http_tokens = "optional"\n'
                "  }\n"
                "}\n"
                'resource "aws_s3_bucket_acl" "pub" {\n'
                '  acl = "public-read"\n'
                "}\n"
            ),
        )

        # 2. Multi-line CSP lookbehind (SEC-YEL-006)
        write_fixture(
            root,
            "web/headers.js",
            (
                "export const headers = {\n"
                '  "Content-Security-Policy": [\n'
                '    "default-src \'self\'",\n'
                '    "script-src \'self\' \'unsafe-eval\'"\n'
                "  ].join('; ')\n"
                "};\n"
            ),
        )

        # 3. GitHub Actions: safe env: after - run: must NOT fire; github.head_ref in run MUST fire
        write_fixture(
            root,
            ".github/workflows/ci.yml",
            (
                "name: CI\n"
                "on: pull_request\n"
                "permissions:\n"
                "  contents: read\n"
                "jobs:\n"
                "  test:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n"
                '      - run: echo "$PR_TITLE"\n'
                "        env:\n"
                "          PR_TITLE: ${{ github.event.pull_request.title }}\n"
                "      - run: echo ${{ github.head_ref }}\n"
                "      # pull_request_target is intentionally avoided\n"
                "      - uses: owner/action@develop\n"
            ),
        )

        # 4. Multi-stage Dockerfile: builder has USER node, final stage has no USER -> must flag SEC-YEL-002
        write_fixture(
            root,
            "Dockerfile",
            (
                "FROM node:20@sha256:abcdef AS builder\n"
                "USER node\n"
                "RUN echo build\n"
                "\n"
                "FROM ubuntu\n"
                "COPY --from=builder /app /app\n"
                "ENV API_KEY=SuperSecretDockerValue123456\n"
            ),
        )

        # 5. ML model.eval() must NOT flag SEC-RED-006; bare eval() MUST flag; multi-line jwt.decode & extractall
        write_fixture(
            root,
            "app/ml.py",
            (
                "model.eval()\n"
                "def bad(x):\n"
                "    return eval(x)\n"
                "payload = jwt.decode(\n"
                "    token,\n"
                "    key,\n"
                '    algorithms=["RS256"],\n'
                ")\n"
                "tar.extractall(\n"
                "    path=dest,\n"
                '    filter="data",\n'
                ")\n"
            ),
        )

        # 6. Public PEM cert must NOT flag SEC-RED-003; private PEM MUST flag
        write_fixture(
            root,
            "certs/ca.pem",
            "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END CERTIFICATE-----\n",
        )
        write_fixture(
            root,
            "certs/priv.pem",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtestkeydata\n-----END RSA PRIVATE KEY-----\n",
        )

        # 7. Firebase RTDB database.rules.json (SEC-RED-014)
        write_fixture(
            root,
            "database.rules.json",
            '{\n  "rules": {\n    ".read": true,\n    ".write": "auth != null"\n  }\n}\n',
        )

        # 8. AI agent & MCP config (SEC-RED-034) + redaction check
        write_fixture(
            root,
            ".mcp.json",
            '{\n  "mcpServers": {\n    "srv": {\n      "env": {\n        "MY_API_KEY": "live_secret_value_987654321"\n      }\n    }\n  }\n}\n',
        )
        write_fixture(
            root,
            "scripts/agent.sh",
            "claude --dangerously-skip-permissions\n",
        )

        # 9. OAuth legacy grant (SEC-RED-036) + inline virgil-ignore suppression
        write_fixture(
            root,
            "auth/oauth.ts",
            (
                'const url = "https://idp.example/auth?response_type=token";\n'
                'const legacyHash = createHash("md5"); // virgil-ignore: SEC-YEL-003\n'
            ),
        )

        # 10. Non-SEC-RED-001 redaction: RABBITMQ_ERLANG_COOKIE & NEXT_PUBLIC_JWT_SECRET
        write_fixture(
            root,
            "broker.env",
            "RABBITMQ_ERLANG_COOKIE=SuperSecretClusterCookie998877\n",
        )
        write_fixture(
            root,
            "web/config.ts",
            'export const s = "NEXT_PUBLIC_JWT_SECRET=MyVerySecretProdJwtKey9988";\n',
        )

        # 11. Inline 'use server' below line 5 (SEC-YEL-011)
        write_fixture(
            root,
            "web/action.ts",
            "// line 1\n// line 2\n// line 3\n// line 4\n// line 5\n// line 6\n'use server';\nexport async function del() {}\n",
        )

        # 12. Path containing 'skills/virgil' substring as part of another folder name must NOT be skipped
        write_fixture(
            root,
            "packages/skills/virgil-adapter/index.ts",
            "export const x = decodeJwt(tok);\n",
        )

    def test_rules_redaction_and_parity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._build_corpus(root)

            py_res = run_py(root, "--format", "json", "--include-optional")
            self.assertEqual(py_res.returncode, 0, py_res.stderr)
            py_data = json.loads(py_res.stdout)

            all_findings = py_data["red"] + py_data["yellow"] + py_data.get("optional", [])
            by_file_rule = {(f["file"], f["rule_id"], f["line"]): f for f in all_findings}
            file_rules = {(f["file"], f["rule_id"]) for f in all_findings}

            # Lookbehind multi-line Terraform CIDR & CSP
            self.assertIn(("infra/main.tf", "SEC-RED-009"), file_rules)
            self.assertIn(("infra/main.tf", "SEC-RED-035"), file_rules)
            self.assertIn(("web/headers.js", "SEC-YEL-006"), file_rules)

            # GHA: safe env: on line 12 must NOT trigger SEC-RED-010; head_ref on line 13 MUST; comment line 14 must NOT
            self.assertNotIn((".github/workflows/ci.yml", "SEC-RED-010", 12), by_file_rule)
            self.assertIn((".github/workflows/ci.yml", "SEC-RED-010", 13), by_file_rule)
            self.assertNotIn((".github/workflows/ci.yml", "SEC-RED-010", 14), by_file_rule)
            self.assertIn((".github/workflows/ci.yml", "SEC-YEL-001", 15), by_file_rule)

            # Multi-stage Dockerfile: untagged FROM ubuntu + missing USER in final stage
            docker_yel = [f for f in all_findings if f["file"] == "Dockerfile" and f["rule_id"] == "SEC-YEL-002"]
            titles = {f["title"] for f in docker_yel}
            self.assertIn("Mutable :latest base image tag in Dockerfile", titles)
            self.assertIn("Dockerfile missing non-root USER directive", titles)

            # ML model.eval() NOT flagged; bare eval() IS flagged; multi-line jwt.decode & extractall NOT flagged
            ml_findings = [f for f in all_findings if f["file"] == "app/ml.py"]
            self.assertEqual([(f["rule_id"], f["line"]) for f in ml_findings], [("SEC-RED-006", 3)])

            # Public PEM NOT flagged; private PEM IS flagged
            self.assertNotIn(("certs/ca.pem", "SEC-RED-003"), file_rules)
            self.assertIn(("certs/priv.pem", "SEC-RED-003"), file_rules)

            # Firebase RTDB database.rules.json
            self.assertIn(("database.rules.json", "SEC-RED-014"), file_rules)

            # AI / MCP rules
            self.assertIn((".mcp.json", "SEC-RED-034"), file_rules)
            self.assertIn(("scripts/agent.sh", "SEC-RED-034"), file_rules)

            # OAuth legacy + virgil-ignore suppression
            self.assertIn(("auth/oauth.ts", "SEC-RED-036"), file_rules)
            self.assertNotIn(("auth/oauth.ts", "SEC-YEL-003"), file_rules)

            # Inline 'use server' below line 5
            self.assertIn(("web/action.ts", "SEC-YEL-011"), file_rules)

            # Self-skill boundary check
            self.assertIn(("packages/skills/virgil-adapter/index.ts", "SEC-RED-007"), file_rules)

            # Evidence redaction for non-SEC-RED-001 secrets
            raw_json = py_res.stdout
            self.assertNotIn("SuperSecretDockerValue123456", raw_json)
            self.assertNotIn("live_secret_value_987654321", raw_json)
            self.assertNotIn("SuperSecretClusterCookie998877", raw_json)
            self.assertNotIn("MyVerySecretProdJwtKey9988", raw_json)

            # SARIF output check
            sarif_py = json.loads(run_py(root, "--format", "sarif", "--include-optional").stdout)
            self.assertEqual(sarif_py["version"], "2.1.0")
            self.assertEqual(len(sarif_py["runs"][0]["results"]), len(all_findings))

            # Full Python vs PowerShell parity check
            if PWSH:
                ps_res = run_ps1(root, "-Format", "json", "-IncludeOptional")
                self.assertEqual(ps_res.returncode, 0, ps_res.stderr)
                ps_data = json.loads(ps_res.stdout)
                self.assertEqual(py_data["files_scanned"], ps_data["files_scanned"])
                self.assertEqual(py_data["counts"], ps_data["counts"])
                self.assertEqual(py_data["red"], ps_data["red"])
                self.assertEqual(py_data["yellow"], ps_data["yellow"])
                self.assertEqual(py_data["optional"], ps_data["optional"])

                sarif_ps = json.loads(run_ps1(root, "-Format", "sarif", "-IncludeOptional").stdout)
                self.assertEqual(sarif_py, sarif_ps)

    def test_respect_gitignore_parity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, "SECURITY.md", "# Security\n")
            write_fixture(root, ".gitignore", ".env.local\n")
            write_fixture(root, ".env.local", "STRIPE=sk_live_1234567890abcdef1234\n")

            without_gi = json.loads(run_py(root, "--format", "json").stdout)
            self.assertGreater(without_gi["counts"]["red"], 0)

            with_gi_py = json.loads(run_py(root, "--format", "json", "--respect-gitignore").stdout)
            self.assertEqual(with_gi_py["counts"]["red"], 0)

            if PWSH:
                with_gi_ps = json.loads(run_ps1(root, "-Format", "json", "-RespectGitignore").stdout)
                self.assertEqual(with_gi_py["files_scanned"], with_gi_ps["files_scanned"])
                self.assertEqual(with_gi_py["counts"], with_gi_ps["counts"])


if __name__ == "__main__":
    unittest.main()
