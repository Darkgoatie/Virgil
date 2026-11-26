#!/usr/bin/env python3
"""Static pre-scanner for the virgil skill (stdlib only)."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "target",
    "vendor",
    ".terraform",
    ".idea",
    ".vs",
    ".pnpm-store",
}

SELF_SKILL_SEGMENTS = (
    "skills/virgil",
    ".claude/skills/virgil",
    ".gemini/skills/virgil",
    ".gemini/config/skills/virgil",
    ".hermes/skills/virgil",
    ".codex/skills/virgil",
    ".cursor/skills/virgil",
    ".agents/skills/virgil",
)

BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".7z", ".exe", ".dll",
    ".so", ".dylib", ".wasm", ".mp4", ".mp3", ".wav", ".avi", ".mov", ".pyc",
}

DOC_EXTS = {".md", ".rst", ".txt"}

LOCKFILE_NAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "cargo.lock",
    "poetry.lock",
    "composer.lock",
    "gemfile.lock",
    "go.sum",
}

MAX_FILE_BYTES = 2 * 1024 * 1024

ENV_SECRET_FILES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
}
SAFE_ENV_FILES = {".env.example", ".env.sample", ".env.template", ".env.dist"}
PRIVATE_KEY_NAMES = {"id_rsa", "id_ed25519", "id_dsa"}
PRIVATE_KEY_EXTS = {".pem", ".key", ".p12", ".pfx"}

SECRET_TOKEN_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk_live_[0-9a-zA-Z]{16,}"),
    re.compile(r"rk_live_[0-9a-zA-Z]{16,}"),
    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"),
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
]

DB_URI_RE = re.compile(
    r"(?P<prefix>(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss)://[^:\s/'\"`]+:)(?P<pw>[^@\s$<{/'\"`]+)(?P<at>@)"
)
PLACEHOLDER_PW_RE = re.compile(
    r"^(?:password|pass|changeme|placeholder|example|dummy|your[-_].*|\*{2,}|x{3,})$",
    re.IGNORECASE,
)

RE_PUBLIC_SECRET_ENV = re.compile(
    r"\b(?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC)_[A-Z0-9_]*"
    r"(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|DB_PASSWORD|DATABASE_URL|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY)[A-Z0-9_]*\b"
)

RE_DISABLED_TLS = re.compile(
    r"(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0\b|\bverify\s*=\s*False\b|InsecureSkipVerify\s*:\s*true|sslmode=(?:disable|allow|prefer|require)\b)"
)

RE_SINKS = re.compile(
    r"(?:dangerouslySetInnerHTML|\bv-html\b|\$queryRawUnsafe\b|\$executeRawUnsafe\b|\beval\s*\(|\bnew\s+Function\s*\(|\bshell\s*=\s*True\b|\bpickle\.loads?\s*\()"
)
RE_YAML_LOAD = re.compile(r"\byaml\.load\s*\(")
RE_YAML_SAFE = re.compile(r"(?:SafeLoader|BaseLoader|CSafeLoader|Loader\s*=)")

RE_JWT_DECODE = re.compile(r"\bjwt\.decode\s*\(")
RE_JWT_BYPASS = re.compile(r"(?:['\"]?verify_signature['\"]?\s*:\s*False|['\"]?alg['\"]?\s*:\s*['\"]none['\"])")

RE_ELECTRON_BAD = re.compile(
    r"(?:nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false|webSecurity\s*:\s*false|\bsandbox\s*:\s*false)"
)

RE_INFRA_EXPOSURE = re.compile(r"(?:privileged\s*:\s*true|/var/run/docker\.sock|PubliclyAccessible\s*[:=]\s*true)")
RE_CIDR_ALL = re.compile(r"0\.0\.0\.0/0")
RE_CIDR_CTX = re.compile(
    r"(?:cidr|ingress|security|postgres|mysql|mongo|redis|5432|3306|27017|6379|ssh|22\b|3389|2375|6443|port)",
    re.IGNORECASE,
)

RE_GHA_PRT = re.compile(r"\bpull_request_target\b")
RE_GHA_EVENT_EXPR = re.compile(
    r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment|discussion|review|head_commit|commits)"
)
RE_GHA_RUN = re.compile(r"^\s*(?:-\s*)?run\s*:")
RE_GHA_USES_UNPINNED = re.compile(
    r"^\s*(?:-\s*)?uses\s*:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@(?:v[0-9][A-Za-z0-9._-]*|main|master|latest)\b"
)
RE_GHA_PERMS = re.compile(r"^\s*permissions\s*:")

RE_MONGO_JS = re.compile(r"(?:javascriptEnabled\s*:\s*true|['\"]\$where['\"]\s*:)")

RE_DOCKER_LATEST = re.compile(r"^\s*FROM\s+\S+:latest(?:\s|$)", re.IGNORECASE)
RE_DOCKER_USER = re.compile(r"^\s*USER\s+(\S+)", re.IGNORECASE)
RE_DOCKER_SECRET_ENV = re.compile(
    r"^\s*(?:ARG|ENV)\s+[A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)\b",
    re.IGNORECASE,
)

RE_WEAK_CRYPTO = re.compile(
    r"(?:createHash\s*\(\s*['\"](?:md5|sha1)['\"]\s*\)|hashlib\.(?:md5|sha1)\s*\(|AES[-_]?[0-9]*[-_]?ECB|\b(?:RC4|DESede)\b|\bcreateCipher\s*\()"
)
RE_NPM_INSTALL = re.compile(r"\bnpm\s+install\b")
RE_DEBUG_TRUE = re.compile(r"^\s*DEBUG\s*[:=]\s*(?:true|1)\b", re.IGNORECASE)
RE_CSP_UNSAFE = re.compile(r"(?:'unsafe-inline'|'unsafe-eval')")
RE_CSP_HEADER = re.compile(r"(?:Content-Security-Policy|script-src|default-src)", re.IGNORECASE)

RE_CORS_ORIGIN_ANY = re.compile(r"(?:origin\s*:\s*(?:true|['\"]\*['\"])|allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\])")
RE_CORS_CREDS = re.compile(r"(?:credentials\s*:\s*true|allow_credentials\s*=\s*True)")

RE_IOS_ATS_KEY = re.compile(r"NSAllowsArbitraryLoads")
RE_IOS_ATS_TRUE = re.compile(r"(?:<true\s*/?>|[:=]\s*true\b)", re.IGNORECASE)
RE_ANDROID_CLEARTEXT = re.compile(r"(?:cleartextTrafficPermitted|android:usesCleartextTraffic)\s*=\s*['\"]true['\"]")
RE_ANDROID_EXPORTED = re.compile(r"android:exported\s*=\s*['\"]true['\"]")
RE_CF_FLEXIBLE = re.compile(r"(?:ssl_mode\s*[:=]\s*['\"]?flexible['\"]?|\"ssl\"\s*:\s*\"flexible\")", re.IGNORECASE)
RE_PAN_LOG = re.compile(
    r"(?:logger\.\w+|console\.log|print)\s*\([^)]*(?:card_?number|cardNumber|\bcvv\b|\bcvc\b)",
    re.IGNORECASE,
)
RE_EXT_SCRIPT = re.compile(r"<script\b[^>]*\bsrc\s*=\s*['\"]https?://[^'\"]+['\"][^>]*>", re.IGNORECASE)
RE_MOBILE_HYGIENE = re.compile(r"(?:android:allowBackup\s*=\s*['\"]true['\"]|\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b)")
RE_RUST_UNSAFE = re.compile(r"\bunsafe\s*\{")
RE_REDOS = re.compile(r"(?:new\s+RegExp|re\.compile)\s*\([^)]*\([^)]*[+*][^)]*\)[+*]")

HTML_EXTS = {".html", ".htm", ".ejs", ".hbs", ".jinja", ".j2", ".twig", ".vue", ".svelte", ".astro"}
CODE_REGEX_EXTS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".py", ".rb", ".php", ".java", ".cs", ".go"}
JS_TS_EXTS = {".js", ".ts", ".jsx", ".tsx", ".mjs"}
FIREBASE_RULES_NAMES = {"firestore.rules", "storage.rules", "database.rules.json"}

RE_SECURITY_DEFINER = re.compile(r"\bSECURITY\s+DEFINER\b", re.IGNORECASE)
RE_SET_SEARCH_PATH = re.compile(r"\bSET\s+search_path\b", re.IGNORECASE)
RE_FB_ANY_ALLOW = re.compile(r"\ballow\s+[^;]*:\s*if\s+true\b")
RE_FB_AUTH_ONLY = re.compile(r"request\.auth\s*!=\s*null")
RE_FB_OWNERSHIP = re.compile(r"(?:resource\.data|request\.auth\.uid\s*==|uid\s*==|isOwner|hasRole|get\()")
RE_TROJAN_BIDI = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
RE_EXTRACTALL = re.compile(r"\.extractall\s*\(")
RE_UNSAFE_XML_PY = re.compile(
    r"\b(?:xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax)\.(?:parse|fromstring|parseString)\s*\("
)
RE_USE_SERVER = re.compile(r"^\s*['\"]use server['\"]\s*;?\s*$")
RE_AUTH_HINT = re.compile(
    r"\b(?:auth|session|getUser|verifySession|currentUser|cookies|requireAuth|getServerSession)\b",
    re.IGNORECASE,
)
SCHEMA_CODE_EXTS = CODE_REGEX_EXTS | {".sql", ".prisma"}
RE_HOST_RESET_CTX = re.compile(r"(?:reset|forgot|magic|verify|invite)", re.IGNORECASE)
RE_HOST_HEADER = re.compile(
    r"(?:req\.headers?(?:\.\s*|\[\s*['\"]?|\(\s*['\"]?)(?:x-forwarded-host|host)|request\.headers?(?:\.get\(\s*['\"]?|\[\s*['\"]?|\.)(?:x-forwarded-host|host)|req\.get\(\s*['\"]?(?:x-forwarded-host|host)|request\.host\b|getHeader\(\s*['\"]?(?:x-forwarded-host|host))",
    re.IGNORECASE,
)
RE_KBA_QUESTION = re.compile(
    r"\b(?:security_?[q]uestion|security[Q]uestion|mother_?[m]aiden|first_?[p]et)\b",
    re.IGNORECASE,
)
PROP_YAML_EXTS = {".properties", ".yml", ".yaml"}
PIP_CFG_EXTS = {".txt", ".cfg", ".conf", ".ini", ".yml", ".yaml", ".sh", ".ps1"}
RE_TRUST_PROXY_TRUE = re.compile(
    r"(?:app\.set\s*\(\s*['\"]trust\s+proxy['\"]\s*,\s*true\s*\)|\btrustProxy\s*:\s*true\b)"
)
RE_ACTUATOR_EXPOSED = re.compile(
    r"management\.endpoints\.web\.exposure\.include\s*[:=]\s*['\"]?(?:\*|[^#\r\n]*\b(?:heapdump|env|mappings)\b)",
    re.IGNORECASE,
)
RE_PIP_EXTRA_INDEX = re.compile(r"--extra-[i]ndex-url(?:\s+|=)\S+", re.IGNORECASE)
RE_POSTMESSAGE_WILDCARD = re.compile(r"\.postMessage\s*\([^,\r\n]+,\s*['\"]\*['\"]\s*\)")
PUBLIC_DUMP_EXTS = {".bak", ".sql", ".dump", ".old", ".orig"}
RE_DEFAULT_CRED = re.compile(
    r"\b(?:admin_?password|root_?password|default_?password|db_?password|postgres_?password|mysql_?root_?password|redis_?password|password|passwd)\b\s*[:=]\s*['\"]?(?:admin|password|123456|changeme|default|toor|root)['\"]?(?:\s|$|,|;|#)",
    re.IGNORECASE,
)
RE_CI_LOG_TRACE = re.compile(
    r"(?:\bset\s+(?:-[a-zA-Z]*x|-o\s+xtrace)\b|(?:^|\s|;|&|\|)(?:printenv|env)\s*(?:$|[;#|&>]))"
)
RE_DOCKER_PORT_DB = re.compile(
    r"^\s*-\s*['\"]?(?:0\.0\.0\.0:)?(?:3306|5432|1433|1521|6379|27017|9200|11211):\d+['\"]?(?:\s|$|#)"
)
RE_DB_OS_EXEC = re.compile(
    r"(?:\bxp_cmdshell\b|\bCOPY\b[^;\r\n]+\b(?:FROM|TO)\s+PROGRAM\b)",
    re.IGNORECASE,
)
RE_WEAK_JWT_SECRET = re.compile(
    r"\bjwt_?secret\b\s*[:=]\s*['\"]?(?:secret|changeme|dev[-_]?secret|test[-_]?secret|123456|default|mysecret)['\"]?(?:\s|$|,|;|#)",
    re.IGNORECASE,
)
RE_DIR_LISTING = re.compile(
    r"(?:\bautoindex\s+on\b|\bOptions\s+[^\r\n]*\+Indexes\b|\bserveIndex\s*\()",
    re.IGNORECASE,
)
RE_PARENT_COOKIE_DOMAIN = re.compile(
    r"(?:Domain=\.[A-Za-z0-9.-]+|\bdomain\s*:\s*['\"]\.[A-Za-z0-9.-]+['\"])"
)
RE_WEBVIEW_FILE_ACCESS = re.compile(
    r"(?:\bsetAllowFileAccess\s*\(\s*true\s*\)|\bsetAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)|\bsetAllowFileAccessFromFileURLs\s*\(\s*true\s*\)|\baddJavascriptInterface\s*\()"
)
RE_BROKER_ANON_OR_COOKIE = re.compile(
    r"(?:\bALLOW_ANONYMOUS_LOGIN\s*[:=]\s*['\"]?yes['\"]?|\ballow_anonymous\s+true\b|\bKAFKA_CFG_ALLOW_PLAINTEXT_LISTENER\s*[:=]\s*['\"]?yes['\"]?|\bRABBITMQ_ERLANG_COOKIE\s*[:=]\s*['\"]?[A-Za-z0-9_-]{4,})",
    re.IGNORECASE,
)
RE_PENDING_INTENT_MUTABLE = re.compile(r"\bPendingIntent\.FLAG_MUTABLE\b")
RE_CMS_FILE_EDIT = re.compile(
    r"define\s*\(\s*['\"]DISALLOW_FILE_(?:EDIT|MODS)['\"]\s*,\s*false\s*\)",
    re.IGNORECASE,
)
RE_DOTNET_JAVA_DESER = re.compile(
    r"\b(?:BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer|SoapFormatter|XMLDecoder)\b|\bObjectInputStream\b[^;\r\n]*\.read(?:Object|Unshared)\s*\("
)
RE_UNSAFE_C_STR = re.compile(r"\b(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\(")
C_CPP_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
RE_SHARE_EXPORT_INSECURE = re.compile(
    r"(?:\bno_root_squash\b|\bserver\s+signing\s*=\s*(?:disabled|no|off)\b|\b(?:min\s+protocol|server\s+min\s+protocol|client\s+min\s+protocol)\s*=\s*(?:NT1|LANMAN[12]|CORE)\b|\bguest\s+ok\s*=\s*yes\b|\banonymous_enable\s*=\s*YES\b|\bcpassword\s*=\s*['\"][A-Za-z0-9+/=]{8,}['\"])",
    re.IGNORECASE,
)
RE_MYSQL_LOCAL_INFILE = re.compile(
    r"(?:\blocal[-_]infile\s*=\s*(?:1|ON|true)\b|\ballowLoadLocalInfile\s*[:=]\s*true\b|\blocalInfile\s*:\s*true\b)",
    re.IGNORECASE,
)
RE_REMOTE_DNS_PKI_INSECURE = re.compile(
    r"(?:\bPermitRootLogin\s+yes\b|\bStrictHostKeyChecking(?:=|\s+)no\b|\bUserKnownHostsFile(?:=|\s+)/dev/null\b|\ballow-transfer\s*\{\s*any\s*;\s*\}|\ballow-recursion\s*\{\s*any\s*;\s*\}|\ballow-update\s*\{\s*any\s*;\s*\}|\ballow_any_name\s*[:=]\s*true\b|\bAllowUnencrypted\s*[:=]\s*['\"]?true\b|\bSecurityTypes\s*[:=]\s*['\"]?None\b|\bsnmp-server\s+community\s+(?:public|private)\b|\bno\s+service\s+password-encryption\b)",
    re.IGNORECASE,
)
RE_K8S_OBS_VIRT_PROXY_INSECURE = re.compile(
    r"(?:\bsystem:(?:anonymous|unauthenticated)\b|--anonymous-auth(?:=|\s+)true\b|--authorization-mode(?:=|\s+)AlwaysAllow\b|--read-only-port(?:=|\s+)10255\b|\b(?:hostNetwork|hostPID|hostIPC)\s*:\s*true\b|\bauth_tcp\s*=\s*['\"]none['\"]|--insecure-registry\b|\bproxy_pass\s+https?://\$(?:http_host|host)\b|\b(?:GF_AUTH_ANONYMOUS_ENABLED|auth\.anonymous\.enabled)\s*[:=]\s*['\"]?true\b)",
    re.IGNORECASE,
)


@dataclass
class Finding:
    severity: str
    rule_id: str
    title: str
    standard: str
    file: str
    line: int
    evidence: str


def mask_token(token: str) -> str:
    if len(token) <= 8:
        return "****"
    return f"{token[:4]}****{token[-4:]}"


def redact_line(text: str) -> str:
    cleaned = text.replace("\r", "").replace("\n", " ").strip()
    for pat in SECRET_TOKEN_PATTERNS:
        cleaned = pat.sub(lambda m: mask_token(m.group(0)), cleaned)
    cleaned = DB_URI_RE.sub(lambda m: f"{m.group('prefix')}****{m.group('at')}", cleaned)
    if len(cleaned) > 140:
        cleaned = cleaned[:137] + "..."
    return cleaned


def is_self_skill_path(rel_posix: str) -> bool:
    low = rel_posix.lower()
    return any(seg in low for seg in SELF_SKILL_SEGMENTS)


def is_built_bundle_path(rel_posix: str) -> bool:
    parts = [p.lower() for p in rel_posix.split("/")]
    if any(p in {"dist", "build", "out"} for p in parts[:-1]):
        return True
    low = rel_posix.lower()
    return low.startswith(".next/static/") or "/.next/static/" in low or low.startswith("public/build/") or "/public/build/" in low


def is_public_static_path(rel_posix: str) -> bool:
    parts = [p.lower() for p in rel_posix.split("/")]
    return "public" in parts[:-1] or is_built_bundle_path(rel_posix)


def is_workflow_file(rel_posix: str) -> bool:
    low = rel_posix.lower()
    return low.startswith(".github/workflows/") and (low.endswith(".yml") or low.endswith(".yaml"))


def is_dockerfile(name: str) -> bool:
    low = name.lower()
    return low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile")


def is_iac_or_config(rel_posix: str) -> bool:
    low = rel_posix.lower()
    return low.endswith((".tf", ".tfvars", ".yml", ".yaml", ".json", ".toml"))


def is_prod_config(rel_posix: str) -> bool:
    low = rel_posix.lower()
    name = low.rsplit("/", 1)[-1]
    return name.startswith(".env.production") or ("prod" in name and name.endswith((".yml", ".yaml", ".json", ".env", ".toml")))


def add_finding(
    findings: list[Finding],
    seen: set[tuple[str, str, str, int]],
    severity: str,
    rule_id: str,
    title: str,
    standard: str,
    rel_posix: str,
    line_no: int,
    raw_line: str,
) -> None:
    key = (rule_id, title, rel_posix, line_no)
    if key in seen:
        return
    seen.add(key)
    findings.append(
        Finding(
            severity=severity,
            rule_id=rule_id,
            title=title,
            standard=standard,
            file=rel_posix,
            line=line_no,
            evidence=redact_line(raw_line),
        )
    )


def scan_secret_patterns(line: str) -> bool:
    for pat in SECRET_TOKEN_PATTERNS:
        if pat.search(line):
            return True
    for m in DB_URI_RE.finditer(line):
        if not PLACEHOLDER_PW_RE.match(m.group("pw")):
            return True
    return False


def scan_file(
    path: Path,
    rel_posix: str,
    findings: list[Finding],
    seen: set[tuple[str, str, str, int]],
) -> None:
    name = path.name
    low_name = name.lower()
    ext = path.suffix.lower()

    if is_public_static_path(rel_posix) and (low_name.endswith(".js.map") or low_name.endswith(".css.map")):
        add_finding(
            findings,
            seen,
            "YELLOW",
            "SEC-YEL-004",
            "Public production source map exposed",
            "OWASP A02:2025 / CWE-200",
            rel_posix,
            1,
            f"Source map file in web/bundle output: {rel_posix}",
        )
        return

    if is_public_static_path(rel_posix) and ext in PUBLIC_DUMP_EXTS:
        add_finding(
            findings,
            seen,
            "RED",
            "SEC-RED-020",
            "Backup or database dump file committed inside public web root",
            "OWASP A02:2025 / CWE-530",
            rel_posix,
            1,
            f"Backup/dump file in web/bundle output: {rel_posix}",
        )
        return

    if low_name.endswith(".tfstate") or low_name.endswith(".tfstate.backup"):
        add_finding(
            findings,
            seen,
            "RED",
            "SEC-RED-022",
            "Terraform state file committed (risks plaintext DB/cloud credentials)",
            "OWASP A04:2025 / CWE-312",
            rel_posix,
            1,
            f"Terraform state file present: {rel_posix}",
        )
        return

    if (
        low_name.endswith(".postman_collection.json")
        or low_name.endswith(".postman_environment.json")
        or (low_name.startswith("insomnia") and low_name.endswith(".json"))
    ):
        add_finding(
            findings,
            seen,
            "RED",
            "SEC-RED-025",
            "API client collection/environment file committed (risks live tokens and internal routes)",
            "OWASP API9 / CWE-312",
            rel_posix,
            1,
            f"API collection file present: {rel_posix}",
        )
        return

    if low_name in ENV_SECRET_FILES or ext in PRIVATE_KEY_EXTS or low_name in PRIVATE_KEY_NAMES or re.search(
        r"service[-_]?account.*\.json$", low_name
    ):
        if low_name not in SAFE_ENV_FILES:
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-003",
                "Sensitive environment or private key file committed",
                "OWASP A04:2025 / CWE-312 / CWE-798",
                rel_posix,
                1,
                f"Sensitive file present: {rel_posix}",
            )

    if ext in BINARY_EXTS or low_name in LOCKFILE_NAMES or low_name.endswith(".map"):
        return

    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    lines = content.splitlines()
    bundle_only = is_built_bundle_path(rel_posix)
    low_name = name.lower()
    is_pip_req = ext == ".txt" and (low_name.startswith("requirements") or low_name.startswith("constraints"))
    doc_only = ext in DOC_EXTS and not is_pip_req
    workflow = is_workflow_file(rel_posix)
    dockerfile = is_dockerfile(name)
    iac_cfg = is_iac_or_config(rel_posix)
    prod_cfg = is_prod_config(rel_posix)

    if bundle_only or doc_only:
        for idx, line in enumerate(lines, start=1):
            if scan_secret_patterns(line):
                title = (
                    "Hardcoded secret or private key in built frontend bundle"
                    if bundle_only
                    else "Hardcoded provider secret, private key, or inline DB credential"
                )
                add_finding(
                    findings,
                    seen,
                    "RED",
                    "SEC-RED-001",
                    title,
                    "OWASP A04:2025 / CWE-798",
                    rel_posix,
                    idx,
                    line,
                )
        return

    has_gha_perms = False
    has_docker_user = False
    in_run_block = False
    run_indent = 0
    is_server_action_file = ext in JS_TS_EXTS and any(RE_USE_SERVER.match(l) for l in lines[:5])
    file_uses_defusedxml = "defusedxml" in content

    for idx, line in enumerate(lines, start=1):
        if scan_secret_patterns(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-001",
                "Hardcoded provider secret, private key, or inline DB credential",
                "OWASP A04:2025 / CWE-798",
                rel_posix,
                idx,
                line,
            )

        if RE_PUBLIC_SECRET_ENV.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-002",
                "Privileged credential exposed via public frontend env prefix",
                "OWASP A04:2025 / CWE-798 / CWE-312",
                rel_posix,
                idx,
                line,
            )

        if RE_DISABLED_TLS.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-004",
                "TLS certificate or hostname verification disabled",
                "OWASP A04:2025 / CWE-295",
                rel_posix,
                idx,
                line,
            )

        window = "\n".join(lines[max(0, idx - 1) : min(len(lines), idx + 5)])
        cors_window = "\n".join(lines[max(0, idx - 6) : min(len(lines), idx + 6)])
        if RE_CORS_ORIGIN_ANY.search(line) and RE_CORS_CREDS.search(cors_window):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-005",
                "Permissive CORS wildcard or reflected origin paired with credentials",
                "OWASP A02:2025 / CWE-942",
                rel_posix,
                idx,
                line,
            )

        if RE_SINKS.search(line) or (RE_YAML_LOAD.search(line) and not RE_YAML_SAFE.search(line)):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-006",
                "High-risk XSS, injection, shell execution, or unsafe deserialization sink",
                "OWASP A05:2025 / CWE-79 / CWE-89 / CWE-78 / CWE-502",
                rel_posix,
                idx,
                line,
            )

        if RE_JWT_BYPASS.search(line) or (
            RE_JWT_DECODE.search(line) and "verify" not in line.lower() and "algorithms" not in line.lower()
        ):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-007",
                "Unverified JWT decode or signature bypass",
                "IETF RFC 8725 / CWE-347",
                rel_posix,
                idx,
                line,
            )

        if RE_ELECTRON_BAD.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-008",
                "Electron renderer sandbox or context isolation disabled",
                "Electron Security Checklist / CWE-250",
                rel_posix,
                idx,
                line,
            )

        if RE_INFRA_EXPOSURE.search(line) or (
            iac_cfg and RE_CIDR_ALL.search(line) and RE_CIDR_CTX.search(window)
        ):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-009",
                "Privileged container, Docker socket mount, or public DB/admin ingress",
                "OWASP A02:2025 / CIS Benchmarks / CWE-250 / CWE-284",
                rel_posix,
                idx,
                line,
            )

        if RE_MONGO_JS.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-011",
                "MongoDB server-side JavaScript enabled or $where operator used",
                "OWASP A05:2025 / CWE-943",
                rel_posix,
                idx,
                line,
            )

        ats_window = "\n".join(lines[max(0, idx - 1) : min(len(lines), idx + 2)])
        if RE_IOS_ATS_KEY.search(line) and RE_IOS_ATS_TRUE.search(ats_window):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-012",
                "iOS App Transport Security disabled (NSAllowsArbitraryLoads)",
                "Apple Platform Security / OWASP MASVS-NETWORK",
                rel_posix,
                idx,
                line,
            )

        if RE_ANDROID_CLEARTEXT.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-012",
                "Android cleartext network traffic permitted",
                "OWASP MASVS-NETWORK / CWE-319",
                rel_posix,
                idx,
                line,
            )

        if low_name == "androidmanifest.xml" and RE_ANDROID_EXPORTED.search(line):
            manifest_win = "\n".join(lines[max(0, idx - 3) : min(len(lines), idx + 6)])
            if "android:permission" not in manifest_win and "android.intent.action.MAIN" not in manifest_win:
                add_finding(
                    findings,
                    seen,
                    "RED",
                    "SEC-RED-012",
                    "Android component exported without permission guard",
                    "OWASP MASVS-PLATFORM / CWE-926",
                    rel_posix,
                    idx,
                    line,
                )

        if RE_CF_FLEXIBLE.search(line) or RE_PAN_LOG.search(line):
            title = (
                "Cloudflare Flexible TLS leaves origin hop unencrypted"
                if RE_CF_FLEXIBLE.search(line)
                else "Raw payment card PAN or CVV logged"
            )
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-013",
                title,
                "PCI-DSS v4.0 / CWE-319 / CWE-532",
                rel_posix,
                idx,
                line,
            )

        if ext in HTML_EXTS and RE_EXT_SCRIPT.search(line) and "integrity=" not in line.lower():
            add_finding(
                findings,
                seen,
                "YELLOW",
                "SEC-YEL-008",
                "External script tag missing Subresource Integrity (integrity=)",
                "PCI-DSS v4.0 / OWASP ASVS V3 / CWE-353",
                rel_posix,
                idx,
                line,
            )

        if RE_MOBILE_HYGIENE.search(line):
            add_finding(
                findings,
                seen,
                "YELLOW",
                "SEC-YEL-009",
                "Insecure mobile backup or deprecated Keychain accessibility",
                "Apple Platform Security / OWASP MASVS-STORAGE",
                rel_posix,
                idx,
                line,
            )

        if ext == ".rs" and RE_RUST_UNSAFE.search(line):
            prev_line = lines[idx - 2] if idx >= 2 else ""
            if "SAFETY:" not in line and "SAFETY:" not in prev_line:
                add_finding(
                    findings,
                    seen,
                    "OPTIONAL",
                    "SEC-OPT-001",
                    "Rust unsafe block missing // SAFETY: invariant comment",
                    "Google Safe Coding / CWE-119",
                    rel_posix,
                    idx,
                    line,
                )

        if ext in CODE_REGEX_EXTS and RE_REDOS.search(line):
            add_finding(
                findings,
                seen,
                "YELLOW",
                "SEC-YEL-010",
                "Potential catastrophic ReDoS nested quantifier regex",
                "OWASP DoS / CWE-1333",
                rel_posix,
                idx,
                line,
            )

        if ext == ".sql" and RE_SECURITY_DEFINER.search(line):
            sql_win = "\n".join(lines[max(0, idx - 3) : min(len(lines), idx + 8)])
            if not RE_SET_SEARCH_PATH.search(sql_win):
                add_finding(
                    findings,
                    seen,
                    "RED",
                    "SEC-RED-014",
                    "PostgreSQL SECURITY DEFINER function missing SET search_path",
                    "Supabase Security / CWE-426",
                    rel_posix,
                    idx,
                    line,
                )

        if low_name in FIREBASE_RULES_NAMES:
            fb_win = "\n".join(lines[max(0, idx - 2) : min(len(lines), idx + 2)])
            if RE_FB_ANY_ALLOW.search(line) or (RE_FB_AUTH_ONLY.search(line) and not RE_FB_OWNERSHIP.search(fb_win)):
                add_finding(
                    findings,
                    seen,
                    "RED",
                    "SEC-RED-014",
                    "Overly permissive Firebase security rule missing ownership check",
                    "Firebase Security Rules / CWE-285",
                    rel_posix,
                    idx,
                    line,
                )

        if RE_TROJAN_BIDI.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-015",
                "Trojan Source bidirectional Unicode control character in file",
                "CVE-2021-42574 / CWE-1007",
                rel_posix,
                idx,
                line,
            )

        if RE_EXTRACTALL.search(line) and "filter=" not in line:
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-015",
                "Potential Zip Slip via unguarded archive extractall()",
                "OWASP File Handling / CWE-22",
                rel_posix,
                idx,
                line,
            )

        if ext == ".py" and RE_UNSAFE_XML_PY.search(line) and not file_uses_defusedxml:
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-015",
                "Unsafe Python XML parser susceptible to XXE / entity expansion",
                "OWASP XXE / CWE-611",
                rel_posix,
                idx,
                line,
            )

        if ext in CODE_REGEX_EXTS and RE_HOST_RESET_CTX.search(line) and RE_HOST_HEADER.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-016",
                "Password-reset, verification, or invite URL built from untrusted Host / X-Forwarded-Host header",
                "OWASP Forgot Password / CWE-640",
                rel_posix,
                idx,
                line,
            )

        if ext in SCHEMA_CODE_EXTS and RE_KBA_QUESTION.search(line):
            add_finding(
                findings,
                seen,
                "YELLOW",
                "SEC-YEL-012",
                "Deprecated static knowledge-based authentication (KBA / security question) recovery pattern",
                "NIST SP 800-63B-4 / OWASP Forgot Password",
                rel_posix,
                idx,
                line,
            )

        if ext in JS_TS_EXTS and RE_TRUST_PROXY_TRUE.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-017",
                "Overly permissive trust proxy setting allows X-Forwarded-For IP spoofing",
                "OWASP API4 / CWE-290",
                rel_posix,
                idx,
                line,
            )

        if ext in PROP_YAML_EXTS and RE_ACTUATOR_EXPOSED.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-018",
                "Sensitive Spring Boot Actuator endpoints exposed over web",
                "OWASP A02:2025 / CWE-200",
                rel_posix,
                idx,
                line,
            )

        if (ext in PIP_CFG_EXTS or name.lower().startswith("dockerfile")) and RE_PIP_EXTRA_INDEX.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-019",
                "pip --extra-index-url enables public PyPI dependency confusion against private packages",
                "OWASP A03:2025 / CWE-427",
                rel_posix,
                idx,
                line,
            )

        if ext in JS_TS_EXTS and RE_POSTMESSAGE_WILDCARD.search(line):
            add_finding(
                findings,
                seen,
                "YELLOW",
                "SEC-YEL-013",
                "window.postMessage called with wildcard '*' targetOrigin",
                "OWASP Client-Side / CWE-346",
                rel_posix,
                idx,
                line,
            )

        if low_name not in SAFE_ENV_FILES and RE_DEFAULT_CRED.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-021",
                "Hardcoded default or weak admin/service credential",
                "OWASP A07:2025 / CWE-798",
                rel_posix,
                idx,
                line,
            )

        if ext in {".yml", ".yaml"} and RE_DOCKER_PORT_DB.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-023",
                "Container publishes DB/cache port on all interfaces (bypasses host firewall)",
                "OWASP A02:2025 / CWE-284",
                rel_posix,
                idx,
                line,
            )

        if ext in SCHEMA_CODE_EXTS and RE_DB_OS_EXEC.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-024",
                "Dangerous database-to-host OS execution primitive (xp_cmdshell / COPY PROGRAM)",
                "OWASP A05:2025 / CWE-250",
                rel_posix,
                idx,
                line,
            )

        if low_name not in SAFE_ENV_FILES and RE_WEAK_JWT_SECRET.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-026",
                "Weak or hardcoded JWT signing secret",
                "OWASP A04:2025 / CWE-798",
                rel_posix,
                idx,
                line,
            )

        if RE_DIR_LISTING.search(line):
            add_finding(
                findings,
                seen,
                "YELLOW",
                "SEC-YEL-015",
                "Directory listing enabled on web server or static middleware",
                "OWASP A02:2025 / CWE-548",
                rel_posix,
                idx,
                line,
            )

        if ext in CODE_REGEX_EXTS and RE_PARENT_COOKIE_DOMAIN.search(line):
            add_finding(
                findings,
                seen,
                "YELLOW",
                "SEC-YEL-016",
                "Cookie scoped to parent domain (exposes cookie to sibling subdomains)",
                "OWASP Session Mgmt / CWE-1275",
                rel_posix,
                idx,
                line,
            )

        if ext in {".java", ".kt"} and RE_WEBVIEW_FILE_ACCESS.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-027",
                "Insecure Android WebView file access or exposed JS bridge",
                "OWASP MASVS-PLATFORM / CWE-749",
                rel_posix,
                idx,
                line,
            )

        if (
            low_name not in SAFE_ENV_FILES
            and (ext in {".yml", ".yaml", ".conf", ".env", ".properties"} or low_name.startswith(".env") or dockerfile)
            and RE_BROKER_ANON_OR_COOKIE.search(line)
        ):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-028",
                "Unauthenticated/plaintext message broker config or hardcoded cluster cookie",
                "OWASP A02:2025 / CWE-306",
                rel_posix,
                idx,
                line,
            )

        if ext in {".java", ".kt"} and RE_PENDING_INTENT_MUTABLE.search(line):
            add_finding(
                findings,
                seen,
                "YELLOW",
                "SEC-YEL-017",
                "Mutable Android PendingIntent allows parameter tampering by third-party apps",
                "OWASP MASVS-PLATFORM / CWE-927",
                rel_posix,
                idx,
                line,
            )

        if ext == ".php" and RE_CMS_FILE_EDIT.search(line):
            add_finding(
                findings,
                seen,
                "YELLOW",
                "SEC-YEL-018",
                "CMS in-dashboard file/plugin editor explicitly enabled",
                "OWASP A02:2025 / CWE-284",
                rel_posix,
                idx,
                line,
            )

        if ext in {".cs", ".java", ".kt"} and RE_DOTNET_JAVA_DESER.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-029",
                "Unsafe .NET or Java binary deserialization API",
                "Microsoft .NET / Oracle Java SE / CWE-502",
                rel_posix,
                idx,
                line,
            )

        if ext in C_CPP_EXTS and RE_UNSAFE_C_STR.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-030",
                "Unbounded C string/buffer function susceptible to buffer overflow",
                "NASA JPL / OpenSSF / Apple / CWE-120",
                rel_posix,
                idx,
                line,
            )

        if RE_SHARE_EXPORT_INSECURE.search(line) or RE_MYSQL_LOCAL_INFILE.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-031",
                "Insecure file-share/NFS/FTP config, GPO cpassword, or MySQL local_infile enabled",
                "CIS Benchmarks / OWASP A02:2025 / CWE-306 / CWE-73",
                rel_posix,
                idx,
                line,
            )

        if RE_REMOTE_DNS_PKI_INSECURE.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-032",
                "Insecure SSH/WinRM/VNC remote admin, open DNS transfer/recursion/update, or wildcard PKI role",
                "CIS Benchmarks / OWASP A02:2025 / CWE-284 / CWE-295",
                rel_posix,
                idx,
                line,
            )

        if RE_K8S_OBS_VIRT_PROXY_INSECURE.search(line):
            add_finding(
                findings,
                seen,
                "RED",
                "SEC-RED-033",
                "Insecure K8s anonymous/host-namespace/kubelet setting, unauthenticated libvirt/Grafana, insecure registry, or NGINX dynamic proxy_pass SSRF",
                "CIS Kubernetes / OWASP A02:2025 / CWE-284 / CWE-918",
                rel_posix,
                idx,
                line,
            )

        if RE_WEAK_CRYPTO.search(line):
            add_finding(
                findings,
                seen,
                "YELLOW",
                "SEC-YEL-003",
                "Deprecated or weak cryptographic primitive",
                "OWASP A04:2025 / CWE-327 / CWE-328",
                rel_posix,
                idx,
                line,
            )

        if RE_CSP_UNSAFE.search(line) and RE_CSP_HEADER.search(window):
            add_finding(
                findings,
                seen,
                "YELLOW",
                "SEC-YEL-006",
                "Weak Content-Security-Policy directive ('unsafe-inline' or 'unsafe-eval')",
                "OWASP ASVS V3 / CWE-79",
                rel_posix,
                idx,
                line,
            )

        if workflow:
            stripped = line.lstrip(" ")
            indent = len(line) - len(stripped)
            if in_run_block and stripped and not stripped.startswith("#") and indent <= run_indent:
                in_run_block = False
            if RE_GHA_RUN.match(line):
                in_run_block = True
                run_indent = indent
            if in_run_block and RE_CI_LOG_TRACE.search(line):
                add_finding(
                    findings,
                    seen,
                    "YELLOW",
                    "SEC-YEL-014",
                    "CI shell trace or environment dump risks leaking secrets into build logs",
                    "OWASP CICD-SEC-1 / CWE-532",
                    rel_posix,
                    idx,
                    line,
                )
            if RE_GHA_PRT.search(line):
                add_finding(
                    findings,
                    seen,
                    "RED",
                    "SEC-RED-010",
                    "GitHub Actions pull_request_target privileged trigger",
                    "OWASP CICD-SEC-1 / CICD-SEC-4",
                    rel_posix,
                    idx,
                    line,
                )
            elif in_run_block and RE_GHA_EVENT_EXPR.search(line):
                add_finding(
                    findings,
                    seen,
                    "RED",
                    "SEC-RED-010",
                    "GitHub Actions script injection via untrusted event context in run block",
                    "OWASP CICD-SEC-4 / CWE-78 / CWE-94",
                    rel_posix,
                    idx,
                    line,
                )
            if RE_GHA_USES_UNPINNED.match(line):
                add_finding(
                    findings,
                    seen,
                    "YELLOW",
                    "SEC-YEL-001",
                    "Third-party GitHub Action not pinned to full 40-char commit SHA",
                    "OWASP CICD-SEC-2 / CWE-829",
                    rel_posix,
                    idx,
                    line,
                )
            if RE_GHA_PERMS.match(line):
                has_gha_perms = True
            if RE_NPM_INSTALL.search(line):
                add_finding(
                    findings,
                    seen,
                    "YELLOW",
                    "SEC-YEL-005",
                    "Non-deterministic npm install in workflow instead of npm ci --ignore-scripts",
                    "OWASP A03:2025 / SLSA",
                    rel_posix,
                    idx,
                    line,
                )

        if dockerfile:
            if RE_DOCKER_LATEST.match(line):
                add_finding(
                    findings,
                    seen,
                    "YELLOW",
                    "SEC-YEL-002",
                    "Mutable :latest base image tag in Dockerfile",
                    "OWASP Docker Cheat Sheet / CWE-494",
                    rel_posix,
                    idx,
                    line,
                )
            m_user = RE_DOCKER_USER.match(line)
            if m_user:
                if m_user.group(1).lower() in {"0", "root", "0:0", "root:root"}:
                    add_finding(
                        findings,
                        seen,
                        "YELLOW",
                        "SEC-YEL-002",
                        "Dockerfile runs container as root user",
                        "OWASP Docker Cheat Sheet / CWE-250",
                        rel_posix,
                        idx,
                        line,
                    )
                else:
                    has_docker_user = True
            if RE_DOCKER_SECRET_ENV.match(line):
                add_finding(
                    findings,
                    seen,
                    "YELLOW",
                    "SEC-YEL-002",
                    "Secret-like ARG or ENV declared in Dockerfile",
                    "OWASP Docker Cheat Sheet / CWE-798",
                    rel_posix,
                    idx,
                    line,
                )
            if RE_NPM_INSTALL.search(line):
                add_finding(
                    findings,
                    seen,
                    "YELLOW",
                    "SEC-YEL-005",
                    "Non-deterministic npm install in Dockerfile instead of npm ci --ignore-scripts",
                    "OWASP A03:2025 / SLSA",
                    rel_posix,
                    idx,
                    line,
                )
            if RE_DEBUG_TRUE.match(line) or ("DEBUG=true" in line or "DEBUG=1" in line):
                add_finding(
                    findings,
                    seen,
                    "YELLOW",
                    "SEC-YEL-005",
                    "Debug mode enabled in Dockerfile",
                    "OWASP A02:2025 / CWE-215",
                    rel_posix,
                    idx,
                    line,
                )

        if prod_cfg and RE_DEBUG_TRUE.match(line):
            add_finding(
                findings,
                seen,
                "YELLOW",
                "SEC-YEL-005",
                "Debug mode enabled in production configuration",
                "OWASP A02:2025 / CWE-215",
                rel_posix,
                idx,
                line,
            )

    if workflow and not has_gha_perms:
        add_finding(
            findings,
            seen,
            "YELLOW",
            "SEC-YEL-001",
            "Workflow missing explicit minimal GITHUB_TOKEN permissions block",
            "OWASP CICD-SEC-6",
            rel_posix,
            1,
            "No top-level or job permissions: declaration found",
        )

    if dockerfile and not has_docker_user:
        add_finding(
            findings,
            seen,
            "YELLOW",
            "SEC-YEL-002",
            "Dockerfile missing non-root USER directive",
            "OWASP Docker Cheat Sheet / CWE-250",
            rel_posix,
            1,
            "No non-root USER instruction found",
        )

    if is_server_action_file and not RE_AUTH_HINT.search(content):
        add_finding(
            findings,
            seen,
            "YELLOW",
            "SEC-YEL-011",
            "Next.js Server Action file missing explicit auth or session verification",
            "Vercel / Next.js Security / CWE-862",
            rel_posix,
            1,
            "File uses 'use server' without visible auth/session check",
        )


def walk_repo(root: Path) -> Iterable[tuple[Path, str]]:
    for dirpath, dirnames, filenames in os.walk(root):
        dir_rel = Path(dirpath).relative_to(root).as_posix()
        kept_dirs = []
        for d in sorted(dirnames):
            if d in EXCLUDED_DIRS:
                continue
            cand_rel = d if dir_rel == "." else f"{dir_rel}/{d}"
            if is_self_skill_path(cand_rel):
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            rel_posix = fname if dir_rel == "." else f"{dir_rel}/{fname}"
            if is_self_skill_path(rel_posix):
                continue
            yield fpath, rel_posix


def render_markdown(repo_name: str, files_scanned: int, findings: list[Finding], include_optional: bool) -> str:
    reds = [f for f in findings if f.severity == "RED"]
    yellows = [f for f in findings if f.severity == "YELLOW"]
    optionals = [f for f in findings if f.severity == "OPTIONAL"] if include_optional else []
    lines = [
        f"# Pre-Scan Results: {repo_name}",
        "",
        "## Summary",
        f"- **Files inspected:** {files_scanned}",
        f"- **Counts:** {len(reds)} Red, {len(yellows)} Yellow",
        "",
        "## Red Vulnerabilities",
    ]
    if not reds:
        lines.append("None found by static pre-scanner.")
    else:
        for idx, f in enumerate(reds, start=1):
            lines.extend([
                f"{idx}. **[RED] `{f.rule_id}` — {f.title}**",
                f"   - **Standard:** {f.standard}",
                f"   - **Location:** `{f.file}:{f.line}`",
                f"   - **Evidence:** `{f.evidence}`",
            ])
    lines.extend(["", "## Yellow Vulnerabilities"])
    if not yellows:
        lines.append("None found by static pre-scanner.")
    else:
        for idx, f in enumerate(yellows, start=1):
            lines.extend([
                f"{idx}. **[YELLOW] `{f.rule_id}` — {f.title}**",
                f"   - **Standard:** {f.standard}",
                f"   - **Location:** `{f.file}:{f.line}`",
                f"   - **Evidence:** `{f.evidence}`",
            ])
    if include_optional:
        lines.extend(["", "## Optional Recommendations (Not Vulnerabilities)"])
        if not optionals:
            lines.append("None flagged by static pre-scanner.")
        else:
            for idx, f in enumerate(optionals, start=1):
                lines.extend([
                    f"{idx}. **[OPTIONAL] `{f.rule_id}` — {f.title}**",
                    f"   - **Standard:** {f.standard}",
                    f"   - **Location:** `{f.file}:{f.line}`",
                    f"   - **Evidence:** `{f.evidence}`",
                ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic static pre-scanner for virgil.")
    parser.add_argument("target", nargs="?", default=".", help="Target repository directory")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--exit-code", action="store_true", help="Exit 2 on Red, 1 on Yellow only, 0 on clean")
    parser.add_argument("--include-optional", action="store_true", help="Include advisory [OPTIONAL] recommendations")
    args = parser.parse_args()

    root = Path(args.target).resolve()
    if not root.is_dir():
        print(f"Error: target directory not found: {root}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    seen: set[tuple[str, str, str, int]] = set()
    files_scanned = 0

    for fpath, rel_posix in walk_repo(root):
        files_scanned += 1
        scan_file(fpath, rel_posix, findings, seen)

    if not (root / "SECURITY.md").is_file() and not (root / ".github" / "SECURITY.md").is_file():
        add_finding(
            findings,
            seen,
            "YELLOW",
            "SEC-YEL-007",
            "Missing root SECURITY.md vulnerability disclosure policy",
            "NIST SSDF / IETF RFC 9116",
            "SECURITY.md",
            1,
            "Neither SECURITY.md nor .github/SECURITY.md exists",
        )

    reds = [f for f in findings if f.severity == "RED"]
    yellows = [f for f in findings if f.severity == "YELLOW"]
    optionals = [f for f in findings if f.severity == "OPTIONAL"]

    if args.format == "json":
        payload = {
            "target": str(root),
            "files_scanned": files_scanned,
            "counts": {"red": len(reds), "yellow": len(yellows)},
            "red": [asdict(f) for f in reds],
            "yellow": [asdict(f) for f in yellows],
        }
        if args.include_optional:
            payload["optional"] = [asdict(f) for f in optionals]
        print(json.dumps(payload, indent=2))
    else:
        print(render_markdown(root.name, files_scanned, findings, args.include_optional))

    if args.exit_code:
        if reds:
            return 2
        if yellows:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
