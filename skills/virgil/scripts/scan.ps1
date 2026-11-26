[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Path = ".",

    [ValidateSet("markdown", "json", "sarif")]
    [string]$Format = "markdown",

    [switch]$ExitCode,
    [switch]$IncludeOptional,
    [switch]$RespectGitignore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScannerVersion = "1.17.0"
$RxCompiled = [System.Text.RegularExpressions.RegexOptions]::Compiled
$RxIgnoreCaseCompiled = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled

$ExcludedDirs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
@(
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "target", "vendor", ".terraform", ".idea", ".vs", ".pnpm-store",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".gradle",
    "Pods", ".dart_tool"
) | ForEach-Object { [void]$ExcludedDirs.Add($_) }

$SelfSkillSegments = @(
    "skills/virgil",
    ".claude/skills/virgil",
    ".gemini/skills/virgil",
    ".gemini/config/skills/virgil",
    ".hermes/skills/virgil",
    ".codex/skills/virgil",
    ".cursor/skills/virgil",
    ".agents/skills/virgil"
)

$BinaryExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".7z", ".exe", ".dll",
    ".so", ".dylib", ".wasm", ".mp4", ".mp3", ".wav", ".avi", ".mov", ".pyc",
    ".lockb"
) | ForEach-Object { [void]$BinaryExts.Add($_) }

$DocExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(".md", ".rst", ".txt") | ForEach-Object { [void]$DocExts.Add($_) }

$LockfileNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock",
    "poetry.lock", "composer.lock", "Gemfile.lock", "go.sum",
    "uv.lock", "bun.lock", "bun.lockb", "Podfile.lock", "pubspec.lock",
    "flake.lock", "packages.lock.json", "gradle.lockfile", "mix.lock"
) | ForEach-Object { [void]$LockfileNames.Add($_) }

$SafeEnvFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(".env.example", ".env.sample", ".env.template", ".env.dist", ".env.schema") | ForEach-Object { [void]$SafeEnvFiles.Add($_) }

$PrivateKeyNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@("id_rsa", "id_ed25519", "id_dsa", "id_ecdsa") | ForEach-Object { [void]$PrivateKeyNames.Add($_) }

$PrivateKeyExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx") | ForEach-Object { [void]$PrivateKeyExts.Add($_) }

$McpConfigNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@("mcp.json", ".mcp.json", "claude_desktop_config.json") | ForEach-Object { [void]$McpConfigNames.Add($_) }

$MaxFileBytes = 2MB

$ReSecretTokens = [regex]::new(
    '(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|sk_live_[0-9a-zA-Z]{16,}|rk_live_[0-9a-zA-Z]{16,}|whsec_[0-9a-zA-Z]{24,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|sk-svcacct-[A-Za-z0-9_-]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|AIza[0-9A-Za-z_-]{35}|sb_secret_[A-Za-z0-9_-]{20,}|sbp_[a-f0-9]{40}|glpat-[0-9A-Za-z_-]{20,}|npm_[A-Za-z0-9]{36}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,}|hf_[A-Za-z0-9]{34,}|gsk_[A-Za-z0-9]{48,}|SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{30,}|AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUUA7L]{58}|-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)',
    $RxCompiled
)
$ReNpmrcAuth = [regex]::new('_authToken\s*=\s*(?<val>[^\s#$<{]+)', $RxCompiled)

$DbUriRegex = [regex]::new('(?<prefix>(?:postgres|postgresql|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|sqlserver|clickhouse|cockroach)://[^:\s/''"`]+:)(?<pw>[^@\s$<{/''"`]+)(?<at>@)', $RxCompiled)
$PlaceholderPwRegex = [regex]::new('^(?:password|pass|changeme|placeholder|example|dummy|your[-_].*|\*{2,}|x{3,}|<[^>]+>|\$\{[^}]+\})$', $RxIgnoreCaseCompiled)

$ReRedactKv = [regex]::new('(?<head>(?:[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ERLANG_COOKIE)|cpassword|_authToken)\b[''"]?\s*[:=]\s*[''"]?)(?<val>[^''"\s,;#$<{]{8,})', $RxIgnoreCaseCompiled)
$ReRedactPan = [regex]::new('\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b', $RxCompiled)

$RePublicSecretEnv = [regex]::new('\b(?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC)_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|DB_PASSWORD|DATABASE_URL|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY)[A-Z0-9_]*\b', $RxCompiled)
$ReDisabledTls = [regex]::new('(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[''"]?0\b|\bverify\s*=\s*False\b|InsecureSkipVerify\s*:\s*true|sslmode=(?:disable|allow|prefer|require)\b|_create_unverified_context\b|GIT_SSL_NO_VERIFY\s*=\s*[''"]?(?:true|1)\b)', $RxCompiled)
$ReSinks = [regex]::new('(?:dangerouslySetInnerHTML|\bv-html\b|\[innerHTML\]|\bbypassSecurityTrustHtml\b|\{@html\b|\bset:html\s*=|\$queryRawUnsafe\b|\$executeRawUnsafe\b|(?<![.\w$])eval\s*\(|(?:window|globalThis)\.eval\s*\(|\bnew\s+Function\s*\(|\bshell\s*=\s*True\b|\bpickle\.loads?\s*\(|\b(?:marshal|jsonpickle)\.(?:loads?|decode)\s*\(|\bMarshal\.load\s*\(|\bunserialize\s*\()', $RxCompiled)
$ReYamlLoad = [regex]::new('\b(?:yaml|YAML)\.load\s*\(', $RxCompiled)
$ReYamlSafe = [regex]::new('(?:SafeLoader|BaseLoader|CSafeLoader|Loader\s*=)', $RxCompiled)
$ReJwtDecode = [regex]::new('\b(?:jwt\.decode|decodeJwt)\s*\(', $RxCompiled)
$ReJwtBypass = [regex]::new('(?:[''"]?verify_signature[''"]?\s*:\s*False|[''"]?alg[''"]?\s*:\s*[''"]none[''"])', $RxCompiled)
$ReJwtAlgsMix = [regex]::new('algorithms\s*[:=]\s*\[[^\]]*(?:HS256|HS384|HS512)[^\]]*(?:RS256|RS384|RS512|ES256|ES384|ES512|PS256)[^\]]*\]|algorithms\s*[:=]\s*\[[^\]]*(?:RS256|RS384|RS512|ES256|ES384|ES512|PS256)[^\]]*(?:HS256|HS384|HS512)[^\]]*\]', $RxCompiled)
$ReElectronBad = [regex]::new('(?:nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false|webSecurity\s*:\s*false|\bsandbox\s*:\s*false)', $RxCompiled)
$ReInfraExposure = [regex]::new('(?:privileged\s*:\s*true|/var/run/docker\.sock|PubliclyAccessible\s*[:=]\s*true)', $RxCompiled)
$ReCidrAll = [regex]::new('0\.0\.0\.0/0', $RxCompiled)
$ReCidrCtx = [regex]::new('(?:cidr|ingress|security|postgres|mysql|mongo|redis|5432|3306|27017|6379|ssh|22\b|3389|2375|6443|port)', $RxIgnoreCaseCompiled)
$ReGhaPrt = [regex]::new('\bpull_request_target\b', $RxCompiled)
$ReGhaEventExpr = [regex]::new('\$\{\{\s*(?:github\.head_ref\b|github\.event\.(?:issue|pull_request|comment|discussion|review|head_commit|commits|workflow_run))', $RxCompiled)
$ReGhaRun = [regex]::new('^(\s*)(?:(-\s*))?run\s*:(.*)$', $RxCompiled)
$ReGhaUsesUnpinned = [regex]::new('^\s*(?:-\s*)?uses\s*:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@(?!([0-9a-fA-F]{40})(?:\s|$|#))[^\s#]+', $RxCompiled)
$ReGhaPerms = [regex]::new('^\s*permissions\s*:', $RxCompiled)
$ReMongoJs = [regex]::new('(?:javascriptEnabled\s*:\s*true|[''"]\$where[''"]\s*:)', $RxCompiled)
$ReDockerFrom = [regex]::new('^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?', $RxIgnoreCaseCompiled)
$ReDockerLatest = [regex]::new('^\s*FROM\s+(?:--\S+\s+)*\S+:latest(?:\s|$)', $RxIgnoreCaseCompiled)
$ReDockerUser = [regex]::new('^\s*USER\s+(\S+)', $RxIgnoreCaseCompiled)
$ReDockerSecretEnv = [regex]::new('^\s*(?:ARG|ENV)\s+[A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)\b', $RxIgnoreCaseCompiled)
$ReWeakCrypto = [regex]::new('(?:createHash\s*\(\s*[''"](?:md5|sha1)[''"]\s*\)|hashlib\.(?:md5|sha1)\s*\(|AES[-_]?[0-9]*[-_]?ECB|\b(?:RC4|DESede)\b|\bcreateCipher\s*\()', $RxCompiled)
$ReNpmInstall = [regex]::new('\bnpm\s+install\b', $RxCompiled)
$ReDebugTrue = [regex]::new('^\s*DEBUG\s*[:=]\s*(?:true|1)\b', $RxIgnoreCaseCompiled)
$ReCspUnsafe = [regex]::new('(?:''unsafe-inline''|''unsafe-eval'')', $RxCompiled)
$ReCspHeader = [regex]::new('(?:Content-Security-Policy|script-src|default-src)', $RxIgnoreCaseCompiled)
$ReCorsOriginAny = [regex]::new('(?:origin\s*:\s*(?:true|[''"]\*[''"]|req\.headers\.origin|\([^)]*\)\s*=>\s*cb\s*\(\s*null\s*,\s*true\s*\))|allow_origins\s*=\s*\[\s*[''"]\*[''"]\s*\]|origins\s*=\s*[''"]\*[''"]|AllowAllOrigins\s*:\s*true|Access-Control-Allow-Origin\s+[''"]?\$http_origin)', $RxCompiled)
$ReCorsCreds = [regex]::new('(?:credentials\s*:\s*true|allow_credentials\s*=\s*True|supports_credentials\s*=\s*True|allowCredentials\s*=\s*[''"]true[''"]|Access-Control-Allow-Credentials\s+[''"]?true)', $RxCompiled)

$ReIosAtsKey = [regex]::new('NSAllowsArbitraryLoads', $RxCompiled)
$ReIosAtsTrue = [regex]::new('(?:<true\s*/?>|[:=]\s*true\b)', $RxIgnoreCaseCompiled)
$ReAndroidCleartext = [regex]::new('(?:cleartextTrafficPermitted|android:usesCleartextTraffic)\s*=\s*[''"]true[''"]', $RxCompiled)
$ReAndroidExported = [regex]::new('android:exported\s*=\s*[''"]true[''"]', $RxCompiled)
$ReCfFlexible = [regex]::new('(?:ssl_mode\s*[:=]\s*[''"]?flexible[''"]?|"ssl"\s*:\s*"flexible")', $RxIgnoreCaseCompiled)
$RePanLog = [regex]::new('(?:logger\.\w+|console\.log|print)\s*\([^)]*(?:card_?number|cardNumber|\bcvv\b|\bcvc\b)', $RxIgnoreCaseCompiled)
$ReExtScript = [regex]::new('<script\b[^>]*\bsrc\s*=\s*[''"]https?://[^''"]+[''"][^>]*>', $RxIgnoreCaseCompiled)
$ReMobileHygiene = [regex]::new('(?:android:allowBackup\s*=\s*[''"]true[''"]|\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b)', $RxCompiled)
$ReRustUnsafe = [regex]::new('\bunsafe\s*\{', $RxCompiled)
$ReRedos = [regex]::new('(?:new\s+RegExp|re\.compile)\s*\([^)]*\([^)]*[+*][^)]*\)[+*]', $RxCompiled)

$HtmlExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('.html', '.htm', '.ejs', '.hbs', '.jinja', '.j2', '.twig', '.vue', '.svelte', '.astro') | ForEach-Object { [void]$HtmlExts.Add($_) }

$CodeRegexExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.py', '.rb', '.php', '.java', '.cs', '.go') | ForEach-Object { [void]$CodeRegexExts.Add($_) }

$JsTsExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs') | ForEach-Object { [void]$JsTsExts.Add($_) }

$FirebaseRulesNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('firestore.rules', 'storage.rules', 'database.rules.json') | ForEach-Object { [void]$FirebaseRulesNames.Add($_) }

$ReSecurityDefiner = [regex]::new('\bSECURITY\s+DEFINER\b', $RxIgnoreCaseCompiled)
$ReSetSearchPath = [regex]::new('\bSET\s+search_path\b', $RxIgnoreCaseCompiled)
$ReFbAnyAllow = [regex]::new('\ballow\s+[^;]*:\s*if\s+true\b', $RxCompiled)
$ReFbAuthOnly = [regex]::new('request\.auth\s*!=\s*null', $RxCompiled)
$ReFbOwnership = [regex]::new('(?:resource\.data|request\.auth\.uid\s*==|uid\s*==|isOwner|hasRole|get\()', $RxCompiled)
$ReFbRtdbOpen = [regex]::new('[''"]\.(?:read|write)[''"]\s*:\s*(?:true\b|[''"]\s*(?:true|auth\s*!=\s*null)\s*[''"])', $RxCompiled)
$ReTrojanBidi = [regex]::new('[\u202a-\u202e\u2066-\u2069]', $RxCompiled)
$ReExtractAll = [regex]::new('\.extractall\s*\(', $RxCompiled)
$ReExtractAllSafeFilter = [regex]::new('filter\s*=\s*[''"](?:data|tar)[''"]', $RxCompiled)
$ReUnsafeXmlPy = [regex]::new('\b(?:xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax)\.(?:parse|fromstring|parseString)\s*\(', $RxCompiled)
$ReUseServer = [regex]::new('^\s*[''"]use server[''"]\s*;?\s*$', $RxCompiled)
$ReAuthHint = [regex]::new('\b(?:auth|session|getUser|verifySession|currentUser|cookies|requireAuth|getServerSession)\b', $RxIgnoreCaseCompiled)
$SchemaCodeExts = [System.Collections.Generic.HashSet[string]]::new($CodeRegexExts, [System.StringComparer]::OrdinalIgnoreCase)
@('.sql', '.prisma') | ForEach-Object { [void]$SchemaCodeExts.Add($_) }
$ReHostResetCtx = [regex]::new('(?:reset|forgot|magic|verify|invite)', $RxIgnoreCaseCompiled)
$ReHostHeader = [regex]::new('(?:req\.headers?(?:\.\s*|\[\s*[''"]?|\(\s*[''"]?)(?:x-forwarded-host|host)|request\.headers?(?:\.get\(\s*[''"]?|\[\s*[''"]?|\.)(?:x-forwarded-host|host)|req\.get\(\s*[''"]?(?:x-forwarded-host|host)|request\.host\b|getHeader\(\s*[''"]?(?:x-forwarded-host|host))', $RxIgnoreCaseCompiled)
$ReKbaQuestion = [regex]::new('\b(?:security_?[q]uestion|security[Q]uestion|mother_?[m]aiden|first_?[p]et)\b', $RxIgnoreCaseCompiled)
$PropYamlExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('.properties', '.yml', '.yaml') | ForEach-Object { [void]$PropYamlExts.Add($_) }
$PipCfgExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('.txt', '.cfg', '.conf', '.ini', '.yml', '.yaml', '.sh', '.ps1') | ForEach-Object { [void]$PipCfgExts.Add($_) }
$ReTrustProxyTrue = [regex]::new('(?:app\.set\s*\(\s*[''"]trust\s+proxy[''"]\s*,\s*true\s*\)|\btrustProxy\s*:\s*true\b)', $RxCompiled)
$ReActuatorExposed = [regex]::new('management\.endpoints\.web\.exposure\.include\s*[:=]\s*[''"]?(?:\*|[^#\r\n]*\b(?:heapdump|env|mappings)\b)', $RxIgnoreCaseCompiled)
$RePipExtraIndex = [regex]::new('--extra-[i]ndex-url(?:\s+|=)\S+', $RxIgnoreCaseCompiled)
$RePostMessageWildcard = [regex]::new('\.postMessage\s*\([^,\r\n]+,\s*[''"]\*[''"]\s*\)', $RxCompiled)
$PublicDumpExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('.bak', '.sql', '.dump', '.old', '.orig') | ForEach-Object { [void]$PublicDumpExts.Add($_) }
$ReDefaultCred = [regex]::new('\b(?:admin_?password|root_?password|default_?password|db_?password|postgres_?password|mysql_?root_?password|redis_?password|password|passwd)\b\s*[:=]\s*[''"]?(?:admin|password|123456|changeme|default|toor|root)[''"]?(?:\s|$|,|;|#)', $RxIgnoreCaseCompiled)
$ReCiLogTrace = [regex]::new('(?:\bset\s+(?:-[a-zA-Z]*x|-o\s+xtrace)\b|(?:^|\s|;|&|\|)(?:printenv|env)\s*(?:$|[;#|&>]))', $RxCompiled)
$ReDockerPortDb = [regex]::new('^\s*-\s*[''"]?(?:0\.0\.0\.0:)?(?:3306|5432|1433|1521|6379|27017|9200|11211):\d+[''"]?(?:\s|$|#)', $RxCompiled)
$ReDbOsExec = [regex]::new('(?:\bxp_cmdshell\b|\bCOPY\b[^;\r\n]+\b(?:FROM|TO)\s+PROGRAM\b)', $RxIgnoreCaseCompiled)
$ReWeakJwtSecret = [regex]::new('\bjwt_?secret\b\s*[:=]\s*[''"]?(?:secret|changeme|dev[-_]?secret|test[-_]?secret|123456|default|mysecret)[''"]?(?:\s|$|,|;|#)', $RxIgnoreCaseCompiled)
$ReDirListing = [regex]::new('(?:\bautoindex\s+on\b|\bOptions\s+[^\r\n]*\+Indexes\b|\bserveIndex\s*\()', $RxIgnoreCaseCompiled)
$ReParentCookieDomain = [regex]::new('(?:Domain=\.[A-Za-z0-9.-]+|\bdomain\s*:\s*[''"]\.[A-Za-z0-9.-]+[''"])', $RxCompiled)
$ReWebViewFileAccess = [regex]::new('(?:\bsetAllowFileAccess\s*\(\s*true\s*\)|\bsetAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)|\bsetAllowFileAccessFromFileURLs\s*\(\s*true\s*\)|\baddJavascriptInterface\s*\()', $RxCompiled)
$ReBrokerAnonOrCookie = [regex]::new('(?:\bALLOW_ANONYMOUS_LOGIN\s*[:=]\s*[''"]?yes[''"]?|\ballow_anonymous\s+true\b|\bKAFKA_CFG_ALLOW_PLAINTEXT_LISTENER\s*[:=]\s*[''"]?yes[''"]?|\bRABBITMQ_ERLANG_COOKIE\s*[:=]\s*[''"]?[A-Za-z0-9_-]{4,})', $RxIgnoreCaseCompiled)
$RePendingIntentMutable = [regex]::new('\bPendingIntent\.FLAG_MUTABLE\b', $RxCompiled)
$ReCmsFileEdit = [regex]::new('define\s*\(\s*[''"]DISALLOW_FILE_(?:EDIT|MODS)[''"]\s*,\s*false\s*\)', $RxIgnoreCaseCompiled)
$ReDotnetJavaDeser = [regex]::new('\b(?:BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer|SoapFormatter|XMLDecoder)\b|\bObjectInputStream\b[^;\r\n]*\.read(?:Object|Unshared)\s*\(', $RxCompiled)
$ReUnsafeCStr = [regex]::new('\b(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\(', $RxCompiled)
$CCppExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('.c', '.cc', '.cpp', '.cxx', '.h', '.hpp') | ForEach-Object { [void]$CCppExts.Add($_) }
$ReShareExportInsecure = [regex]::new('(?:\bno_root_squash\b|\bserver\s+signing\s*=\s*(?:disabled|no|off)\b|\b(?:min\s+protocol|server\s+min\s+protocol|client\s+min\s+protocol)\s*=\s*(?:NT1|LANMAN[12]|CORE)\b|\bguest\s+ok\s*=\s*yes\b|\banonymous_enable\s*=\s*YES\b|\bcpassword\s*=\s*[''"][A-Za-z0-9+/=]{8,}[''"])', $RxIgnoreCaseCompiled)
$ReMysqlLocalInfile = [regex]::new('(?:\blocal[-_]infile\s*=\s*(?:1|ON|true)\b|\ballowLoadLocalInfile\s*[:=]\s*true\b|\blocalInfile\s*:\s*true\b)', $RxIgnoreCaseCompiled)
$ReRemoteDnsPkiInsecure = [regex]::new('(?:\bPermitRootLogin\s+yes\b|\bStrictHostKeyChecking(?:=|\s+)no\b|\bUserKnownHostsFile(?:=|\s+)/dev/null\b|\ballow-transfer\s*\{\s*any\s*;\s*\}|\ballow-recursion\s*\{\s*any\s*;\s*\}|\ballow-update\s*\{\s*any\s*;\s*\}|\ballow_any_name\s*[:=]\s*true\b|\bAllowUnencrypted\s*[:=]\s*[''"]?true\b|\bSecurityTypes\s*[:=]\s*[''"]?None\b|\bsnmp-server\s+community\s+(?:public|private)\b|\bno\s+service\s+password-encryption\b)', $RxIgnoreCaseCompiled)
$ReK8sObsVirtProxyInsecure = [regex]::new('(?:\bsystem:(?:anonymous|unauthenticated)\b|--anonymous-auth(?:=|\s+)true\b|--authorization-mode(?:=|\s+)AlwaysAllow\b|--read-only-port(?:=|\s+)10255\b|\b(?:hostNetwork|hostPID|hostIPC|allowPrivilegeEscalation)\s*:\s*true\b|\bhostPath\s*:|\bauth_tcp\s*=\s*[''"]none[''"]|--insecure-registry\b|\bproxy_pass\s+https?://\$(?:http_host|host)\b|\b(?:GF_AUTH_ANONYMOUS_ENABLED|auth\.anonymous\.enabled)\s*[:=]\s*[''"]?true\b)', $RxIgnoreCaseCompiled)
$ReAiAgentUnsafe = [regex]::new('(?:--dangerously-skip-permissions\b|--dangerously-bypass-approvals-and-sandbox\b)', $RxCompiled)
$ReMcpSecretKv = [regex]::new('[''"][A-Z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)[A-Z0-9_]*[''"]\s*:\s*[''"](?!\$\{)(?!<)(?<val>[^''"\s]{8,})[''"]', $RxIgnoreCaseCompiled)
$ReCloudImdsBucketInsecure = [regex]::new('(?:\bhttp_tokens\s*[:=]\s*[''"]?optional[''"]?|\bHttpTokens\s*[:=]\s*[''"]?optional[''"]?|\bacl\s*[:=]\s*[''"]public-read(?:-write)?[''"]|\bblock_public_acls\s*[:=]\s*false\b|\bAllowBlobPublicAccess\s*[:=]\s*true\b|[''"](?:allUsers|allAuthenticatedUsers)[''"])', $RxIgnoreCaseCompiled)
$ReIamActionStar = [regex]::new('[''"]Action[''"]\s*:\s*(?:[''"]\*[''"]|\[\s*[''"]\*[''"]\s*\])', $RxCompiled)
$ReIamResourceStar = [regex]::new('[''"]Resource[''"]\s*:\s*(?:[''"]\*[''"]|\[\s*[''"]\*[''"]\s*\])', $RxCompiled)
$ReOauthLegacy = [regex]::new('(?:\bresponse_type\s*[:=]\s*[''"]?token[''"]?(?:\b|&|[''"])|\bgrant_type\s*[:=]\s*[''"]?password[''"]?(?:\b|&|[''"])|\bcode_challenge_method\s*[:=]\s*[''"]?plain[''"]?(?:\b|&|[''"]))', $RxIgnoreCaseCompiled)
$ReIgnoreDirective = [regex]::new('virgil-ignore:\s*([A-Z0-9_,-]+|\*)', $RxIgnoreCaseCompiled)

function Mask-Token {
    param([string]$Token)
    if ($Token.Length -le 8) { return "****" }
    return "{0}****{1}" -f $Token.Substring(0, 4), $Token.Substring($Token.Length - 4)
}

function Redact-Line {
    param([string]$Text)
    $cleaned = ($Text -replace "`r", "" -replace "`n", " ").Trim()
    $cleaned = $ReSecretTokens.Replace($cleaned, { param($m) Mask-Token $m.Value })
    $cleaned = $DbUriRegex.Replace($cleaned, {
        param($m)
        "{0}****{1}" -f $m.Groups["prefix"].Value, $m.Groups["at"].Value
    })
    $cleaned = $ReRedactKv.Replace($cleaned, {
        param($m)
        $val = $m.Groups["val"].Value
        if ($PlaceholderPwRegex.IsMatch($val)) { return $m.Value }
        "{0}{1}" -f $m.Groups["head"].Value, (Mask-Token $val)
    })
    $cleaned = $ReRedactPan.Replace($cleaned, { param($m) Mask-Token $m.Value })
    if ($cleaned.Length -gt 140) {
        $cleaned = $cleaned.Substring(0, 137) + "..."
    }
    return $cleaned
}

function Get-SliceWindow {
    param([string[]]$Lines, [int]$Index, [int]$Before, [int]$After)
    $start = [Math]::Max(0, $Index - $Before)
    $end = [Math]::Min($Lines.Count - 1, $Index + $After)
    return ($Lines[$start..$end]) -join "`n"
}

function Test-IgnoredLine {
    param([string[]]$Lines, [int]$Index, [string]$RuleId)
    $target = $RuleId.ToUpperInvariant()
    $checks = @($Lines[$Index])
    if ($Index -gt 0) { $checks += $Lines[$Index - 1] }
    foreach ($txt in $checks) {
        $m = $ReIgnoreDirective.Match($txt)
        if (-not $m.Success) { continue }
        $raw = $m.Groups[1].Value.ToUpperInvariant()
        if ($raw -eq "*") { return $true }
        foreach ($tok in $raw.Split(",")) {
            if ($tok.Trim() -eq $target) { return $true }
        }
    }
    return $false
}

function Test-SelfSkillPath {
    param([string]$RelPosix)
    $low = $RelPosix.ToLowerInvariant().Trim("/")
    $wrapped = "/$low/"
    foreach ($seg in $SelfSkillSegments) {
        if ($wrapped.Contains("/$seg/")) { return $true }
    }
    return $false
}

function Test-BuiltBundlePath {
    param([string]$RelPosix)
    $parts = $RelPosix.ToLowerInvariant().Split("/")
    if ($parts.Length -gt 1) {
        foreach ($p in $parts[0..($parts.Length - 2)]) {
            if ($p -in @("dist", "build", "out")) { return $true }
        }
    }
    $low = $RelPosix.ToLowerInvariant()
    return $low.StartsWith(".next/static/") -or $low.Contains("/.next/static/") -or $low.StartsWith("public/build/") -or $low.Contains("/public/build/")
}

function Test-PublicStaticPath {
    param([string]$RelPosix)
    if (Test-BuiltBundlePath $RelPosix) { return $true }
    $parts = $RelPosix.ToLowerInvariant().Split("/")
    if ($parts.Length -gt 1) {
        return ($parts[0..($parts.Length - 2)] -contains "public")
    }
    return $false
}

function Test-EnvSecretFile {
    param([string]$LowName)
    if ($SafeEnvFiles.Contains($LowName)) { return $false }
    return ($LowName -eq ".env") -or $LowName.StartsWith(".env.") -or ($LowName -eq ".envrc")
}

function Get-GitignorePatterns {
    param([string]$RootFullName)
    $giPath = Join-Path $RootFullName ".gitignore"
    if (-not (Test-Path -LiteralPath $giPath -PathType Leaf)) { return @() }
    $info = [System.IO.FileInfo]::new($giPath)
    if (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return @() }
    $patterns = [System.Collections.Generic.List[string]]::new()
    try {
        foreach ($raw in [System.IO.File]::ReadAllLines($giPath)) {
            $line = $raw.Trim()
            if (-not $line -or $line.StartsWith("#") -or $line.StartsWith("!")) { continue }
            $patterns.Add($line)
        }
    } catch {
        return @()
    }
    return ,$patterns.ToArray()
}

function Convert-GlobToRegex {
    param([string]$Glob)
    $sb = [System.Text.StringBuilder]::new("^")
    for ($k = 0; $k -lt $Glob.Length; $k++) {
        $ch = $Glob[$k]
        if ($ch -eq '*') { [void]$sb.Append('.*') }
        elseif ($ch -eq '?') { [void]$sb.Append('.') }
        else { [void]$sb.Append([regex]::Escape($ch.ToString())) }
    }
    [void]$sb.Append('$')
    return $sb.ToString()
}

function Test-MatchesGitignore {
    param([string]$RelPosix, [bool]$IsDir, [string[]]$Patterns)
    if ($Patterns.Length -eq 0) { return $false }
    $parts = $RelPosix.Split("/")
    $name = $parts[$parts.Length - 1]
    foreach ($pat in $Patterns) {
        $dirOnly = $pat.EndsWith("/")
        $clean = $pat.TrimEnd("/")
        $rxStr = Convert-GlobToRegex ($clean.TrimStart("/"))
        if ($dirOnly -and -not $IsDir) {
            if ($parts.Length -gt 1) {
                foreach ($p in $parts[0..($parts.Length - 2)]) {
                    if ($p -cmatch $rxStr) { return $true }
                }
            }
            continue
        }
        if ($clean.TrimStart("/").Contains("/")) {
            if ($RelPosix -cmatch $rxStr) { return $true }
        } else {
            if ($name -cmatch $rxStr) { return $true }
            if ($parts.Length -gt 1) {
                foreach ($p in $parts[0..($parts.Length - 2)]) {
                    if ($p -cmatch $rxStr) { return $true }
                }
            }
        }
    }
    return $false
}

function Test-SecretPatterns {
    param([string]$Line, [string]$LowName = "")
    if ($ReSecretTokens.IsMatch($Line)) { return $true }
    foreach ($m in $DbUriRegex.Matches($Line)) {
        if (-not $PlaceholderPwRegex.IsMatch($m.Groups["pw"].Value)) {
            return $true
        }
    }
    if ($LowName -eq ".npmrc") {
        $mNpm = $ReNpmrcAuth.Match($Line)
        if ($mNpm.Success -and -not $PlaceholderPwRegex.IsMatch($mNpm.Groups["val"].Value)) {
            return $true
        }
    }
    return $false
}

function Test-BinaryFile {
    param([string]$FullName)
    try {
        $fs = [System.IO.File]::OpenRead($FullName)
        try {
            $buf = [byte[]]::new(8192)
            $read = $fs.Read($buf, 0, $buf.Length)
            for ($k = 0; $k -lt $read; $k++) {
                if ($buf[$k] -eq 0) { return $true }
            }
            return $false
        } finally {
            $fs.Dispose()
        }
    } catch {
        return $true
    }
}

function Add-Finding {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [System.Collections.Generic.HashSet[string]]$Seen,
        [string]$Severity,
        [string]$RuleId,
        [string]$Title,
        [string]$Standard,
        [string]$RelPosix,
        [int]$LineNo,
        [string]$RawLine,
        [string[]]$Lines = $null,
        [int]$LineIdx = -1
    )
    if ($null -ne $Lines -and $LineIdx -ge 0 -and (Test-IgnoredLine $Lines $LineIdx $RuleId)) { return }
    $key = "$RuleId|$Title|$RelPosix|$LineNo"
    if ($Seen.Contains($key)) { return }
    [void]$Seen.Add($key)
    $Findings.Add([pscustomobject]@{
        severity = $Severity
        rule_id  = $RuleId
        title    = $Title
        standard = $Standard
        file     = $RelPosix
        line     = $LineNo
        evidence = (Redact-Line $RawLine)
    })
}

function Invoke-ScanFile {
    param(
        [System.IO.FileInfo]$FileInfo,
        [string]$RelPosix,
        [System.Collections.Generic.List[object]]$Findings,
        [System.Collections.Generic.HashSet[string]]$Seen
    )
    $name = $FileInfo.Name
    $lowName = $name.ToLowerInvariant()
    $ext = $FileInfo.Extension.ToLowerInvariant()

    if ((Test-PublicStaticPath $RelPosix) -and ($lowName.EndsWith(".js.map") -or $lowName.EndsWith(".css.map"))) {
        Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-004" "Public production source map exposed" "OWASP A02:2025 / CWE-200" $RelPosix 1 "Source map file in web/bundle output: $RelPosix"
        return
    }
    if ((Test-PublicStaticPath $RelPosix) -and $PublicDumpExts.Contains($ext)) {
        Add-Finding $Findings $Seen "RED" "SEC-RED-020" "Backup or database dump file committed inside public web root" "OWASP A02:2025 / CWE-530" $RelPosix 1 "Backup/dump file in web/bundle output: $RelPosix"
        return
    }
    if ($lowName.EndsWith(".tfstate") -or $lowName.EndsWith(".tfstate.backup")) {
        Add-Finding $Findings $Seen "RED" "SEC-RED-022" "Terraform state file committed (risks plaintext DB/cloud credentials)" "OWASP A04:2025 / CWE-312" $RelPosix 1 "Terraform state file present: $RelPosix"
        return
    }
    if ($lowName.EndsWith(".postman_collection.json") -or $lowName.EndsWith(".postman_environment.json") -or ($lowName.StartsWith("insomnia") -and $lowName.EndsWith(".json"))) {
        Add-Finding $Findings $Seen "RED" "SEC-RED-025" "API client collection/environment file committed (risks live tokens and internal routes)" "OWASP API9 / CWE-312" $RelPosix 1 "API collection file present: $RelPosix"
        return
    }

    if ((Test-EnvSecretFile $lowName) -or $PrivateKeyExts.Contains($ext) -or $PrivateKeyNames.Contains($lowName) -or ($lowName -match "service[-_]?account.*\.json$")) {
        Add-Finding $Findings $Seen "RED" "SEC-RED-003" "Sensitive environment or private key file committed" "OWASP A04:2025 / CWE-312 / CWE-798" $RelPosix 1 "Sensitive file present: $RelPosix"
    }

    if ($BinaryExts.Contains($ext) -or $LockfileNames.Contains($lowName) -or $lowName.EndsWith(".map")) { return }
    if ($FileInfo.Length -gt $MaxFileBytes) { return }
    if (Test-BinaryFile $FileInfo.FullName) { return }

    try {
        $content = [System.IO.File]::ReadAllText($FileInfo.FullName)
    } catch {
        return
    }

    if ($ext -eq ".pem" -and $content.Contains("PRIVATE KEY")) {
        Add-Finding $Findings $Seen "RED" "SEC-RED-003" "Sensitive environment or private key file committed" "OWASP A04:2025 / CWE-312 / CWE-798" $RelPosix 1 "Private key PEM file present: $RelPosix"
    }

    if ($content.Length -eq 0) {
        [string[]]$lines = @()
    } else {
        $rawLines = $content -split "`r?`n"
        if ($rawLines.Count -gt 0 -and ($content.EndsWith("`n") -or $content.EndsWith("`r")) -and $rawLines[$rawLines.Count - 1] -eq "") {
            if ($rawLines.Count -eq 1) {
                [string[]]$lines = @()
            } else {
                [string[]]$lines = $rawLines[0..($rawLines.Count - 2)]
            }
        } else {
            [string[]]$lines = $rawLines
        }
    }

    $bundleOnly = Test-BuiltBundlePath $RelPosix
    $isPipReq = ($ext -eq ".txt") -and ($lowName.StartsWith("requirements") -or $lowName.StartsWith("constraints"))
    $docOnly = $DocExts.Contains($ext) -and -not $isPipReq
    $lowRel = $RelPosix.ToLowerInvariant()
    $isGhWorkflow = $lowRel.StartsWith(".github/workflows/") -and ($lowRel.EndsWith(".yml") -or $lowRel.EndsWith(".yaml"))
    $isGhAction = $lowRel.StartsWith(".github/actions/") -and ($lowName -eq "action.yml" -or $lowName -eq "action.yaml")
    $workflow = $isGhWorkflow -or $isGhAction
    $dockerfile = ($lowName -eq "dockerfile") -or $lowName.StartsWith("dockerfile.") -or $lowName.EndsWith(".dockerfile")
    $iacCfg = $lowRel -match "\.(?:tf|tfvars|ya?ml|json|toml)$"
    $prodCfg = $lowName.StartsWith(".env.production") -or $lowName.StartsWith(".env.prod") -or ($lowName.Contains("prod") -and ($lowName -match "\.(?:ya?ml|json|env|toml)$"))
    $isMcpCfg = $McpConfigNames.Contains($lowName)

    if ($bundleOnly -or $docOnly) {
        $title = if ($bundleOnly) {
            "Hardcoded secret or private key in built frontend bundle"
        } else {
            "Hardcoded provider secret, private key, or inline DB credential"
        }
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if (Test-SecretPatterns $lines[$i] $lowName) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-001" $title "OWASP A04:2025 / CWE-798" $RelPosix ($i + 1) $lines[$i] $lines $i
            }
        }
        return
    }

    $hasGhaPerms = $false
    $dockerStageCount = 0
    $dockerStageUser = $null
    $dockerStageUserLine = 1
    $dockerStageUserRaw = ""
    $dockerStageAliases = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $inRunBlock = $false
    $runIndent = 0
    $isServerActionFile = $false
    if ($JsTsExts.Contains($ext)) {
        for ($k = 0; $k -lt $lines.Count; $k++) {
            if ($ReUseServer.IsMatch($lines[$k])) { $isServerActionFile = $true; break }
        }
    }
    $fileUsesDefusedXml = $content.Contains("defusedxml")

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $idx = $i + 1
        $line = $lines[$i]

        if (Test-SecretPatterns $line $lowName) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-001" "Hardcoded provider secret, private key, or inline DB credential" "OWASP A04:2025 / CWE-798" $RelPosix $idx $line $lines $i
        }
        if ($RePublicSecretEnv.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-002" "Privileged credential exposed via public frontend env prefix" "OWASP A04:2025 / CWE-798 / CWE-312" $RelPosix $idx $line $lines $i
        }
        if ($ReDisabledTls.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-004" "TLS certificate or hostname verification disabled" "OWASP A04:2025 / CWE-295" $RelPosix $idx $line $lines $i
        }
        if ($ReCorsOriginAny.IsMatch($line)) {
            $corsWindow = Get-SliceWindow $lines $i 5 5
            if ($ReCorsCreds.IsMatch($corsWindow)) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-005" "Permissive CORS wildcard or reflected origin paired with credentials" "OWASP A02:2025 / CWE-942" $RelPosix $idx $line $lines $i
            }
        }
        if ($ReSinks.IsMatch($line) -or ($ReYamlLoad.IsMatch($line) -and -not $ReYamlSafe.IsMatch($line))) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-006" "High-risk XSS, injection, shell execution, or unsafe deserialization sink" "OWASP A05:2025 / CWE-79 / CWE-89 / CWE-78 / CWE-502" $RelPosix $idx $line $lines $i
        }
        if ($ReJwtBypass.IsMatch($line) -or $ReJwtAlgsMix.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-007" "Unverified JWT decode or signature bypass" "IETF RFC 8725 / CWE-347" $RelPosix $idx $line $lines $i
        } elseif ($ReJwtDecode.IsMatch($line)) {
            if ($JsTsExts.Contains($ext)) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-007" "Unverified JWT decode or signature bypass" "IETF RFC 8725 / CWE-347" $RelPosix $idx $line $lines $i
            } else {
                $jwtWin = (Get-SliceWindow $lines $i 0 4).ToLowerInvariant()
                if (-not $jwtWin.Contains("verify") -and -not $jwtWin.Contains("algorithms")) {
                    Add-Finding $Findings $Seen "RED" "SEC-RED-007" "Unverified JWT decode or signature bypass" "IETF RFC 8725 / CWE-347" $RelPosix $idx $line $lines $i
                }
            }
        }
        if ($ReElectronBad.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-008" "Electron renderer sandbox or context isolation disabled" "Electron Security Checklist / CWE-250" $RelPosix $idx $line $lines $i
        }
        if ($ReInfraExposure.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-009" "Privileged container, Docker socket mount, or public DB/admin ingress" "OWASP A02:2025 / CIS Benchmarks / CWE-250 / CWE-284" $RelPosix $idx $line $lines $i
        } elseif ($iacCfg -and $ReCidrAll.IsMatch($line)) {
            $cidrWin = Get-SliceWindow $lines $i 5 5
            if ($ReCidrCtx.IsMatch($cidrWin)) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-009" "Privileged container, Docker socket mount, or public DB/admin ingress" "OWASP A02:2025 / CIS Benchmarks / CWE-250 / CWE-284" $RelPosix $idx $line $lines $i
            }
        }
        if ($ReMongoJs.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-011" "MongoDB server-side JavaScript enabled or `$where operator used" "OWASP A05:2025 / CWE-943" $RelPosix $idx $line $lines $i
        }
        if ($ReIosAtsKey.IsMatch($line)) {
            $atsWindow = Get-SliceWindow $lines $i 0 2
            if ($ReIosAtsTrue.IsMatch($atsWindow)) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-012" "iOS App Transport Security disabled (NSAllowsArbitraryLoads)" "Apple Platform Security / OWASP MASVS-NETWORK" $RelPosix $idx $line $lines $i
            }
        }
        if ($ReAndroidCleartext.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-012" "Android cleartext network traffic permitted" "OWASP MASVS-NETWORK / CWE-319" $RelPosix $idx $line $lines $i
        }
        if ($lowName -eq "androidmanifest.xml" -and $ReAndroidExported.IsMatch($line)) {
            $manifestWin = Get-SliceWindow $lines $i 2 5
            if (-not $manifestWin.Contains("android:permission") -and -not $manifestWin.Contains("android.intent.action.MAIN")) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-012" "Android component exported without permission guard" "OWASP MASVS-PLATFORM / CWE-926" $RelPosix $idx $line $lines $i
            }
        }
        if ($ReCfFlexible.IsMatch($line) -or $RePanLog.IsMatch($line)) {
            $cfTitle = if ($ReCfFlexible.IsMatch($line)) {
                "Cloudflare Flexible TLS leaves origin hop unencrypted"
            } else {
                "Raw payment card PAN or CVV logged"
            }
            Add-Finding $Findings $Seen "RED" "SEC-RED-013" $cfTitle "PCI-DSS v4.0 / CWE-319 / CWE-532" $RelPosix $idx $line $lines $i
        }
        if ($HtmlExts.Contains($ext) -and $ReExtScript.IsMatch($line) -and -not $line.ToLowerInvariant().Contains("integrity=")) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-008" "External script tag missing Subresource Integrity (integrity=)" "PCI-DSS v4.0 / OWASP ASVS V3 / CWE-353" $RelPosix $idx $line $lines $i
        }
        if ($ReMobileHygiene.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-009" "Insecure mobile backup or deprecated Keychain accessibility" "Apple Platform Security / OWASP MASVS-STORAGE" $RelPosix $idx $line $lines $i
        }
        if ($ext -eq ".rs" -and $ReRustUnsafe.IsMatch($line)) {
            $prevLine = if ($i -ge 1) { $lines[$i - 1] } else { "" }
            if (-not $line.Contains("SAFETY:") -and -not $prevLine.Contains("SAFETY:")) {
                Add-Finding $Findings $Seen "OPTIONAL" "SEC-OPT-001" "Rust unsafe block missing // SAFETY: invariant comment" "Google Safe Coding / CWE-119" $RelPosix $idx $line $lines $i
            }
        }
        if ($CodeRegexExts.Contains($ext) -and $ReRedos.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-010" "Potential catastrophic ReDoS nested quantifier regex" "OWASP DoS / CWE-1333" $RelPosix $idx $line $lines $i
        }
        if ($ext -eq ".sql" -and $ReSecurityDefiner.IsMatch($line)) {
            $sqlWin = Get-SliceWindow $lines $i 4 8
            if (-not $ReSetSearchPath.IsMatch($sqlWin)) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-014" "PostgreSQL SECURITY DEFINER function missing SET search_path" "Supabase Security / CWE-426" $RelPosix $idx $line $lines $i
            }
        }
        if ($FirebaseRulesNames.Contains($lowName)) {
            if ($lowName -eq "database.rules.json") {
                if ($ReFbRtdbOpen.IsMatch($line)) {
                    Add-Finding $Findings $Seen "RED" "SEC-RED-014" "Overly permissive Firebase security rule missing ownership check" "Firebase Security Rules / CWE-285" $RelPosix $idx $line $lines $i
                }
            } else {
                if ($ReFbAnyAllow.IsMatch($line)) {
                    Add-Finding $Findings $Seen "RED" "SEC-RED-014" "Overly permissive Firebase security rule missing ownership check" "Firebase Security Rules / CWE-285" $RelPosix $idx $line $lines $i
                } elseif ($ReFbAuthOnly.IsMatch($line)) {
                    $fbWin = Get-SliceWindow $lines $i 1 1
                    if (-not $ReFbOwnership.IsMatch($fbWin)) {
                        Add-Finding $Findings $Seen "RED" "SEC-RED-014" "Overly permissive Firebase security rule missing ownership check" "Firebase Security Rules / CWE-285" $RelPosix $idx $line $lines $i
                    }
                }
            }
        }
        if ($ReTrojanBidi.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-015" "Trojan Source bidirectional Unicode control character in file" "CVE-2021-42574 / CWE-1007" $RelPosix $idx $line $lines $i
        }
        if ($ReExtractAll.IsMatch($line)) {
            $extWin = Get-SliceWindow $lines $i 0 3
            if (-not $ReExtractAllSafeFilter.IsMatch($extWin)) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-015" "Potential Zip Slip via unguarded archive extractall()" "OWASP File Handling / CWE-22" $RelPosix $idx $line $lines $i
            }
        }
        if ($ext -eq ".py" -and $ReUnsafeXmlPy.IsMatch($line) -and -not $fileUsesDefusedXml) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-015" "Unsafe Python XML parser susceptible to XXE / entity expansion" "OWASP XXE / CWE-611" $RelPosix $idx $line $lines $i
        }
        if ($CodeRegexExts.Contains($ext) -and $ReHostResetCtx.IsMatch($line) -and $ReHostHeader.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-016" "Password-reset, verification, or invite URL built from untrusted Host / X-Forwarded-Host header" "OWASP Forgot Password / CWE-640" $RelPosix $idx $line $lines $i
        }
        if ($SchemaCodeExts.Contains($ext) -and $ReKbaQuestion.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-012" "Deprecated static knowledge-based authentication (KBA / security question) recovery pattern" "NIST SP 800-63B-4 / OWASP Forgot Password" $RelPosix $idx $line $lines $i
        }
        if ($JsTsExts.Contains($ext) -and $ReTrustProxyTrue.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-017" "Overly permissive trust proxy setting allows X-Forwarded-For IP spoofing" "OWASP API4 / CWE-290" $RelPosix $idx $line $lines $i
        }
        if ($PropYamlExts.Contains($ext) -and $ReActuatorExposed.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-018" "Sensitive Spring Boot Actuator endpoints exposed over web" "OWASP A02:2025 / CWE-200" $RelPosix $idx $line $lines $i
        }
        if (($PipCfgExts.Contains($ext) -or $dockerfile) -and $RePipExtraIndex.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-019" "pip --extra-index-url enables public PyPI dependency confusion against private packages" "OWASP A03:2025 / CWE-427" $RelPosix $idx $line $lines $i
        }
        if ($JsTsExts.Contains($ext) -and $RePostMessageWildcard.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-013" "window.postMessage called with wildcard '*' targetOrigin" "OWASP Client-Side / CWE-346" $RelPosix $idx $line $lines $i
        }
        if (-not $SafeEnvFiles.Contains($lowName) -and $ReDefaultCred.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-021" "Hardcoded default or weak admin/service credential" "OWASP A07:2025 / CWE-798" $RelPosix $idx $line $lines $i
        }
        if (($ext -eq ".yml" -or $ext -eq ".yaml") -and $ReDockerPortDb.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-023" "Container publishes DB/cache port on all interfaces (bypasses host firewall)" "OWASP A02:2025 / CWE-284" $RelPosix $idx $line $lines $i
        }
        if ($SchemaCodeExts.Contains($ext) -and $ReDbOsExec.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-024" "Dangerous database-to-host OS execution primitive (xp_cmdshell / COPY PROGRAM)" "OWASP A05:2025 / CWE-250" $RelPosix $idx $line $lines $i
        }
        if (-not $SafeEnvFiles.Contains($lowName) -and $ReWeakJwtSecret.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-026" "Weak or hardcoded JWT signing secret" "OWASP A04:2025 / CWE-798" $RelPosix $idx $line $lines $i
        }
        if ($ReDirListing.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-015" "Directory listing enabled on web server or static middleware" "OWASP A02:2025 / CWE-548" $RelPosix $idx $line $lines $i
        }
        if ($CodeRegexExts.Contains($ext) -and $ReParentCookieDomain.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-016" "Cookie scoped to parent domain (exposes cookie to sibling subdomains)" "OWASP Session Mgmt / CWE-1275" $RelPosix $idx $line $lines $i
        }
        if (($ext -eq ".java" -or $ext -eq ".kt") -and $ReWebViewFileAccess.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-027" "Insecure Android WebView file access or exposed JS bridge" "OWASP MASVS-PLATFORM / CWE-749" $RelPosix $idx $line $lines $i
        }
        if ((-not $SafeEnvFiles.Contains($lowName)) -and (($ext -in @(".yml", ".yaml", ".conf", ".env", ".properties")) -or $lowName.StartsWith(".env") -or $dockerfile) -and $ReBrokerAnonOrCookie.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-028" "Unauthenticated/plaintext message broker config or hardcoded cluster cookie" "OWASP A02:2025 / CWE-306" $RelPosix $idx $line $lines $i
        }
        if (($ext -eq ".java" -or $ext -eq ".kt") -and $RePendingIntentMutable.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-017" "Mutable Android PendingIntent allows parameter tampering by third-party apps" "OWASP MASVS-PLATFORM / CWE-927" $RelPosix $idx $line $lines $i
        }
        if ($ext -eq ".php" -and $ReCmsFileEdit.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-018" "CMS in-dashboard file/plugin editor explicitly enabled" "OWASP A02:2025 / CWE-284" $RelPosix $idx $line $lines $i
        }
        if (($ext -in @(".cs", ".java", ".kt")) -and $ReDotnetJavaDeser.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-029" "Unsafe .NET or Java binary deserialization API" "Microsoft .NET / Oracle Java SE / CWE-502" $RelPosix $idx $line $lines $i
        }
        if ($CCppExts.Contains($ext) -and $ReUnsafeCStr.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-030" "Unbounded C string/buffer function susceptible to buffer overflow" "NASA JPL / OpenSSF / Apple / CWE-120" $RelPosix $idx $line $lines $i
        }
        if ($ReShareExportInsecure.IsMatch($line) -or $ReMysqlLocalInfile.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-031" "Insecure file-share/NFS/FTP config, GPO cpassword, or MySQL local_infile enabled" "CIS Benchmarks / OWASP A02:2025 / CWE-306 / CWE-73" $RelPosix $idx $line $lines $i
        }
        if ($ReRemoteDnsPkiInsecure.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-032" "Insecure SSH/WinRM/VNC remote admin, open DNS transfer/recursion/update, or wildcard PKI role" "CIS Benchmarks / OWASP A02:2025 / CWE-284 / CWE-295" $RelPosix $idx $line $lines $i
        }
        if ($ReK8sObsVirtProxyInsecure.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-033" "Insecure K8s anonymous/host-namespace/kubelet setting, unauthenticated libvirt/Grafana, insecure registry, or NGINX dynamic proxy_pass SSRF" "CIS Kubernetes / OWASP A02:2025 / CWE-284 / CWE-918" $RelPosix $idx $line $lines $i
        }
        if ($ReAiAgentUnsafe.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-034" "AI agent sandbox/permission bypass flag or hardcoded MCP config secret" "OWASP ASI02 / ASI05 / CWE-250 / CWE-798" $RelPosix $idx $line $lines $i
        } elseif ($isMcpCfg) {
            $mMcp = $ReMcpSecretKv.Match($line)
            if ($mMcp.Success -and -not $PlaceholderPwRegex.IsMatch($mMcp.Groups["val"].Value)) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-034" "AI agent sandbox/permission bypass flag or hardcoded MCP config secret" "OWASP ASI02 / ASI05 / CWE-250 / CWE-798" $RelPosix $idx $line $lines $i
            }
        }
        if ($iacCfg) {
            if ($ReCloudImdsBucketInsecure.IsMatch($line)) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-035" "Cloud IMDSv1 enabled, public object storage ACL, or wildcard IAM policy" "CIS Cloud Benchmarks / OWASP A02:2025 / CWE-918 / CWE-284" $RelPosix $idx $line $lines $i
            } elseif ($ReIamActionStar.IsMatch($line)) {
                $iamWin = Get-SliceWindow $lines $i 4 4
                if ($ReIamResourceStar.IsMatch($iamWin)) {
                    Add-Finding $Findings $Seen "RED" "SEC-RED-035" "Cloud IMDSv1 enabled, public object storage ACL, or wildcard IAM policy" "CIS Cloud Benchmarks / OWASP A02:2025 / CWE-918 / CWE-284" $RelPosix $idx $line $lines $i
                }
            }
        }
        if (($CodeRegexExts.Contains($ext) -or $iacCfg) -and $ReOauthLegacy.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-036" "Legacy OAuth Implicit/ROPC grant or plain PKCE downgrade" "OAuth 2.1 / IETF RFC 9700 / CWE-287" $RelPosix $idx $line $lines $i
        }
        if ($ReWeakCrypto.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-003" "Deprecated or weak cryptographic primitive" "OWASP A04:2025 / CWE-327 / CWE-328" $RelPosix $idx $line $lines $i
        }
        if ($ReCspUnsafe.IsMatch($line)) {
            $cspWin = Get-SliceWindow $lines $i 5 5
            if ($ReCspHeader.IsMatch($cspWin)) {
                Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-006" "Weak Content-Security-Policy directive ('unsafe-inline' or 'unsafe-eval')" "OWASP ASVS V3 / CWE-79" $RelPosix $idx $line $lines $i
            }
        }

        if ($workflow) {
            $trimmed = $line.TrimStart(" ")
            $indent = $line.Length - $trimmed.Length
            $isComment = $trimmed.StartsWith("#")
            if ($inRunBlock -and $trimmed.Length -gt 0 -and -not $isComment -and $indent -le $runIndent) {
                $inRunBlock = $false
            }
            $mRun = if (-not $isComment) { $ReGhaRun.Match($line) } else { $null }
            $singleLineRun = $false
            if ($null -ne $mRun -and $mRun.Success) {
                $leadLen = $mRun.Groups[1].Value.Length + $mRun.Groups[2].Value.Length
                $rhs = $mRun.Groups[3].Value.Trim()
                if ($rhs.StartsWith("|") -or $rhs.StartsWith(">") -or $rhs -eq "") {
                    $inRunBlock = $true
                    $runIndent = $leadLen
                } else {
                    $singleLineRun = $true
                    $inRunBlock = $false
                }
            }
            if (-not $isComment) {
                if (($inRunBlock -or $singleLineRun) -and $ReCiLogTrace.IsMatch($line)) {
                    Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-014" "CI shell trace or environment dump risks leaking secrets into build logs" "OWASP CICD-SEC-1 / CWE-532" $RelPosix $idx $line $lines $i
                }
                if ($ReGhaPrt.IsMatch($line)) {
                    Add-Finding $Findings $Seen "RED" "SEC-RED-010" "GitHub Actions pull_request_target privileged trigger" "OWASP CICD-SEC-1 / CICD-SEC-4" $RelPosix $idx $line $lines $i
                } elseif (($inRunBlock -or $singleLineRun) -and $ReGhaEventExpr.IsMatch($line)) {
                    Add-Finding $Findings $Seen "RED" "SEC-RED-010" "GitHub Actions script injection via untrusted event context in run block" "OWASP CICD-SEC-4 / CWE-78 / CWE-94" $RelPosix $idx $line $lines $i
                }
                if ($ReGhaUsesUnpinned.IsMatch($line)) {
                    Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-001" "Third-party GitHub Action not pinned to full 40-char commit SHA" "OWASP CICD-SEC-2 / CWE-829" $RelPosix $idx $line $lines $i
                }
                if ($ReGhaPerms.IsMatch($line)) { $hasGhaPerms = $true }
                if ($ReNpmInstall.IsMatch($line)) {
                    Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-005" "Non-deterministic npm install in workflow instead of npm ci --ignore-scripts" "OWASP A03:2025 / SLSA" $RelPosix $idx $line $lines $i
                }
            }
        }

        if ($dockerfile) {
            $mFrom = $ReDockerFrom.Match($line)
            if ($mFrom.Success) {
                $dockerStageCount++
                $dockerStageUser = $null
                $dockerStageUserLine = $idx
                $dockerStageUserRaw = ""
                $img = $mFrom.Groups[1].Value
                $alias = $mFrom.Groups[2].Value
                if ($alias) { [void]$dockerStageAliases.Add($alias.ToLowerInvariant()) }
                $lowImg = $img.ToLowerInvariant()
                if ($ReDockerLatest.IsMatch($line) -or (
                    -not $img.Contains(":") -and -not $img.Contains("@") -and -not $img.StartsWith("$") -and $lowImg -ne "scratch" -and -not $dockerStageAliases.Contains($lowImg)
                )) {
                    Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-002" "Mutable :latest base image tag in Dockerfile" "OWASP Docker Cheat Sheet / CWE-494" $RelPosix $idx $line $lines $i
                }
            }
            $mUser = $ReDockerUser.Match($line)
            if ($mUser.Success) {
                $dockerStageUser = $mUser.Groups[1].Value.ToLowerInvariant()
                $dockerStageUserLine = $idx
                $dockerStageUserRaw = $line
            }
            if ($ReDockerSecretEnv.IsMatch($line)) {
                Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-002" "Secret-like ARG or ENV declared in Dockerfile" "OWASP Docker Cheat Sheet / CWE-798" $RelPosix $idx $line $lines $i
            }
            if ($ReNpmInstall.IsMatch($line)) {
                Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-005" "Non-deterministic npm install in Dockerfile instead of npm ci --ignore-scripts" "OWASP A03:2025 / SLSA" $RelPosix $idx $line $lines $i
            }
            if ($ReDebugTrue.IsMatch($line) -or $line.Contains("DEBUG=true") -or $line.Contains("DEBUG=1")) {
                Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-005" "Debug mode enabled in Dockerfile" "OWASP A02:2025 / CWE-215" $RelPosix $idx $line $lines $i
            }
        }

        if ($prodCfg -and $ReDebugTrue.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-005" "Debug mode enabled in production configuration" "OWASP A02:2025 / CWE-215" $RelPosix $idx $line $lines $i
        }
    }

    if ($isGhWorkflow -and -not $hasGhaPerms) {
        Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-001" "Workflow missing explicit minimal GITHUB_TOKEN permissions block" "OWASP CICD-SEC-6" $RelPosix 1 "No top-level or job permissions: declaration found"
    }
    if ($dockerfile -and $dockerStageCount -gt 0) {
        if ($dockerStageUser -in @("0", "root", "0:0", "root:root")) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-002" "Dockerfile runs container as root user" "OWASP Docker Cheat Sheet / CWE-250" $RelPosix $dockerStageUserLine $dockerStageUserRaw $lines ($dockerStageUserLine - 1)
        } elseif ($null -eq $dockerStageUser) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-002" "Dockerfile missing non-root USER directive" "OWASP Docker Cheat Sheet / CWE-250" $RelPosix 1 "No non-root USER instruction found in final stage"
        }
    }
    if ($isServerActionFile -and -not $ReAuthHint.IsMatch($content)) {
        Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-011" "Next.js Server Action file missing explicit auth or session verification" "Vercel / Next.js Security / CWE-862" $RelPosix 1 "File uses 'use server' without visible auth/session check"
    }
}

if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    [Console]::Error.WriteLine("Error: target directory not found: $Path")
    exit 2
}

$RootInfo = (Get-Item -LiteralPath $Path).FullName
$RootDir = [System.IO.DirectoryInfo]::new($RootInfo)
[string[]]$GitignorePatterns = @()
if ($RespectGitignore) {
    $GitignorePatterns = @(Get-GitignorePatterns $RootDir.FullName)
}
$Findings = [System.Collections.Generic.List[object]]::new()
$Seen = [System.Collections.Generic.HashSet[string]]::new()
$FilesScanned = 0

$Stack = [System.Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()
$Stack.Push($RootDir)

while ($Stack.Count -gt 0) {
    $curr = $Stack.Pop()
    try {
        [System.IO.DirectoryInfo[]]$rawDirs = $curr.GetDirectories()
        $dirs = [System.Collections.Generic.List[System.IO.DirectoryInfo]]::new($rawDirs)
        $dirs.Sort([System.Comparison[System.IO.DirectoryInfo]]{ param($a, $b) [string]::CompareOrdinal($b.Name, $a.Name) })
        foreach ($d in $dirs) {
            if ($ExcludedDirs.Contains($d.Name)) { continue }
            if (($d.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            $relDir = $d.FullName.Substring($RootDir.FullName.Length).TrimStart("\", "/").Replace("\", "/")
            if (Test-SelfSkillPath $relDir) { continue }
            if ($GitignorePatterns.Count -gt 0 -and (Test-MatchesGitignore $relDir $true $GitignorePatterns)) { continue }
            $Stack.Push($d)
        }
        [System.IO.FileInfo[]]$rawFiles = $curr.GetFiles()
        $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new($rawFiles)
        $files.Sort([System.Comparison[System.IO.FileInfo]]{ param($a, $b) [string]::CompareOrdinal($a.Name, $b.Name) })
        foreach ($f in $files) {
            if (($f.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            $relFile = $f.FullName.Substring($RootDir.FullName.Length).TrimStart("\", "/").Replace("\", "/")
            if (Test-SelfSkillPath $relFile) { continue }
            if ($GitignorePatterns.Count -gt 0 -and (Test-MatchesGitignore $relFile $false $GitignorePatterns)) { continue }
            $FilesScanned++
            Invoke-ScanFile $f $relFile $Findings $Seen
        }
    } catch {
        continue
    }
}

$secMdRoot = Join-Path $RootDir.FullName "SECURITY.md"
$secMdGh = Join-Path $RootDir.FullName ".github\SECURITY.md"
if (-not (Test-Path -LiteralPath $secMdRoot -PathType Leaf) -and -not (Test-Path -LiteralPath $secMdGh -PathType Leaf)) {
    Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-007" "Missing root SECURITY.md vulnerability disclosure policy" "NIST SSDF / IETF RFC 9116" "SECURITY.md" 1 "Neither SECURITY.md nor .github/SECURITY.md exists"
}

$Reds = @($Findings | Where-Object { $_.severity -eq "RED" })
$Yellows = @($Findings | Where-Object { $_.severity -eq "YELLOW" })
$Optionals = @($Findings | Where-Object { $_.severity -eq "OPTIONAL" })

if ($Format -eq "json") {
    $payload = [ordered]@{
        target        = $RootDir.FullName
        files_scanned = $FilesScanned
        counts        = [ordered]@{
            red    = $Reds.Count
            yellow = $Yellows.Count
        }
        red           = $Reds
        yellow        = $Yellows
    }
    if ($IncludeOptional) {
        $payload["optional"] = $Optionals
    }
    $payload | ConvertTo-Json -Depth 6
} elseif ($Format -eq "sarif") {
    $levelMap = @{ "RED" = "error"; "YELLOW" = "warning"; "OPTIONAL" = "note" }
    $selected = @($Findings | Where-Object { $IncludeOptional -or $_.severity -ne "OPTIONAL" })
    $rulesById = [ordered]@{}
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $selected) {
        if (-not $rulesById.Contains($f.rule_id)) {
            $rulesById[$f.rule_id] = [ordered]@{
                id               = $f.rule_id
                shortDescription = [ordered]@{ text = $f.title }
                properties       = [ordered]@{ standard = $f.standard; severity = $f.severity }
            }
        }
        $results.Add([ordered]@{
            ruleId    = $f.rule_id
            level     = $levelMap[$f.severity]
            message   = [ordered]@{ text = "$($f.title) ($($f.standard)): $($f.evidence)" }
            locations = @(
                [ordered]@{
                    physicalLocation = [ordered]@{
                        artifactLocation = [ordered]@{ uri = $f.file }
                        region           = [ordered]@{ startLine = $f.line }
                    }
                }
            )
        })
    }
    $sarif = [ordered]@{
        "`$schema" = "https://json.schemastore.org/sarif-2.1.0.json"
        version    = "2.1.0"
        runs       = @(
            [ordered]@{
                tool    = [ordered]@{
                    driver = [ordered]@{
                        name    = "virgil"
                        version = $ScannerVersion
                        rules   = @($rulesById.Values)
                    }
                }
                results = $results.ToArray()
            }
        )
    }
    $sarif | ConvertTo-Json -Depth 10
} else {
    $out = [System.Collections.Generic.List[string]]::new()
    $out.Add("# Pre-Scan Results: $($RootDir.Name)")
    $out.Add("")
    $out.Add("## Summary")
    $out.Add("- **Files inspected:** $FilesScanned")
    $out.Add("- **Counts:** $($Reds.Count) Red, $($Yellows.Count) Yellow")
    $out.Add("")
    $out.Add("## Red Vulnerabilities")
    if ($Reds.Count -eq 0) {
        $out.Add("None found by static pre-scanner.")
    } else {
        for ($i = 0; $i -lt $Reds.Count; $i++) {
            $f = $Reds[$i]
            $out.Add("$($i + 1). **[RED] ``$($f.rule_id)`` — $($f.title)**")
            $out.Add("   - **Standard:** $($f.standard)")
            $out.Add("   - **Location:** ``$($f.file):$($f.line)``")
            $out.Add("   - **Evidence:** ``$($f.evidence)``")
        }
    }
    $out.Add("")
    $out.Add("## Yellow Vulnerabilities")
    if ($Yellows.Count -eq 0) {
        $out.Add("None found by static pre-scanner.")
    } else {
        for ($i = 0; $i -lt $Yellows.Count; $i++) {
            $f = $Yellows[$i]
            $out.Add("$($i + 1). **[YELLOW] ``$($f.rule_id)`` — $($f.title)**")
            $out.Add("   - **Standard:** $($f.standard)")
            $out.Add("   - **Location:** ``$($f.file):$($f.line)``")
            $out.Add("   - **Evidence:** ``$($f.evidence)``")
        }
    }
    if ($IncludeOptional) {
        $out.Add("")
        $out.Add("## Optional Recommendations (Not Vulnerabilities)")
        if ($Optionals.Count -eq 0) {
            $out.Add("None flagged by static pre-scanner.")
        } else {
            for ($i = 0; $i -lt $Optionals.Count; $i++) {
                $f = $Optionals[$i]
                $out.Add("$($i + 1). **[OPTIONAL] ``$($f.rule_id)`` — $($f.title)**")
                $out.Add("   - **Standard:** $($f.standard)")
                $out.Add("   - **Location:** ``$($f.file):$($f.line)``")
                $out.Add("   - **Evidence:** ``$($f.evidence)``")
            }
        }
    }
    $out -join "`n"
}

if ($ExitCode) {
    if ($Reds.Count -gt 0) { exit 2 }
    if ($Yellows.Count -gt 0) { exit 1 }
}
exit 0
