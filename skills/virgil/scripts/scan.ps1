[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Path = ".",

    [ValidateSet("markdown", "json")]
    [string]$Format = "markdown",

    [switch]$ExitCode,
    [switch]$IncludeOptional
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ExcludedDirs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "target", "vendor", ".terraform", ".idea", ".vs", ".pnpm-store"
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
    ".so", ".dylib", ".wasm", ".mp4", ".mp3", ".wav", ".avi", ".mov", ".pyc"
) | ForEach-Object { [void]$BinaryExts.Add($_) }

$DocExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(".md", ".rst", ".txt") | ForEach-Object { [void]$DocExts.Add($_) }

$LockfileNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock",
    "poetry.lock", "composer.lock", "Gemfile.lock", "go.sum"
) | ForEach-Object { [void]$LockfileNames.Add($_) }

$EnvSecretFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(".env", ".env.local", ".env.production", ".env.staging", ".env.development") | ForEach-Object { [void]$EnvSecretFiles.Add($_) }

$SafeEnvFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(".env.example", ".env.sample", ".env.template", ".env.dist") | ForEach-Object { [void]$SafeEnvFiles.Add($_) }

$PrivateKeyNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@("id_rsa", "id_ed25519", "id_dsa") | ForEach-Object { [void]$PrivateKeyNames.Add($_) }

$PrivateKeyExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(".pem", ".key", ".p12", ".pfx") | ForEach-Object { [void]$PrivateKeyExts.Add($_) }

$MaxFileBytes = 2MB

$SecretTokenRegexes = @(
    [regex]::new('AKIA[0-9A-Z]{16}'),
    [regex]::new('ghp_[A-Za-z0-9]{30,}'),
    [regex]::new('github_pat_[A-Za-z0-9_]{20,}'),
    [regex]::new('sk_live_[0-9a-zA-Z]{16,}'),
    [regex]::new('rk_live_[0-9a-zA-Z]{16,}'),
    [regex]::new('sk-ant-[A-Za-z0-9_-]{20,}'),
    [regex]::new('sk-proj-[A-Za-z0-9_-]{20,}'),
    [regex]::new('xox[baprs]-[0-9A-Za-z-]{10,}'),
    [regex]::new('AIza[0-9A-Za-z_-]{35}'),
    [regex]::new('-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----')
)

$DbUriRegex = [regex]::new('(?<prefix>(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss)://[^:\s/''"`]+:)(?<pw>[^@\s$<{/''"`]+)(?<at>@)')
$PlaceholderPwRegex = [regex]::new('^(?:password|pass|changeme|placeholder|example|dummy|your[-_].*|\*{2,}|x{3,})$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

$RePublicSecretEnv = [regex]::new('\b(?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC)_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|DB_PASSWORD|DATABASE_URL|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY)[A-Z0-9_]*\b')
$ReDisabledTls = [regex]::new('(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[''"]?0\b|\bverify\s*=\s*False\b|InsecureSkipVerify\s*:\s*true|sslmode=(?:disable|allow|prefer|require)\b)')
$ReSinks = [regex]::new('(?:dangerouslySetInnerHTML|\bv-html\b|\$queryRawUnsafe\b|\$executeRawUnsafe\b|\beval\s*\(|\bnew\s+Function\s*\(|\bshell\s*=\s*True\b|\bpickle\.loads?\s*\()')
$ReYamlLoad = [regex]::new('\byaml\.load\s*\(')
$ReYamlSafe = [regex]::new('(?:SafeLoader|BaseLoader|CSafeLoader|Loader\s*=)')
$ReJwtDecode = [regex]::new('\bjwt\.decode\s*\(')
$ReJwtBypass = [regex]::new('(?:[''"]?verify_signature[''"]?\s*:\s*False|[''"]?alg[''"]?\s*:\s*[''"]none[''"])')
$ReElectronBad = [regex]::new('(?:nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false|webSecurity\s*:\s*false|\bsandbox\s*:\s*false)')
$ReInfraExposure = [regex]::new('(?:privileged\s*:\s*true|/var/run/docker\.sock|PubliclyAccessible\s*[:=]\s*true)')
$ReCidrAll = [regex]::new('0\.0\.0\.0/0')
$ReCidrCtx = [regex]::new('(?:cidr|ingress|security|postgres|mysql|mongo|redis|5432|3306|27017|6379|ssh|22\b|3389|2375|6443|port)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReGhaPrt = [regex]::new('\bpull_request_target\b')
$ReGhaEventExpr = [regex]::new('\$\{\{\s*github\.event\.(?:issue|pull_request|comment|discussion|review|head_commit|commits)')
$ReGhaRun = [regex]::new('^\s*(?:-\s*)?run\s*:')
$ReGhaUsesUnpinned = [regex]::new('^\s*(?:-\s*)?uses\s*:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@(?:v[0-9][A-Za-z0-9._-]*|main|master|latest)\b')
$ReGhaPerms = [regex]::new('^\s*permissions\s*:')
$ReMongoJs = [regex]::new('(?:javascriptEnabled\s*:\s*true|[''"]\$where[''"]\s*:)')
$ReDockerLatest = [regex]::new('^\s*FROM\s+\S+:latest(?:\s|$)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReDockerUser = [regex]::new('^\s*USER\s+(\S+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReDockerSecretEnv = [regex]::new('^\s*(?:ARG|ENV)\s+[A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReWeakCrypto = [regex]::new('(?:createHash\s*\(\s*[''"](?:md5|sha1)[''"]\s*\)|hashlib\.(?:md5|sha1)\s*\(|AES[-_]?[0-9]*[-_]?ECB|\b(?:RC4|DESede)\b|\bcreateCipher\s*\()')
$ReNpmInstall = [regex]::new('\bnpm\s+install\b')
$ReDebugTrue = [regex]::new('^\s*DEBUG\s*[:=]\s*(?:true|1)\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReCspUnsafe = [regex]::new('(?:''unsafe-inline''|''unsafe-eval'')')
$ReCspHeader = [regex]::new('(?:Content-Security-Policy|script-src|default-src)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReCorsOriginAny = [regex]::new('(?:origin\s*:\s*(?:true|[''"]\*[''"])|allow_origins\s*=\s*\[\s*[''"]\*[''"]\s*\])')
$ReCorsCreds = [regex]::new('(?:credentials\s*:\s*true|allow_credentials\s*=\s*True)')

$ReIosAtsKey = [regex]::new('NSAllowsArbitraryLoads')
$ReIosAtsTrue = [regex]::new('(?:<true\s*/?>|[:=]\s*true\b)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReAndroidCleartext = [regex]::new('(?:cleartextTrafficPermitted|android:usesCleartextTraffic)\s*=\s*[''"]true[''"]')
$ReAndroidExported = [regex]::new('android:exported\s*=\s*[''"]true[''"]')
$ReCfFlexible = [regex]::new('(?:ssl_mode\s*[:=]\s*[''"]?flexible[''"]?|"ssl"\s*:\s*"flexible")', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$RePanLog = [regex]::new('(?:logger\.\w+|console\.log|print)\s*\([^)]*(?:card_?number|cardNumber|\bcvv\b|\bcvc\b)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReExtScript = [regex]::new('<script\b[^>]*\bsrc\s*=\s*[''"]https?://[^''"]+[''"][^>]*>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReMobileHygiene = [regex]::new('(?:android:allowBackup\s*=\s*[''"]true[''"]|\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b)')
$ReRustUnsafe = [regex]::new('\bunsafe\s*\{')
$ReRedos = [regex]::new('(?:new\s+RegExp|re\.compile)\s*\([^)]*\([^)]*[+*][^)]*\)[+*]')

$HtmlExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('.html', '.htm', '.ejs', '.hbs', '.jinja', '.j2', '.twig', '.vue', '.svelte', '.astro') | ForEach-Object { [void]$HtmlExts.Add($_) }

$CodeRegexExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.py', '.rb', '.php', '.java', '.cs', '.go') | ForEach-Object { [void]$CodeRegexExts.Add($_) }

$JsTsExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('.js', '.ts', '.jsx', '.tsx', '.mjs') | ForEach-Object { [void]$JsTsExts.Add($_) }

$FirebaseRulesNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('firestore.rules', 'storage.rules', 'database.rules.json') | ForEach-Object { [void]$FirebaseRulesNames.Add($_) }

$ReSecurityDefiner = [regex]::new('\bSECURITY\s+DEFINER\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReSetSearchPath = [regex]::new('\bSET\s+search_path\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReFbAnyAllow = [regex]::new('\ballow\s+[^;]*:\s*if\s+true\b')
$ReFbAuthOnly = [regex]::new('request\.auth\s*!=\s*null')
$ReFbOwnership = [regex]::new('(?:resource\.data|request\.auth\.uid\s*==|uid\s*==|isOwner|hasRole|get\()')
$ReTrojanBidi = [regex]::new('[\u202a-\u202e\u2066-\u2069]')
$ReExtractAll = [regex]::new('\.extractall\s*\(')
$ReUnsafeXmlPy = [regex]::new('\b(?:xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax)\.(?:parse|fromstring|parseString)\s*\(')
$ReUseServer = [regex]::new('^\s*[''"]use server[''"]\s*;?\s*$')
$ReAuthHint = [regex]::new('\b(?:auth|session|getUser|verifySession|currentUser|cookies|requireAuth|getServerSession)\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$SchemaCodeExts = [System.Collections.Generic.HashSet[string]]::new($CodeRegexExts, [System.StringComparer]::OrdinalIgnoreCase)
@('.sql', '.prisma') | ForEach-Object { [void]$SchemaCodeExts.Add($_) }
$ReHostResetCtx = [regex]::new('(?:reset|forgot|magic|verify|invite)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReHostHeader = [regex]::new('(?:req\.headers?(?:\.\s*|\[\s*[''"]?|\(\s*[''"]?)(?:x-forwarded-host|host)|request\.headers?(?:\.get\(\s*[''"]?|\[\s*[''"]?|\.)(?:x-forwarded-host|host)|req\.get\(\s*[''"]?(?:x-forwarded-host|host)|request\.host\b|getHeader\(\s*[''"]?(?:x-forwarded-host|host))', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReKbaQuestion = [regex]::new('\b(?:security_?[q]uestion|security[Q]uestion|mother_?[m]aiden|first_?[p]et)\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$PropYamlExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('.properties', '.yml', '.yaml') | ForEach-Object { [void]$PropYamlExts.Add($_) }
$PipCfgExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('.txt', '.cfg', '.conf', '.ini', '.yml', '.yaml', '.sh', '.ps1') | ForEach-Object { [void]$PipCfgExts.Add($_) }
$ReTrustProxyTrue = [regex]::new('(?:app\.set\s*\(\s*[''"]trust\s+proxy[''"]\s*,\s*true\s*\)|\btrustProxy\s*:\s*true\b)')
$ReActuatorExposed = [regex]::new('management\.endpoints\.web\.exposure\.include\s*[:=]\s*[''"]?(?:\*|[^#\r\n]*\b(?:heapdump|env|mappings)\b)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$RePipExtraIndex = [regex]::new('--extra-[i]ndex-url(?:\s+|=)\S+', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$RePostMessageWildcard = [regex]::new('\.postMessage\s*\([^,\r\n]+,\s*[''"]\*[''"]\s*\)')
$PublicDumpExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('.bak', '.sql', '.dump', '.old', '.orig') | ForEach-Object { [void]$PublicDumpExts.Add($_) }
$ReDefaultCred = [regex]::new('\b(?:admin_?password|root_?password|default_?password|db_?password|postgres_?password|mysql_?root_?password|redis_?password|password|passwd)\b\s*[:=]\s*[''"]?(?:admin|password|123456|changeme|default|toor|root)[''"]?(?:\s|$|,|;|#)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReCiLogTrace = [regex]::new('(?:\bset\s+(?:-[a-zA-Z]*x|-o\s+xtrace)\b|(?:^|\s|;|&|\|)(?:printenv|env)\s*(?:$|[;#|&>]))')
$ReDockerPortDb = [regex]::new('^\s*-\s*[''"]?(?:0\.0\.0\.0:)?(?:3306|5432|1433|1521|6379|27017|9200|11211):\d+[''"]?(?:\s|$|#)')
$ReDbOsExec = [regex]::new('(?:\bxp_cmdshell\b|\bCOPY\b[^;\r\n]+\b(?:FROM|TO)\s+PROGRAM\b)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReWeakJwtSecret = [regex]::new('\bjwt_?secret\b\s*[:=]\s*[''"]?(?:secret|changeme|dev[-_]?secret|test[-_]?secret|123456|default|mysecret)[''"]?(?:\s|$|,|;|#)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReDirListing = [regex]::new('(?:\bautoindex\s+on\b|\bOptions\s+[^\r\n]*\+Indexes\b|\bserveIndex\s*\()', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReParentCookieDomain = [regex]::new('(?:Domain=\.[A-Za-z0-9.-]+|\bdomain\s*:\s*[''"]\.[A-Za-z0-9.-]+[''"])')
$ReWebViewFileAccess = [regex]::new('(?:\bsetAllowFileAccess\s*\(\s*true\s*\)|\bsetAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)|\bsetAllowFileAccessFromFileURLs\s*\(\s*true\s*\)|\baddJavascriptInterface\s*\()')
$ReBrokerAnonOrCookie = [regex]::new('(?:\bALLOW_ANONYMOUS_LOGIN\s*[:=]\s*[''"]?yes[''"]?|\ballow_anonymous\s+true\b|\bKAFKA_CFG_ALLOW_PLAINTEXT_LISTENER\s*[:=]\s*[''"]?yes[''"]?|\bRABBITMQ_ERLANG_COOKIE\s*[:=]\s*[''"]?[A-Za-z0-9_-]{4,})', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$RePendingIntentMutable = [regex]::new('\bPendingIntent\.FLAG_MUTABLE\b')
$ReCmsFileEdit = [regex]::new('define\s*\(\s*[''"]DISALLOW_FILE_(?:EDIT|MODS)[''"]\s*,\s*false\s*\)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReDotnetJavaDeser = [regex]::new('\b(?:BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer|SoapFormatter|XMLDecoder)\b|\bObjectInputStream\b[^;\r\n]*\.read(?:Object|Unshared)\s*\(')
$ReUnsafeCStr = [regex]::new('\b(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\(')
$CCppExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('.c', '.cc', '.cpp', '.cxx', '.h', '.hpp') | ForEach-Object { [void]$CCppExts.Add($_) }
$ReShareExportInsecure = [regex]::new('(?:\bno_root_squash\b|\bserver\s+signing\s*=\s*(?:disabled|no|off)\b|\b(?:min\s+protocol|server\s+min\s+protocol|client\s+min\s+protocol)\s*=\s*(?:NT1|LANMAN[12]|CORE)\b|\bguest\s+ok\s*=\s*yes\b|\banonymous_enable\s*=\s*YES\b|\bcpassword\s*=\s*[''"][A-Za-z0-9+/=]{8,}[''"])', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReMysqlLocalInfile = [regex]::new('(?:\blocal[-_]infile\s*=\s*(?:1|ON|true)\b|\ballowLoadLocalInfile\s*[:=]\s*true\b|\blocalInfile\s*:\s*true\b)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ReRemoteDnsPkiInsecure = [regex]::new('(?:\bPermitRootLogin\s+yes\b|\bStrictHostKeyChecking(?:=|\s+)no\b|\bUserKnownHostsFile(?:=|\s+)/dev/null\b|\ballow-transfer\s*\{\s*any\s*;\s*\}|\ballow-recursion\s*\{\s*any\s*;\s*\}|\ballow-update\s*\{\s*any\s*;\s*\}|\ballow_any_name\s*[:=]\s*true\b|\bAllowUnencrypted\s*[:=]\s*[''"]?true\b|\bSecurityTypes\s*[:=]\s*[''"]?None\b|\bsnmp-server\s+community\s+(?:public|private)\b|\bno\s+service\s+password-encryption\b)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

function Mask-Token {
    param([string]$Token)
    if ($Token.Length -le 8) { return "****" }
    return "{0}****{1}" -f $Token.Substring(0, 4), $Token.Substring($Token.Length - 4)
}

function Redact-Line {
    param([string]$Text)
    $cleaned = ($Text -replace "`r", "" -replace "`n", " ").Trim()
    foreach ($rx in $SecretTokenRegexes) {
        $cleaned = $rx.Replace($cleaned, { param($m) Mask-Token $m.Value })
    }
    $cleaned = $DbUriRegex.Replace($cleaned, {
        param($m)
        "{0}****{1}" -f $m.Groups["prefix"].Value, $m.Groups["at"].Value
    })
    if ($cleaned.Length -gt 140) {
        $cleaned = $cleaned.Substring(0, 137) + "..."
    }
    return $cleaned
}

function Test-SelfSkillPath {
    param([string]$RelPosix)
    $low = $RelPosix.ToLowerInvariant()
    foreach ($seg in $SelfSkillSegments) {
        if ($low.Contains($seg)) { return $true }
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

function Test-SecretPatterns {
    param([string]$Line)
    foreach ($rx in $SecretTokenRegexes) {
        if ($rx.IsMatch($Line)) { return $true }
    }
    foreach ($m in $DbUriRegex.Matches($Line)) {
        if (-not $PlaceholderPwRegex.IsMatch($m.Groups["pw"].Value)) {
            return $true
        }
    }
    return $false
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
        [string]$RawLine
    )
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

    if ($EnvSecretFiles.Contains($lowName) -or $PrivateKeyExts.Contains($ext) -or $PrivateKeyNames.Contains($lowName) -or ($lowName -match "service[-_]?account.*\.json$")) {
        if (-not $SafeEnvFiles.Contains($lowName)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-003" "Sensitive environment or private key file committed" "OWASP A04:2025 / CWE-312 / CWE-798" $RelPosix 1 "Sensitive file present: $RelPosix"
        }
    }

    if ($BinaryExts.Contains($ext) -or $LockfileNames.Contains($lowName) -or $lowName.EndsWith(".map")) { return }
    if ($FileInfo.Length -gt $MaxFileBytes) { return }

    try {
        $content = [System.IO.File]::ReadAllText($FileInfo.FullName)
    } catch {
        return
    }

    $lines = $content -split "`r?`n"
    $bundleOnly = Test-BuiltBundlePath $RelPosix
    $isPipReq = ($ext -eq ".txt") -and ($lowName.StartsWith("requirements") -or $lowName.StartsWith("constraints"))
    $docOnly = $DocExts.Contains($ext) -and -not $isPipReq
    $lowRel = $RelPosix.ToLowerInvariant()
    $workflow = $lowRel.StartsWith(".github/workflows/") -and ($lowRel.EndsWith(".yml") -or $lowRel.EndsWith(".yaml"))
    $dockerfile = ($lowName -eq "dockerfile") -or $lowName.StartsWith("dockerfile.") -or $lowName.EndsWith(".dockerfile")
    $iacCfg = $lowRel -match "\.(?:tf|tfvars|ya?ml|json|toml)$"
    $prodCfg = $lowName.StartsWith(".env.production") -or ($lowName.Contains("prod") -and ($lowName -match "\.(?:ya?ml|json|env|toml)$"))

    if ($bundleOnly -or $docOnly) {
        $title = if ($bundleOnly) {
            "Hardcoded secret or private key in built frontend bundle"
        } else {
            "Hardcoded provider secret, private key, or inline DB credential"
        }
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if (Test-SecretPatterns $lines[$i]) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-001" $title "OWASP A04:2025 / CWE-798" $RelPosix ($i + 1) $lines[$i]
            }
        }
        return
    }

    $hasGhaPerms = $false
    $hasDockerUser = $false
    $inRunBlock = $false
    $runIndent = 0
    $isServerActionFile = $false
    if ($JsTsExts.Contains($ext)) {
        $topLimit = [Math]::Min(5, $lines.Count) - 1
        for ($k = 0; $k -le $topLimit; $k++) {
            if ($ReUseServer.IsMatch($lines[$k])) { $isServerActionFile = $true; break }
        }
    }
    $fileUsesDefusedXml = $content.Contains("defusedxml")

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $idx = $i + 1
        $line = $lines[$i]

        if (Test-SecretPatterns $line) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-001" "Hardcoded provider secret, private key, or inline DB credential" "OWASP A04:2025 / CWE-798" $RelPosix $idx $line
        }
        if ($RePublicSecretEnv.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-002" "Privileged credential exposed via public frontend env prefix" "OWASP A04:2025 / CWE-798 / CWE-312" $RelPosix $idx $line
        }
        if ($ReDisabledTls.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-004" "TLS certificate or hostname verification disabled" "OWASP A04:2025 / CWE-295" $RelPosix $idx $line
        }

        $startIdx = [Math]::Max(0, $i - 5)
        $endIdx = [Math]::Min($lines.Count - 1, $i + 5)
        $window = ($lines[$i..$endIdx]) -join "`n"
        $corsWindow = ($lines[$startIdx..$endIdx]) -join "`n"

        if ($ReCorsOriginAny.IsMatch($line) -and $ReCorsCreds.IsMatch($corsWindow)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-005" "Permissive CORS wildcard or reflected origin paired with credentials" "OWASP A02:2025 / CWE-942" $RelPosix $idx $line
        }
        if ($ReSinks.IsMatch($line) -or ($ReYamlLoad.IsMatch($line) -and -not $ReYamlSafe.IsMatch($line))) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-006" "High-risk XSS, injection, shell execution, or unsafe deserialization sink" "OWASP A05:2025 / CWE-79 / CWE-89 / CWE-78 / CWE-502" $RelPosix $idx $line
        }
        if ($ReJwtBypass.IsMatch($line) -or ($ReJwtDecode.IsMatch($line) -and $line.ToLowerInvariant() -notmatch "verify|algorithms")) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-007" "Unverified JWT decode or signature bypass" "IETF RFC 8725 / CWE-347" $RelPosix $idx $line
        }
        if ($ReElectronBad.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-008" "Electron renderer sandbox or context isolation disabled" "Electron Security Checklist / CWE-250" $RelPosix $idx $line
        }
        if ($ReInfraExposure.IsMatch($line) -or ($iacCfg -and $ReCidrAll.IsMatch($line) -and $ReCidrCtx.IsMatch($window))) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-009" "Privileged container, Docker socket mount, or public DB/admin ingress" "OWASP A02:2025 / CIS Benchmarks / CWE-250 / CWE-284" $RelPosix $idx $line
        }
        if ($ReMongoJs.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-011" "MongoDB server-side JavaScript enabled or `$where operator used" "OWASP A05:2025 / CWE-943" $RelPosix $idx $line
        }

        $atsEnd = [Math]::Min($lines.Count - 1, $i + 1)
        $atsWindow = ($lines[$i..$atsEnd]) -join "`n"
        if ($ReIosAtsKey.IsMatch($line) -and $ReIosAtsTrue.IsMatch($atsWindow)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-012" "iOS App Transport Security disabled (NSAllowsArbitraryLoads)" "Apple Platform Security / OWASP MASVS-NETWORK" $RelPosix $idx $line
        }
        if ($ReAndroidCleartext.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-012" "Android cleartext network traffic permitted" "OWASP MASVS-NETWORK / CWE-319" $RelPosix $idx $line
        }
        if ($lowName -eq "androidmanifest.xml" -and $ReAndroidExported.IsMatch($line)) {
            $mStart = [Math]::Max(0, $i - 2)
            $mEnd = [Math]::Min($lines.Count - 1, $i + 5)
            $manifestWin = ($lines[$mStart..$mEnd]) -join "`n"
            if (-not $manifestWin.Contains("android:permission") -and -not $manifestWin.Contains("android.intent.action.MAIN")) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-012" "Android component exported without permission guard" "OWASP MASVS-PLATFORM / CWE-926" $RelPosix $idx $line
            }
        }
        if ($ReCfFlexible.IsMatch($line) -or $RePanLog.IsMatch($line)) {
            $cfTitle = if ($ReCfFlexible.IsMatch($line)) {
                "Cloudflare Flexible TLS leaves origin hop unencrypted"
            } else {
                "Raw payment card PAN or CVV logged"
            }
            Add-Finding $Findings $Seen "RED" "SEC-RED-013" $cfTitle "PCI-DSS v4.0 / CWE-319 / CWE-532" $RelPosix $idx $line
        }
        if ($HtmlExts.Contains($ext) -and $ReExtScript.IsMatch($line) -and -not $line.ToLowerInvariant().Contains("integrity=")) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-008" "External script tag missing Subresource Integrity (integrity=)" "PCI-DSS v4.0 / OWASP ASVS V3 / CWE-353" $RelPosix $idx $line
        }
        if ($ReMobileHygiene.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-009" "Insecure mobile backup or deprecated Keychain accessibility" "Apple Platform Security / OWASP MASVS-STORAGE" $RelPosix $idx $line
        }
        if ($ext -eq ".rs" -and $ReRustUnsafe.IsMatch($line)) {
            $prevLine = if ($i -ge 1) { $lines[$i - 1] } else { "" }
            if (-not $line.Contains("SAFETY:") -and -not $prevLine.Contains("SAFETY:")) {
                Add-Finding $Findings $Seen "OPTIONAL" "SEC-OPT-001" "Rust unsafe block missing // SAFETY: invariant comment" "Google Safe Coding / CWE-119" $RelPosix $idx $line
            }
        }
        if ($CodeRegexExts.Contains($ext) -and $ReRedos.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-010" "Potential catastrophic ReDoS nested quantifier regex" "OWASP DoS / CWE-1333" $RelPosix $idx $line
        }
        if ($ext -eq ".sql" -and $ReSecurityDefiner.IsMatch($line)) {
            $sqlStart = [Math]::Max(0, $i - 2)
            $sqlEnd = [Math]::Min($lines.Count - 1, $i + 7)
            $sqlWin = ($lines[$sqlStart..$sqlEnd]) -join "`n"
            if (-not $ReSetSearchPath.IsMatch($sqlWin)) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-014" "PostgreSQL SECURITY DEFINER function missing SET search_path" "Supabase Security / CWE-426" $RelPosix $idx $line
            }
        }
        if ($FirebaseRulesNames.Contains($lowName)) {
            $fbStart = [Math]::Max(0, $i - 1)
            $fbEnd = [Math]::Min($lines.Count - 1, $i + 1)
            $fbWin = ($lines[$fbStart..$fbEnd]) -join "`n"
            if ($ReFbAnyAllow.IsMatch($line) -or ($ReFbAuthOnly.IsMatch($line) -and -not $ReFbOwnership.IsMatch($fbWin))) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-014" "Overly permissive Firebase security rule missing ownership check" "Firebase Security Rules / CWE-285" $RelPosix $idx $line
            }
        }
        if ($ReTrojanBidi.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-015" "Trojan Source bidirectional Unicode control character in file" "CVE-2021-42574 / CWE-1007" $RelPosix $idx $line
        }
        if ($ReExtractAll.IsMatch($line) -and -not $line.Contains("filter=")) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-015" "Potential Zip Slip via unguarded archive extractall()" "OWASP File Handling / CWE-22" $RelPosix $idx $line
        }
        if ($ext -eq ".py" -and $ReUnsafeXmlPy.IsMatch($line) -and -not $fileUsesDefusedXml) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-015" "Unsafe Python XML parser susceptible to XXE / entity expansion" "OWASP XXE / CWE-611" $RelPosix $idx $line
        }
        if ($CodeRegexExts.Contains($ext) -and $ReHostResetCtx.IsMatch($line) -and $ReHostHeader.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-016" "Password-reset, verification, or invite URL built from untrusted Host / X-Forwarded-Host header" "OWASP Forgot Password / CWE-640" $RelPosix $idx $line
        }
        if ($SchemaCodeExts.Contains($ext) -and $ReKbaQuestion.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-012" "Deprecated static knowledge-based authentication (KBA / security question) recovery pattern" "NIST SP 800-63B-4 / OWASP Forgot Password" $RelPosix $idx $line
        }
        if ($JsTsExts.Contains($ext) -and $ReTrustProxyTrue.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-017" "Overly permissive trust proxy setting allows X-Forwarded-For IP spoofing" "OWASP API4 / CWE-290" $RelPosix $idx $line
        }
        if ($PropYamlExts.Contains($ext) -and $ReActuatorExposed.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-018" "Sensitive Spring Boot Actuator endpoints exposed over web" "OWASP A02:2025 / CWE-200" $RelPosix $idx $line
        }
        if (($PipCfgExts.Contains($ext) -or $lowName.StartsWith("dockerfile")) -and $RePipExtraIndex.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-019" "pip --extra-index-url enables public PyPI dependency confusion against private packages" "OWASP A03:2025 / CWE-427" $RelPosix $idx $line
        }
        if ($JsTsExts.Contains($ext) -and $RePostMessageWildcard.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-013" "window.postMessage called with wildcard '*' targetOrigin" "OWASP Client-Side / CWE-346" $RelPosix $idx $line
        }
        if (-not $SafeEnvFiles.Contains($lowName) -and $ReDefaultCred.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-021" "Hardcoded default or weak admin/service credential" "OWASP A07:2025 / CWE-798" $RelPosix $idx $line
        }
        if (($ext -eq ".yml" -or $ext -eq ".yaml") -and $ReDockerPortDb.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-023" "Container publishes DB/cache port on all interfaces (bypasses host firewall)" "OWASP A02:2025 / CWE-284" $RelPosix $idx $line
        }
        if ($SchemaCodeExts.Contains($ext) -and $ReDbOsExec.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-024" "Dangerous database-to-host OS execution primitive (xp_cmdshell / COPY PROGRAM)" "OWASP A05:2025 / CWE-250" $RelPosix $idx $line
        }
        if (-not $SafeEnvFiles.Contains($lowName) -and $ReWeakJwtSecret.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-026" "Weak or hardcoded JWT signing secret" "OWASP A04:2025 / CWE-798" $RelPosix $idx $line
        }
        if ($ReDirListing.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-015" "Directory listing enabled on web server or static middleware" "OWASP A02:2025 / CWE-548" $RelPosix $idx $line
        }
        if ($CodeRegexExts.Contains($ext) -and $ReParentCookieDomain.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-016" "Cookie scoped to parent domain (exposes cookie to sibling subdomains)" "OWASP Session Mgmt / CWE-1275" $RelPosix $idx $line
        }
        if (($ext -eq ".java" -or $ext -eq ".kt") -and $ReWebViewFileAccess.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-027" "Insecure Android WebView file access or exposed JS bridge" "OWASP MASVS-PLATFORM / CWE-749" $RelPosix $idx $line
        }
        if ((-not $SafeEnvFiles.Contains($lowName)) -and (($ext -in @(".yml", ".yaml", ".conf", ".env", ".properties")) -or $lowName.StartsWith(".env") -or $dockerfile) -and $ReBrokerAnonOrCookie.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-028" "Unauthenticated/plaintext message broker config or hardcoded cluster cookie" "OWASP A02:2025 / CWE-306" $RelPosix $idx $line
        }
        if (($ext -eq ".java" -or $ext -eq ".kt") -and $RePendingIntentMutable.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-017" "Mutable Android PendingIntent allows parameter tampering by third-party apps" "OWASP MASVS-PLATFORM / CWE-927" $RelPosix $idx $line
        }
        if ($ext -eq ".php" -and $ReCmsFileEdit.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-018" "CMS in-dashboard file/plugin editor explicitly enabled" "OWASP A02:2025 / CWE-284" $RelPosix $idx $line
        }
        if (($ext -in @(".cs", ".java", ".kt")) -and $ReDotnetJavaDeser.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-029" "Unsafe .NET or Java binary deserialization API" "Microsoft .NET / Oracle Java SE / CWE-502" $RelPosix $idx $line
        }
        if ($CCppExts.Contains($ext) -and $ReUnsafeCStr.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-030" "Unbounded C string/buffer function susceptible to buffer overflow" "NASA JPL / OpenSSF / Apple / CWE-120" $RelPosix $idx $line
        }
        if ($ReShareExportInsecure.IsMatch($line) -or $ReMysqlLocalInfile.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-031" "Insecure file-share/NFS/FTP config, GPO cpassword, or MySQL local_infile enabled" "CIS Benchmarks / OWASP A02:2025 / CWE-306 / CWE-73" $RelPosix $idx $line
        }
        if ($ReRemoteDnsPkiInsecure.IsMatch($line)) {
            Add-Finding $Findings $Seen "RED" "SEC-RED-032" "Insecure SSH/WinRM/VNC remote admin, open DNS transfer/recursion/update, or wildcard PKI role" "CIS Benchmarks / OWASP A02:2025 / CWE-284 / CWE-295" $RelPosix $idx $line
        }
        if ($ReWeakCrypto.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-003" "Deprecated or weak cryptographic primitive" "OWASP A04:2025 / CWE-327 / CWE-328" $RelPosix $idx $line
        }
        if ($ReCspUnsafe.IsMatch($line) -and $ReCspHeader.IsMatch($window)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-006" "Weak Content-Security-Policy directive ('unsafe-inline' or 'unsafe-eval')" "OWASP ASVS V3 / CWE-79" $RelPosix $idx $line
        }

        if ($workflow) {
            $trimmed = $line.TrimStart(" ")
            $indent = $line.Length - $trimmed.Length
            if ($inRunBlock -and $trimmed.Length -gt 0 -and -not $trimmed.StartsWith("#") -and $indent -le $runIndent) {
                $inRunBlock = $false
            }
            if ($ReGhaRun.IsMatch($line)) {
                $inRunBlock = $true
                $runIndent = $indent
            }
            if ($inRunBlock -and $ReCiLogTrace.IsMatch($line)) {
                Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-014" "CI shell trace or environment dump risks leaking secrets into build logs" "OWASP CICD-SEC-1 / CWE-532" $RelPosix $idx $line
            }
            if ($ReGhaPrt.IsMatch($line)) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-010" "GitHub Actions pull_request_target privileged trigger" "OWASP CICD-SEC-1 / CICD-SEC-4" $RelPosix $idx $line
            } elseif ($inRunBlock -and $ReGhaEventExpr.IsMatch($line)) {
                Add-Finding $Findings $Seen "RED" "SEC-RED-010" "GitHub Actions script injection via untrusted event context in run block" "OWASP CICD-SEC-4 / CWE-78 / CWE-94" $RelPosix $idx $line
            }
            if ($ReGhaUsesUnpinned.IsMatch($line)) {
                Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-001" "Third-party GitHub Action not pinned to full 40-char commit SHA" "OWASP CICD-SEC-2 / CWE-829" $RelPosix $idx $line
            }
            if ($ReGhaPerms.IsMatch($line)) { $hasGhaPerms = $true }
            if ($ReNpmInstall.IsMatch($line)) {
                Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-005" "Non-deterministic npm install in workflow instead of npm ci --ignore-scripts" "OWASP A03:2025 / SLSA" $RelPosix $idx $line
            }
        }

        if ($dockerfile) {
            if ($ReDockerLatest.IsMatch($line)) {
                Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-002" "Mutable :latest base image tag in Dockerfile" "OWASP Docker Cheat Sheet / CWE-494" $RelPosix $idx $line
            }
            $mUser = $ReDockerUser.Match($line)
            if ($mUser.Success) {
                $uVal = $mUser.Groups[1].Value.ToLowerInvariant()
                if ($uVal -in @("0", "root", "0:0", "root:root")) {
                    Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-002" "Dockerfile runs container as root user" "OWASP Docker Cheat Sheet / CWE-250" $RelPosix $idx $line
                } else {
                    $hasDockerUser = $true
                }
            }
            if ($ReDockerSecretEnv.IsMatch($line)) {
                Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-002" "Secret-like ARG or ENV declared in Dockerfile" "OWASP Docker Cheat Sheet / CWE-798" $RelPosix $idx $line
            }
            if ($ReNpmInstall.IsMatch($line)) {
                Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-005" "Non-deterministic npm install in Dockerfile instead of npm ci --ignore-scripts" "OWASP A03:2025 / SLSA" $RelPosix $idx $line
            }
            if ($ReDebugTrue.IsMatch($line) -or $line.Contains("DEBUG=true") -or $line.Contains("DEBUG=1")) {
                Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-005" "Debug mode enabled in Dockerfile" "OWASP A02:2025 / CWE-215" $RelPosix $idx $line
            }
        }

        if ($prodCfg -and $ReDebugTrue.IsMatch($line)) {
            Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-005" "Debug mode enabled in production configuration" "OWASP A02:2025 / CWE-215" $RelPosix $idx $line
        }
    }

    if ($workflow -and -not $hasGhaPerms) {
        Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-001" "Workflow missing explicit minimal GITHUB_TOKEN permissions block" "OWASP CICD-SEC-6" $RelPosix 1 "No top-level or job permissions: declaration found"
    }
    if ($dockerfile -and -not $hasDockerUser) {
        Add-Finding $Findings $Seen "YELLOW" "SEC-YEL-002" "Dockerfile missing non-root USER directive" "OWASP Docker Cheat Sheet / CWE-250" $RelPosix 1 "No non-root USER instruction found"
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
$Findings = [System.Collections.Generic.List[object]]::new()
$Seen = [System.Collections.Generic.HashSet[string]]::new()
$FilesScanned = 0

$Stack = [System.Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()
$Stack.Push($RootDir)

while ($Stack.Count -gt 0) {
    $curr = $Stack.Pop()
    try {
        $dirs = $curr.GetDirectories() | Sort-Object Name -Descending
        foreach ($d in $dirs) {
            if ($ExcludedDirs.Contains($d.Name)) { continue }
            $relDir = $d.FullName.Substring($RootDir.FullName.Length).TrimStart("\", "/").Replace("\", "/")
            if (Test-SelfSkillPath $relDir) { continue }
            $Stack.Push($d)
        }
        $files = $curr.GetFiles() | Sort-Object Name
        foreach ($f in $files) {
            $relFile = $f.FullName.Substring($RootDir.FullName.Length).TrimStart("\", "/").Replace("\", "/")
            if (Test-SelfSkillPath $relFile) { continue }
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
