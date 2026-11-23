# Web Applications, Frontend, Browser & Client Runtime Security

## 1. Architecture & Exception Handling (OWASP Top 10:2025, ASVS v5.0.0)
- `[YELLOW]` **No ASVS Baseline / Fail-Open Exceptions (`A10:2025`):** Select an OWASP ASVS v5.0.0 assurance level (Level 2 default for apps handling sensitive data) and map V1–V17 controls upfront. Ensure global error handlers catch exceptions fail-closed and never return stack traces, SQL strings, or internal paths in production HTTP `400`/`500` responses.
- `[RED]` **Fail-Open Exception Bypass (`A10:2025`):** Never let `catch` blocks silently skip authentication, signature validation, or authorization checks.

## 2. Public Frontend Secrets, Bundles & Source Maps
- `[RED]` **Privileged Keys in Public Env Vars or Built Bundles (`CWE-798`, `CWE-312`):** Build tools (`Next.js`, `Vite`, `Expo`, `CRA`, `Nuxt`) inline `NEXT_PUBLIC_*`, `VITE_*`, `EXPO_PUBLIC_*`, `REACT_APP_*`, and `NUXT_PUBLIC_*` into public client JavaScript. Never place `SERVICE_ROLE`, Stripe `sk_*`, OpenAI/Anthropic/Gemini API keys, DB URLs, or signing secrets in frontend code or public env prefixes. Proxy privileged third-party calls through backend endpoints.
- `[RED]` **Client Public Keys Without Backend RLS/Rules:** Intentional public client identifiers (Supabase `anon`, Firebase web config, Stripe `pk_*`) must be backed by strict server-side authorization or database Row-Level Security / Firebase Security Rules; verify policies exist in the repo or flag as `[RED]`/`Unverified`.
- `[RED]` **Web-Root `.env` or `.git` Exposure:** Never copy `.env*` or `.git/` into `public/`, `static/`, `dist/`, or Docker web roots served directly by Nginx/Apache/CDN.
- `[YELLOW]` **Public Production Source Maps (`*.js.map`, `*.css.map`):** Disable public source map emission (`productionBrowserSourceMaps: false`, Vite `build.sourcemap: false` or `'hidden'`) in production or upload `.map` files solely to private error-tracking storage.

## 3. Injection & Client-Side Execution
- `[RED]` **XSS (`CWE-79`, `A05:2025`):** Ban `eval()`, `new Function()`, `document.write()`, string `setTimeout`/`setInterval`, and unsanitized `dangerouslySetInnerHTML`, `v-html`, or `[innerHTML]`. Use framework auto-escaping and safe DOM APIs (`textContent`). Validate dynamic `href`/`src` attributes to allow `https:`/`http:`/`mailto:` only (block `javascript:`/`data:`).
- `[RED]` **Rich HTML & DOM Clobbering (`CWE-79`, `CWE-451`):** When rich HTML rendering is required, sanitize immediately before insertion with **DOMPurify** using strict tag/attribute allowlists (forbid or prefix `id`/`name`), enforce **Trusted Types** via CSP (`require-trusted-types-for 'script'; trusted-types app-policy dompurify;`), freeze config objects (`Object.freeze`), and verify globals are not DOM nodes (`!('nodeType' in obj)`).
- `[RED]` **SSTI (`CWE-1336` / `CWE-94`):** Never concatenate user input into server template strings (`Template(user_str).render()`). Render static template files with typed context data and enable sandboxed template modes.
- `[RED]` **Prototype Pollution (`CWE-1321`):** Use `Map`/`Set` or `Object.create(null)` for dynamic lookup tables; reject `__proto__`, `constructor`, and `prototype` keys in deep-merge/clone/query parsers.

## 4. Browser Security Boundaries & HTTP Headers
- `[RED]` **Permissive CORS (`CWE-942`):** Disable CORS by default on same-origin apps. When cross-origin API calls are required, match `Origin` against an exact server-side allowlist (never reflect arbitrary `Origin`, never allow `Origin: null`, never combine `*` with `Access-Control-Allow-Credentials: true`), and return `Vary: Origin`.
- `[YELLOW]` **Missing Security Headers (`A02:2025`):**
  - `Content-Security-Policy: default-src 'self'; script-src 'nonce-<RANDOM>' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none';` (fresh >=128-bit CSPRNG nonce per request; avoid `'unsafe-inline'`/`'unsafe-eval'`)
  - `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` (RFC 6797, HTTPS only)
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY` (legacy fallback paired with `frame-ancestors 'none'`)
  - `Cross-Origin-Opener-Policy: same-origin`
  - `Cross-Origin-Resource-Policy: same-origin` (and `Cross-Origin-Embedder-Policy: require-corp` when full isolation is required)
  - `Referrer-Policy: strict-origin-when-cross-origin` (`no-referrer` on auth/reset routes)
  - `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`

## 5. Session Management, Cookies & CSRF
- `[RED]` **Session Hijacking / Fixation (`CWE-384`, `A07:2025`):** Generate opaque session IDs with >=128 bits CSPRNG entropy; never place session tokens in URLs or `localStorage`. Rotate/regenerate session IDs immediately upon login, MFA step-up, and privilege escalation, and destroy server-side state on logout.
- `[RED]` **Missing CSRF Protection (`CWE-352`):** Require Synchronizer CSRF tokens on state-changing cookie-authenticated endpoints (plus Fetch Metadata `Sec-Fetch-Site` blocking unexpected `cross-site` mutations with `403`). Never perform state mutations on `GET` requests.
- `[YELLOW]` **Weak Cookie Attributes (RFC 6265bis):** Prefer the `__Host-` cookie prefix: `Set-Cookie: __Host-session_id=<TOKEN>; Secure; HttpOnly; SameSite=Lax; Path=/` (must omit `Domain`; use `SameSite=Strict` for admin panels).

## 6. SSRF, Redirects, Path Traversal & File Uploads
- `[RED]` **SSRF (`CWE-918`, `A01:2025`):** Never fetch arbitrary user URLs directly. Allowlist `https://`/`http://` and trusted domains via a standard URL parser, **disable HTTP redirects**, resolve DNS at connect time blocking loopback (`127.0.0.0/8`, `::1`), link-local/metadata (`169.254.0.0/16`, `fe80::/10`), and RFC 1918/ULA ranges via an isolated egress proxy, and never return raw upstream responses.
- `[RED]` **Open Redirect (`CWE-601`):** Map opaque IDs to server-side destinations, or allow only relative paths starting with a single `/` (rejecting `//` and `/\`) or exact hostname allowlists.
- `[RED]` **Path Traversal (`CWE-22`):** Reference stored files by server UUIDs. Where paths are required, decode once, canonicalize (`realpath` / `Path.normalize().toAbsolutePath()`), and enforce strict canonical base-directory prefix containment.
- `[RED]` **Unsafe File Upload (`CWE-434`):** Validate magic bytes + strict extension allowlist (do not trust `Content-Type` or accept active `.svg`/`.html` served inline same-origin), re-encode/CDR untrusted images/docs, rename to UUIDs, enforce byte size + decompression-bomb limits, and store outside web root on an isolated non-executable sandbox origin with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.

## 7. Client Trust, Electron / Webviews & TLS Edge
- `[RED]` **Client Trust Inversion (`A01:2025`):** Re-validate all inputs, pricing, state transitions, and authorization server-side; never treat UI route guards or hidden form fields as security boundaries.
- `[RED]` **Insecure Electron / Desktop Webviews:** Explicitly enforce `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, and `webSecurity: true`. Never expose raw `ipcRenderer` via `contextBridge`; validate IPC senders/arguments in Main, block `will-navigate`/`setWindowOpenHandler`, and allowlist `https://` in `shell.openExternal()`.
- `[RED]` / `[YELLOW]` **TLS & Reverse Proxy Edge:** Reject TLS 1.0/1.1 (`[RED]`); enforce TLS 1.3 and AEAD-only TLS 1.2 (`[YELLOW]` if weak TLS 1.2 suites remain), terminate TLS at proxy/WAF with HTTP->HTTPS `301`, Slowloris timeouts, and TLS/mTLS re-encryption to private origin backends.

## 8. DNS, Domain, Email & Edge Protection (Cloudflare / Google / Microsoft)
- `[RED]` **Cloudflare `Flexible` TLS & Dangling DNS / Subdomain Takeover:** Never run reverse-proxy/CDN edge TLS in `Flexible` mode (leaves edge-to-origin plaintext); enforce **`Full (Strict)`** with verified origin certificates. Audit and remove orphaned `CNAME`/`A` records pointing to decommissioned cloud services (S3, Heroku, GitHub Pages, Azure) to prevent subdomain takeover (`CWE-350`).
- `[YELLOW]` **Subresource Integrity (SRI) on Third-Party Scripts:** Require cryptographic `integrity="sha384-..."` and `crossorigin="anonymous"` on all external CDN `<script>`/`<link>` tags (mandatory on auth and payment pages under PCI-DSS v4.0).
- `[YELLOW]` **Email Auth (SPF, DKIM, DMARC), DNSSEC & CAA:** Configure **SPF** (staying within 10 DNS lookups), **DKIM** cryptographic signing, and enforced **DMARC (`p=reject`)** on domains sending transactional mail to prevent spoofing/BEC. Enable **DNSSEC** (registrar DS record) and **CAA** records restricting which CAs may issue certificates for your domain, alongside edge DDoS and Bot Management on auth/checkout routes.

## Verification Checklist
- Run `scan.py`/`scan.ps1` across both source and compiled frontend bundles (`dist/`, `.next/`, `build/`).
- Probe CORS (`Origin: https://evil.example`, `Origin: null`), headers (`curl -I`), `Set-Cookie` flags, `169.254.169.254` SSRF/redirect payloads, `../` paths, and Electron `BrowserWindow` flags.
- Verify DNS/email posture (`SPF`, `DKIM`, `DMARC p=reject`, `DNSSEC`, `CAA`), absence of dangling CNAMEs, `Full (Strict)` edge TLS, and `integrity=` attributes on external `<script>` tags.

## Authoritative Sources
- [OWASP Top 10:2025](https://top10.owasp.org/2025/) | [OWASP ASVS 5.0](https://asvs.owasp.org/)
- [OWASP XSS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | [CSP](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | [HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) | [Session Mgmt](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) | [CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Request_Forgery_Prevention_Cheat_Sheet.html) | [SSRF](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | [File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security) | [Trusted Types](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API) | [Electron Security](https://www.electronjs.org/docs/latest/tutorial/security) | [PortSwigger Academy](https://portswigger.net/web-security)
