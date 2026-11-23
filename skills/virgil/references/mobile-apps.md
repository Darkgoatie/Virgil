# Mobile Application Security (Apple Platform Security, Android & OWASP MASVS)

## 1. Network & Transport Security (MASVS-NETWORK)
- `[RED]` **Disabled iOS App Transport Security (ATS):** Never enable `NSAllowsArbitraryLoads` globally in `Info.plist`. Require HTTPS with TLS 1.2+/1.3 and forward-secrecy ciphers; justify and scope any narrow domain exception strictly.
- `[RED]` **Android Cleartext Traffic:** Forbid `android:usesCleartextTraffic="true"` in `AndroidManifest.xml` and `cleartextTrafficPermitted="true"` in `network_security_config.xml`. Do not trust user-installed CA certificates in production release builds, and never disable TLS verification in HTTP debug interceptors shipped to release.
- `[OPTIONAL]` **Certificate Pinning:** Pin SPKI hashes only where operationally rotatable (with backup pins and remote kill-switch/refresh) to avoid self-DoS lockouts.

## 2. Local Data Storage & Hardware Key Protection (MASVS-STORAGE / MASVS-CRYPTO)
- `[RED]` **Plaintext Secrets or PII in App Storage (`CWE-312`, `CWE-922`):** Never store access/refresh tokens, encryption keys, or sensitive PII in `UserDefaults`, `SharedPreferences`, unencrypted SQLite/Realm, `AsyncStorage`, or external/shared storage.
- `[RED]` **Weak Keychain Accessibility (`kSecAttrAccessibleAlways`):** Never use deprecated `kSecAttrAccessibleAlways` or `kSecAttrAccessibleAlwaysThisDeviceOnly`.
- `[YELLOW]` **Hardened iOS Keychain & Android Backups:**
  - Use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (or `AfterFirstUnlockThisDeviceOnly` only for background tasks) so credentials do not migrate across iCloud backups/devices, and wipe stale Keychain items on first launch after fresh install.
  - Set `android:allowBackup="false"` (or strict `fullBackupContent` / `dataExtractionRules` exclusions).
- `[OPTIONAL]` **Hardware Key Enclaves & UI Masking:** Anchor high-value private keys in hardware (**Apple Secure Enclave** via `kSecAttrTokenIDSecureEnclave` / **Android StrongBox Keystore**) and mask sensitive views in app-switcher snapshots and clipboards.

## 3. Platform Components, Deep Links & Biometrics (MASVS-PLATFORM / MASVS-AUTH)
- `[RED]` **Exposed Android Components & Deep-Link Hijacking:** Set `android:exported="false"` on internal activities, services, broadcast receivers, and content providers unless explicitly required; guard intentionally exported components with signature/custom permissions. Validate all incoming URI schemes, Universal Links (AASA), Android App Links (`assetlinks.json`), and Intent extras against strict allowlists before navigation or WebView loading.
- `[RED]` **Client-Only Biometric Bypass:** Never gate sensitive actions solely on a boolean `LAContext` / `BiometricPrompt` success callback. Bind biometrics to a hardware-backed cryptographic key (Keychain `SecAccessControl` / Keystore `CryptoObject`) that signs a server challenge or unlocks an encrypted server-validated token.
- `[RED]` **Hardcoded Backend Secrets in IPA/APK:** Treat mobile binaries as fully reverse-engineerable (`CWE-798`); never embed privileged API keys, signing secrets, or master encryption keys inside app bundles or `EXPO_PUBLIC_*` variables.

## Verification Checklist
- Inspect `Info.plist` for `NSAllowsArbitraryLoads`, `AndroidManifest.xml` for `usesCleartextTraffic`, `allowBackup="true"`, and unguarded `android:exported="true"`, and `network_security_config.xml` for `cleartextTrafficPermitted="true"`.
- Audit Keychain/Keystore wrappers for `ThisDeviceOnly` flags, absence of `kSecAttrAccessibleAlways`, and hardware-backed biometric binding.
- Fuzz custom URL schemes and exported Intents with crafted parameters (`javascript:`, `file://`, `../`, untrusted redirect URLs).

## Authoritative Sources
- [OWASP MASVS (Mobile Application Security Verification Standard)](https://mas.owasp.org/MASVS/)
- [Apple Platform Security](https://support.apple.com/guide/security/welcome/web)
- [Android App Security Best Practices](https://developer.android.com/privacy-and-security/security-tips)
