# SATVRA Threat Model & Security Posture
**Standard:** STRIDE & OWASP Browser Extension Security Principles  
**Status:** Reviewed for MVP Version 1.0.0

---

## 1. Threat Categories & Defenses

| Threat Vector | Attack Scenario | SATVRA Defense & Mitigation | Status |
| :--- | :--- | :--- | :--- |
| **Punycode / Homograph Attacks** | Malicious actor registers `xn--gogle-pra.com` (rendered as `göogle.com`) to impersonate official portals. | Domain normalizer forces Unicode canonical decomposition (NFKC) and extracts raw ASCII punycode alongside decoded representation. Flags mixed-script and spoofed top-level domains. | **Mitigated** |
| **User-Info Obfuscation** | Attacker crafts `https://irs.gov@evil-site.com/login` where browser treats `irs.gov` as credentials and navigates to `evil-site.com`. | RFC 3986 parser strips username/password user-info and evaluates the true hostname (`evil-site.com`), refusing to match official-source credentials against user-info segments. | **Mitigated** |
| **Deceptive Subdomains** | Attacker creates `https://irs.gov.portal-taxrefund.com` mimicking an official domain. | Strict right-to-left canonical domain matching. Official source records are anchored to exact registered domains (e.g. `irs.gov`), never subdomains of untrusted parent domains. | **Mitigated** |
| **Port & IP Obfuscation** | Attacker uses hex/octal IP formats (`http://0177.0.0.1` or `http://2130706433`) or non-standard ports to bypass simple string matchers. | Standardized URL parser normalizes IP representations and strips irrelevant port configurations for threat checking. | **Mitigated** |
| **Network Failures & Downgrades** | Attacker drops packets or causes provider timeout hoping SATVRA will default to "clean" status. | Fail-closed state modeling: Any timeout or provider error yields `CHECK_UNAVAILABLE`. The UI explicitly displays: *"Threat verification could not complete. Proceed with caution."* Never defaults to safe. | **Mitigated** |
| **Open Redirects** | Vulnerable site redirects from legitimate `example.com/out?url=malicious.com`. | Service worker inspects both `webNavigation.onBeforeNavigate` and `onCommitted` transitions. declarativeNetRequest rules monitor target redirect destinations. | **Mitigated** |
| **API Key Exfiltration** | Attacker inspects extension bundle to steal commercial threat intelligence API keys. | Extension contains zero API secrets. Lookups are proxied through SATVRA's backend server with strict rate limiting and request validation. | **Mitigated** |
| **Clickjacking / False Bypass** | Malicious page tries to iframe the warning interstitial or click-jack the bypass button. | Warning page enforces `X-Frame-Options: DENY`, strict CSP, requires a two-step deliberate confirmation to proceed, and logs security override events. | **Mitigated** |

---

## 2. Explicit System Limitations (What SATVRA Does NOT Promise)

1. **Zero-Day & Real-Time Undetected Malware:** No threat intelligence feed has 100% immediate coverage. A brand-new domain registered 5 minutes ago will return `NO_KNOWN_THREAT_FOUND` or `UNVERIFIED`. SATVRA never reports "SAFE", only "NO KNOWN THREAT FOUND".
2. **Post-Load In-Memory DOM Attacks:** SATVRA MVP focuses on network-level navigation protection and domain validation. It does not perform in-depth heap inspection or headless JavaScript sandbox execution on client devices.
3. **Compromised Legitimate Domains:** If a verified official government domain is actively compromised (e.g., via stored XSS or supply-chain script), SATVRA will indicate `OFFICIAL_SOURCE_MATCHED` unless/until threat feeds flag the specific sub-path as compromised, in which case `CONFLICTING_SIGNALS` or `KNOWN_THREAT` is triggered.
4. **Offline Mode:** When offline, threat intelligence lookups are unavailable (`CHECK_UNAVAILABLE`), though pre-compiled local declarativeNetRequest rules and local official directory caches continue to protect against known offline vectors.
