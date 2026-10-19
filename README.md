# SATVRA — Trust What You Browse
**Version:** 1.0.0-mvp  
**Target Platform:** Chrome Manifest V3 Desktop Extension (Edge Compatible) & Security Console  
**License:** Apache-2.0

---

## 1. What is SATVRA?

SATVRA is a privacy-conscious browser security extension and threat-intelligence platform designed for students, job seekers, citizens accessing government services, online shoppers, and everyday internet users.

Unlike conventional antivirus tools that display arbitrary "98/100" safety badges or make blanket guarantees, SATVRA is built upon strict **Honesty & Explainability First Principles**:
- **Never claims a website is 100% safe.**
- **Separates official institutional authority from absence of known malware.**
- **Explains what evidence establishes and what it does NOT establish.**
- **Enforces fail-closed security:** If an API lookup fails, times out, or is offline, the status is reported as `CHECK_UNAVAILABLE`, never as a false clean pass.

---

## 2. Core Capabilities

### A. Real Website Threat Detection
- Decoupled threat provider adapter interface (`ThreatIntelProvider`).
- Supports **Google Web Risk API** (commercial compliance), **abuse.ch URLhaus**, and **deterministic verified security test fixtures**.
- RFC 3986 URL normalizer defending against Punycode/IDN homographs (`xn--...`), user-info tricks (`https://irs.gov@evil.com`), and trailing dots.
- Strips URL query parameters and fragments for privacy-first anonymized queries.

### B. Navigation Protection (Manifest V3 declarativeNetRequest)
- Pre-navigation blocking via Chrome Manifest V3 dynamic rules.
- Intercepts malicious main_frame navigations before the destination socket/DOM loads.
- Redirects threats to a comprehensive **Interstitial Warning Page** (`warning.html`) with an immediate "Back to Safety" route and a deliberate two-step override.

### C. Official Source Prioritization
- Audited directory of verified public services (tax administration, social security, postal services, federal student financial aid, civil service jobs, and state portals).
- Strict right-to-left canonical domain matching: prevents deceptive subdomain attacks (e.g. `irs.gov.attacker-fake.com` is rejected; `sa.www4.irs.gov` is recognized).
- Each record links to an authoritative government citation and audit date.

### D. The 6 Explainable Website Risk States
1. **`KNOWN_THREAT`**: A threat intelligence feed flags confirmed malware, phishing, or unwanted software.
2. **`NO_KNOWN_THREAT_FOUND`**: Threat checks completed without hits in active blocklists (with explicit caveats that zero-days or uncataloged sites may still exist).
3. **`OFFICIAL_SOURCE_MATCHED`**: Domain matches an audited official public service record with verified authority.
4. **`UNVERIFIED`**: General web domain with insufficient public evidence.
5. **`CHECK_UNAVAILABLE`**: Network failure, timeout, or missing provider credentials (never reported clean).
6. **`CONFLICTING_SIGNALS`**: An official or allowlisted domain is flagged by threat intelligence as having active malicious artifacts.

---

## 3. Quick Start & Chrome Extension Installation

### Loading in Google Chrome / Microsoft Edge
1. In the SATVRA web console, click **"Download Extension (.zip)"** or fetch `/api/extension/download`.
2. Extract the downloaded `satvra-extension-mv3.zip` to a local folder (e.g., `~/Downloads/satvra-extension`).
3. Open Chrome and navigate to `chrome://extensions` (or `edge://extensions` in Edge).
4. Turn on the **Developer mode** toggle in the upper right corner.
5. Click **Load unpacked** and select the extracted folder containing `manifest.json`.
6. Pin **SATVRA** to your browser toolbar.

---

## 4. Safe Verification Fixtures (No Live Malware Needed)

- **Phishing Intercept Fixture:** `http://malware-test.satvra.local/phishing` or `http://testsafebrowsing.appspot.com/s/phishing.html`
  - *Result:* Blocked before navigation; redirects to Interstitial Warning page.
- **Malware Block Fixture:** `http://malware-test.satvra.local/malware`
  - *Result:* Status badge `!` (Red); blocked at network layer.
- **Audited Official Source:** `https://irs.gov/refunds` or `https://studentaid.gov`
  - *Result:* Status badge `GOV` (Emerald); displays verified authority citation.
- **Deceptive Subdomain Spoof:** `https://irs.gov.attacker-domain.com`
  - *Result:* Recognized as unverified third-party domain; official IRS status is withheld.

---

## 5. Automated Tests

Run the full verification suite via terminal:
```bash
npm test
```
Or view the interactive test runner directly in the web console under the **"Verification Tests"** tab.
All 17 tests verify:
- URL normalization & user-info stripping
- Punycode & homograph risk detection
- Deceptive subdomain defenses
- Fail-closed error handling
- DeclarativeNetRequest dynamic rules
- Official source keyword ranking & citations
