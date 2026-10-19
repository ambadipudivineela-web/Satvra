# SATVRA Chrome Extension — Installation & Verification Guide

## 1. Quick Start: Loading the Extension in Google Chrome or Microsoft Edge

1. **Obtain the Extension Package:**
   - In the SATVRA web console, click **"Export Unpacked Extension (.zip)"** or **"View Extension Files"**.
   - Extract the downloaded ZIP archive into a local folder (e.g. `~/Downloads/satvra-extension`).
   
2. **Open Chrome / Edge Extensions Management:**
   - In Google Chrome, navigate to `chrome://extensions`.
   - In Microsoft Edge, navigate to `edge://extensions`.

3. **Enable Developer Mode:**
   - Toggle the **"Developer mode"** switch in the top-right corner.

4. **Load the Unpacked Folder:**
   - Click the **"Load unpacked"** button in the top-left toolbar.
   - Select the extracted `satvra-extension` folder (the folder containing `manifest.json`).

5. **Pin and Verify:**
   - Click the Extension puzzle icon in your browser toolbar and pin **SATVRA**.
   - Click the SATVRA icon on any tab: you will see the active domain, explainable status, verification details, and quick controls.

---

## 2. Testing Threat Protection Safely (Using Controlled Harmless Test Fixtures)

**NEVER navigate to real malware or phishing sites to test security tools.**
SATVRA includes certified harmless test domains recognized by the extension's declarativeNetRequest rules and backend adapter:

- **Phishing Test Fixture:** `http://malware-test.satvra.local/phishing` or `http://testsafebrowsing.appspot.com/s/phishing.html`
  - *Expected Result:* declarativeNetRequest intercepts navigation immediately and redirects to SATVRA's Interstitial Warning page (`warning.html`).
- **Malware Test Fixture:** `http://malware-test.satvra.local/malware`
  - *Expected Result:* Status badge turns red, labeled `KNOWN THREAT`, network request blocked.
- **Official Source Test:** `https://irs.gov`, `https://gov.uk`, `https://usps.com`, `https://ssa.gov`
  - *Expected Result:* Labeled `OFFICIAL SOURCE MATCHED` with official citation, verified jurisdiction, and direct link.
- **Deceptive Subdomain Test:** `https://irs.gov.attacker-domain.com`
  - *Expected Result:* Correctly identified as `UNVERIFIED` attacker domain, NOT an official IRS domain.
- **Unverified General Site:** `https://random-portfolio-example.org`
  - *Expected Result:* Labeled `UNVERIFIED / NO KNOWN THREAT FOUND`, with clear explanation that lack of blocklist entry does not guarantee safety.
