# SATVRA Architecture & System Design
**Tagline:** Trust What You Browse  
**Version:** 1.0.0-mvp  
**Target Platform:** Chrome Manifest V3 (Chromium / Edge compatible) + Node.js/Express Backend Proxy + Web Verification Testbench

---

## 1. System Overview

SATVRA combines three primary security capabilities into a cohesive, privacy-conscious desktop browser extension:
1. **Real Threat Intelligence Check:** Validates normalized URLs against verified threat intelligence feeds (Google Web Risk API, abuse.ch URLhaus, and local fast-path blocklists) using a decoupled adapter pattern.
2. **Pre-Navigation & Request Protection:** Employs Chrome Manifest V3 `declarativeNetRequest` dynamic rules and background navigation interceptors to block known malicious destinations before network requests execute, redirecting to a safe interstitial warning page.
3. **Evidence-Based Official Source Discovery:** Identifies legitimate government, educational, and public service domains via an audited, evidence-backed directory with canonical records, review status, and direct citations.
4. **Explainable Website Risk Statuses:** Instead of generating arbitrary 0–100 pseudo-scores, SATVRA classifies pages into 6 clear, explainable states:
   - `KNOWN_THREAT`: Reported by active threat intelligence as malicious (malware, phishing, social engineering).
   - `NO_KNOWN_THREAT_FOUND`: Check completed; no covered threat identified in feeds (never equates to "guaranteed safe").
   - `OFFICIAL_SOURCE_MATCHED`: Domain matches an audited official public service record with verified authority.
   - `UNVERIFIED`: General web domain; no active threat reported, but lacks official verification.
   - `CHECK_UNAVAILABLE`: Network timeout, provider error, or offline state (never reported as clean).
   - `CONFLICTING_SIGNALS`: Threat feed reports risk while an official source or user rule conflicts, requiring manual review.

---

## 2. Component Topology

```
+-----------------------------------------------------------------------------------+
|                              CHROME BROWSER (MV3)                                 |
|                                                                                   |
|  +--------------------+   chrome.webNavigation   +-----------------------------+  |
|  |                    | -----------------------> |                             |  |
|  |  Content Page /    |                          | Background Service Worker   |  |
|  |  Active Tab        | <----------------------- | (service-worker.ts)         |  |
|  |                    |      badge & status      | - URL Normalization Engine  |  |
|  +--------------------+                          | - State Cache (LRU TTL)     |  |
|                                                  | - DNR Dynamic Rule Sync     |  |
|  +--------------------+                          +-----------------------------+  |
|  |                    |                                       |                   |
|  | Browser Popup      | <---- chrome.runtime.sendMessage -----+                   |
|  | (popup.html / tsx) |                                       |                   |
|  | - Risk Explanation |                                       v                   |
|  | - Official Citation|                          +-----------------------------+  |
|  | - Action Controls  |                          | declarativeNetRequest       |  |
|  +--------------------+                          | Dynamic Block Rules         |  |
|                                                  | (redirect -> warning.html)  |  |
|  +--------------------+                          +-----------------------------+  |
|  | Interstitial Page  |                                                           |
|  | (warning.html/tsx) |                                                           |
|  | - Threat details   |                                                           |
|  | - Safe return path |                                                           |
|  +--------------------+                                                           |
+-----------------------------------------------------------------------------------+
                                         |
                       HTTPS REST API (Zero credentials in client)
                                         v
+-----------------------------------------------------------------------------------+
|                         SATVRA SECURE BACKEND PROXY (server.ts)                   |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | /api/threat-intel/check                                                     |  |
|  | - Rate limiting (token bucket per IP/client)                                |  |
|  | - URL canonicalization (RFC 3986, Punycode decoding, userinfo stripping)    |  |
|  | - Provider Adapter Interface (Google Web Risk, URLhaus, Local Heuristics)   |  |
|  | - Structured audit logging (hashed URLs, no query params with sensitive data)|  |
|  +-----------------------------------------------------------------------------+  |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | /api/official-sources                                                       |  |
|  | - Audited directory of government (.gov, state/federal), academic, utility  |  |
|  | - Search & query filtering with authoritative citations                     |  |
|  +-----------------------------------------------------------------------------+  |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | /api/extension/download                                                     |  |
|  | - Dynamic packaging of ready-to-load Chrome MV3 unpacked extension zip      |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 3. Data Flow & Security Boundaries

1. **Client Isolation:**
   - The browser extension never embeds raw threat provider API keys.
   - All external intelligence lookups route through the SATVRA backend proxy or verified local DNR rules.
2. **Minimal Data Transmission:**
   - URLs are normalized and stripped of query parameters/fragment identifiers before external checks, preventing transmission of sensitive tokens, session IDs, or form data.
3. **Defense in Depth:**
   - Manifest V3 declarativeNetRequest blocks threats at the browser network layer before socket connection.
   - Background worker validates navigation events and manages dynamic rules.
   - Interstitial warning blocks execution and prevents automatic click-through.
