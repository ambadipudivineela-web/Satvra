# SATVRA Privacy & Data Flow Policy

## 1. Minimal Data Collection Principles

1. **No Sensitive Payload Transmission:** SATVRA strips query strings (`?param=value`), URL fragments (`#token`), credentials (`user:pass@`), and cookies before running any lookup. Only `scheme://host/path` (or `scheme://host` when domain-level check is performed) is evaluated.
2. **No Form Content, DOM Scraping, or Keystroke Logging:** SATVRA only inspects navigation targets, HTTP headers (for declarativeNetRequest), and active domain identity. It never accesses password fields, payment information, or personal communications.
3. **No Centralized Browsing History Tracking:** URLs are cached locally in memory with strict TTLs (default 15 minutes) solely to reduce redundant network queries and enhance browsing performance. No long-term persistent database of visited pages is maintained.
4. **Zero Third-Party Ad Trackers or Telemetry:** No Google Analytics, Mixpanel, Segment, or ad networks are embedded in SATVRA.

---

## 2. Manifest V3 Permissions Explanation

| Permission | Purpose | Justification |
| :--- | :--- | :--- |
| `declarativeNetRequest` | Pre-navigation threat blocking | Blocks requests to known malware/phishing sites at the network layer before execution. |
| `declarativeNetRequestFeedback` | Rule execution verification | Used strictly in developer/test mode to verify dynamic rules triggered. |
| `webNavigation` | Navigation event monitoring | Detects address bar changes and redirects to verify destination safety before rendering. |
| `activeTab` | Read active tab URL when user clicks extension popup | Reads current tab URL strictly on user invocation to display risk report. |
| `storage` | Local extension settings storage | Stores user preferences (threat sensitivity, provider choice, whitelisted domains). |

---

## 3. Data Flow Diagram

```
User navigates to: https://service.example.org/portal?session=xyz987#token
                            |
                   URL Normalization
                            |
     Normalized Query: https://service.example.org/portal
                            |
           [Local In-Memory Cache (15m TTL)]
                 /                   \
        Cache Hit                     Cache Miss
           |                              |
    Immediate Return         Secure Backend Proxy Request
                             (/api/threat-intel/check)
                                          |
                              Provider Adapter Check
                             (Google Web Risk / URLhaus)
                                          |
                            Response (Threat / No Threat)
                                          |
                              Update Local Cache & DNR
```
