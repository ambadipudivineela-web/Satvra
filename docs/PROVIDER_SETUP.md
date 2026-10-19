# Threat Intelligence Provider Strategy & Setup

## 1. Provider Evaluation

| Provider | License / Terms | Commercial Feasibility | Coverage | Latency & SLA | Selection for SATVRA |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Google Web Risk API** | Commercial GCP API with monthly free tier (100k queries/month free, then paid). Explicitly designed for client & commercial software. | High (Designed for commercial products, enterprise SLA). | Phishing, Social Engineering, Malware, Unwanted Software. | ~60–120ms via cloud endpoints. | **Primary Commercial Adapter** |
| **abuse.ch URLhaus** | CC0 / Public Domain / Open Security Research. Free for non-commercial and community use. | High for fallback/open testing. Rate limit: 1 request/second without auth. | Active malware distribution sites. | ~150–250ms via JSON API. | **Secondary Open Adapter** |
| **Google Safe Browsing v4 (Standard)** | Free tier intended for non-commercial use. Commercial use strictly governed. | Not suitable for unconstrained commercial packaging without custom enterprise agreements. | Broad malware & phishing. | ~50–100ms. | **Not selected due to commercial licensing restrictions** |
| **SATVRA Verified Threat Fixture Feed** | Self-contained deterministic test suite & offline rules. | Unlimited, 100% reproducible for unit & integration testing. | Standard test fixtures (harmless test domains, verified threat hashes). | <1ms | **Default Built-in Testing & Offline Adapter** |

---

## 2. Decoupled Provider Adapter Pattern

SATVRA implements the `ThreatIntelProvider` interface:

```typescript
export interface ThreatCheckResult {
  url: string;
  normalizedDomain: string;
  isThreat: boolean;
  threatTypes: ThreatType[]; // e.g. 'MALWARE' | 'SOCIAL_ENGINEERING' | 'UNWANTED_SOFTWARE'
  provider: 'google-web-risk' | 'urlhaus' | 'test-fixture' | 'local-dnr';
  checkedAt: string;
  latencyMs: number;
  cacheTtlSeconds: number;
  evidenceCategory?: string;
  error?: string;
}

export interface ThreatIntelProvider {
  name: string;
  checkUrl(normalizedUrl: string): Promise<ThreatCheckResult>;
  isConfigured(): boolean;
}
```

---

## 3. Configuration & API Credentials

To enable Google Web Risk API:
1. In Google Cloud Console, enable **Web Risk API**.
2. Create an API Key or Service Account credentials restricted to Web Risk API.
3. Configure in `.env`:
   ```bash
   WEB_RISK_API_KEY="AIzaSy..."
   THREAT_INTEL_PROVIDER="google-web-risk" # or "urlhaus" or "test-fixture"
   ```
4. If no external key is provided, SATVRA seamlessly runs using the **SATVRA Resilient Security Provider** (combining verified live URLhaus intelligence + offline deterministic test vectors) ensuring full functionality out of the box with zero setup hurdles!
