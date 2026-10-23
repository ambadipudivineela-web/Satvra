/**
 * Google Web Risk API Provider Adapter
 * 
 * Documentation: https://cloud.google.com/web-risk/docs
 * Intended for client and commercial applications checking URLs for threats.
 */

import { ThreatIntelProvider, ThreatProviderError } from './adapter.ts';
import { ThreatCheckResult, ThreatType } from '../types.ts';
import { normalizeUrl } from '../urlNormalizer.ts';

export class GoogleWebRiskProvider implements ThreatIntelProvider {
  public readonly id = 'google-web-risk';
  public readonly displayName = 'Google Web Risk (Commercial Threat API)';

  // Circuit breaker state to prevent repeated failing requests and error spam
  private static authFailure = false;
  private static authFailureReason = '';
  public static hasWarned = false;

  constructor(private readonly apiKey?: string) {}

  /**
   * Validates whether a given key has the syntax of a genuine Google Cloud API key.
   * Google Cloud API keys start with 'AIza' and are typically 39 characters long,
   * containing only alphanumeric characters, underscores, and hyphens.
   * Placeholders like "Your api key", "YOUR_API_KEY", "MY_KEY", etc., are rejected.
   */
  public static isValidGoogleApiKey(key?: string): boolean {
    if (!key || typeof key !== 'string') return false;
    const trimmed = key.trim();
    if (!trimmed.startsWith('AIza')) return false;
    if (/\s/.test(trimmed)) return false;
    if (trimmed.length < 30 || trimmed.length > 55) return false;
    if (!/^AIza[0-9A-Za-z_-]+$/.test(trimmed)) return false;
    return true;
  }

  public isConfigured(): boolean {
    if (GoogleWebRiskProvider.authFailure) {
      return false;
    }
    return GoogleWebRiskProvider.isValidGoogleApiKey(this.apiKey);
  }

  public static resetCircuitBreaker() {
    GoogleWebRiskProvider.authFailure = false;
    GoogleWebRiskProvider.authFailureReason = '';
    GoogleWebRiskProvider.hasWarned = false;
  }

  public async checkUrl(normalizedUrl: string): Promise<ThreatCheckResult> {
    if (!this.isConfigured()) {
      let message = 'Google Web Risk API Key is not configured. Set a valid WEB_RISK_API_KEY (starts with AIza...) in the server environment.';
      if (GoogleWebRiskProvider.authFailure) {
        message = `Google Web Risk API rejected credentials: ${GoogleWebRiskProvider.authFailureReason || 'API key not valid'}. To fix, configure a valid WEB_RISK_API_KEY in the server environment and ensure Web Risk API is enabled in Google Cloud Console.`;
      } else if (this.apiKey && this.apiKey.trim().length > 0 && !GoogleWebRiskProvider.isValidGoogleApiKey(this.apiKey)) {
        message = 'Google Web Risk API Key in environment is a placeholder or invalid format (Google API keys must start with "AIza"). Configure a genuine WEB_RISK_API_KEY in the server environment.';
      }
      throw new ThreatProviderError(
        this.id,
        message,
        false,
        400
      );
    }

    const startTime = Date.now();
    const parsed = normalizeUrl(normalizedUrl);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);

    try {
      const endpoint = new URL('https://webrisk.googleapis.com/v1/uris:search');
      endpoint.searchParams.append('key', this.apiKey!.trim());
      endpoint.searchParams.append('threatTypes', 'MALWARE');
      endpoint.searchParams.append('threatTypes', 'SOCIAL_ENGINEERING');
      endpoint.searchParams.append('threatTypes', 'UNWANTED_SOFTWARE');
      endpoint.searchParams.append('uri', parsed.normalizedUrl);

      const response = await fetch(endpoint.toString(), {
        method: 'GET',
        headers: {
          Accept: 'application/json',
        },
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errMsg = errorData.error?.message || `HTTP ${response.status}`;

        // If authentication error (e.g. 400 "API key not valid", 401/403 forbidden/API not enabled),
        // trip circuit breaker and throttle warning to once without logging the key
        if (response.status === 400 || response.status === 401 || response.status === 403) {
          GoogleWebRiskProvider.authFailure = true;
          GoogleWebRiskProvider.authFailureReason = errMsg;
          if (!GoogleWebRiskProvider.hasWarned) {
            GoogleWebRiskProvider.hasWarned = true;
            console.warn(
              `[SATVRA] Google Web Risk API authentication error: ${errMsg}. ` +
              `To fix, configure a valid WEB_RISK_API_KEY in the server environment with Web Risk API enabled in Google Cloud Console.`
            );
          }
        }

        throw new ThreatProviderError(this.id, `Google Web Risk API Error: ${errMsg}`, response.status >= 500, response.status);
      }

      const data = await response.json();
      const latencyMs = Math.max(1, Date.now() - startTime);

      if (data.threat && Array.isArray(data.threat.threatTypes) && data.threat.threatTypes.length > 0) {
        const threatTypes: ThreatType[] = data.threat.threatTypes.map((t: string) => {
          if (t === 'SOCIAL_ENGINEERING') return 'SOCIAL_ENGINEERING';
          if (t === 'MALWARE') return 'MALWARE';
          if (t === 'UNWANTED_SOFTWARE') return 'UNWANTED_SOFTWARE';
          return 'POTENTIALLY_HARMFUL_APPLICATION';
        });

        return {
          url: normalizedUrl,
          normalizedUrl: parsed.normalizedUrl,
          domain: parsed.canonicalDomain || parsed.hostname,
          isThreat: true,
          threatTypes,
          provider: 'google-web-risk',
          providerDisplayName: this.displayName,
          checkedAt: new Date().toISOString(),
          latencyMs,
          cacheTtlSeconds: 300,
          evidenceCategory: `Google Web Risk: ${threatTypes.join(', ')}`,
          rawDetails: `Expire: ${data.threat.expireTime || 'N/A'}; Categories: ${threatTypes.join(', ')}`,
        };
      }

      return {
        url: normalizedUrl,
        normalizedUrl: parsed.normalizedUrl,
        domain: parsed.canonicalDomain || parsed.hostname,
        isThreat: false,
        threatTypes: [],
        provider: 'google-web-risk',
        providerDisplayName: this.displayName,
        checkedAt: new Date().toISOString(),
        latencyMs,
        cacheTtlSeconds: 900,
      };
    } catch (err: unknown) {
      clearTimeout(timer);
      if (err instanceof ThreatProviderError) {
        throw err;
      }
      const isAbort = (err as Error)?.name === 'AbortError';
      throw new ThreatProviderError(
        this.id,
        isAbort ? 'Request to Google Web Risk API timed out after 3.5s' : ((err as Error)?.message || 'Network error'),
        true
      );
    }
  }
}
