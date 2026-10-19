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

  constructor(private readonly apiKey?: string) {}

  public isConfigured(): boolean {
    return Boolean(this.apiKey && this.apiKey.trim().length > 0 && !this.apiKey.includes('MY_KEY'));
  }

  public async checkUrl(normalizedUrl: string): Promise<ThreatCheckResult> {
    if (!this.isConfigured()) {
      throw new ThreatProviderError(
        this.id,
        'Google Web Risk API Key is not configured. Set WEB_RISK_API_KEY in environment or settings.',
        false
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
