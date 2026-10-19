/**
 * abuse.ch URLhaus Threat Intelligence Provider Adapter
 * 
 * Free / CC0 community threat dataset tracking active malware distribution URLs.
 * Documentation: https://urlhaus-api.abuse.ch/
 */

import { ThreatIntelProvider, ThreatProviderError } from './adapter.ts';
import { ThreatCheckResult } from '../types.ts';
import { normalizeUrl } from '../urlNormalizer.ts';

export class UrlhausThreatProvider implements ThreatIntelProvider {
  public readonly id = 'urlhaus';
  public readonly displayName = 'abuse.ch URLhaus (Community Threat Feed)';

  constructor(private readonly apiKey?: string) {}

  public isConfigured(): boolean {
    return Boolean(this.apiKey && this.apiKey.trim().length > 0 && !this.apiKey.includes('MY_KEY'));
  }

  public async checkUrl(normalizedUrl: string): Promise<ThreatCheckResult> {
    const startTime = Date.now();
    const parsed = normalizeUrl(normalizedUrl);

    // Timeout controller after 3500ms
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/x-www-form-urlencoded',
      };
      if (this.apiKey) {
        headers['Auth-Key'] = this.apiKey.trim();
      }

      const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
        method: 'POST',
        headers,
        body: new URLSearchParams({ url: parsed.normalizedUrl }).toString(),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        throw new ThreatProviderError(
          this.id,
          `HTTP Error ${response.status} from URLhaus API`,
          response.status >= 500,
          response.status
        );
      }

      const data = await response.json();
      const latencyMs = Math.max(1, Date.now() - startTime);

      if (data.query_status === 'ok') {
        const threatType = data.threat === 'malware_download' ? 'MALWARE' : 'COMMAND_AND_CONTROL';
        return {
          url: normalizedUrl,
          normalizedUrl: parsed.normalizedUrl,
          domain: parsed.canonicalDomain || parsed.hostname,
          isThreat: true,
          threatTypes: [threatType],
          provider: 'urlhaus',
          providerDisplayName: this.displayName,
          checkedAt: new Date().toISOString(),
          latencyMs,
          cacheTtlSeconds: 300,
          evidenceCategory: `Active Malware Distribution (URLhaus ID: ${data.id || 'N/A'})`,
          rawDetails: `Status: ${data.url_status}; Threat: ${data.threat}; Added: ${data.date_added || 'Recent'}`,
        };
      }

      // If query_status is 'no_results', the URL is not in the active malware list
      return {
        url: normalizedUrl,
        normalizedUrl: parsed.normalizedUrl,
        domain: parsed.canonicalDomain || parsed.hostname,
        isThreat: false,
        threatTypes: [],
        provider: 'urlhaus',
        providerDisplayName: this.displayName,
        checkedAt: new Date().toISOString(),
        latencyMs,
        cacheTtlSeconds: 600,
      };
    } catch (err: unknown) {
      clearTimeout(timer);
      if (err instanceof ThreatProviderError) {
        throw err;
      }
      const isAbort = (err as Error)?.name === 'AbortError';
      throw new ThreatProviderError(
        this.id,
        isAbort ? 'Request to URLhaus API timed out after 3.5s' : ((err as Error)?.message || 'Network error'),
        true
      );
    }
  }
}
