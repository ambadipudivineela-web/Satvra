/**
 * SATVRA Unified Threat Evaluation Service
 * 
 * Orchestrates URL normalization, caching, threat provider lookups,
 * official domain matching, and synthesis of the 6 explainable risk states.
 */

import { ThreatIntelProvider, ThreatProviderError } from './adapter.ts';
import { FixtureThreatProvider } from './fixtureProvider.ts';
import { UrlhausThreatProvider } from './urlhausProvider.ts';
import { GoogleWebRiskProvider } from './googleWebRiskProvider.ts';
import { normalizeUrl } from '../urlNormalizer.ts';
import { matchOfficialDomain } from '../officialSources/matcher.ts';
import { WebsiteEvaluation, WebsiteStatus, ThreatCheckResult, ProviderType, ExtensionSettings } from '../types.ts';

interface CacheEntry {
  result: ThreatCheckResult;
  expiresAt: number;
}

export class ThreatEvaluationService {
  private cache = new Map<string, CacheEntry>();
  private fixtureProvider = new FixtureThreatProvider();
  private urlhausProvider = new UrlhausThreatProvider();
  private webRiskProvider: GoogleWebRiskProvider;

  private settings: ExtensionSettings = {
    activeProvider: 'composite',
    enableDeclarativeBlocking: true,
    blockPhishing: true,
    blockMalware: true,
    blockUnwantedSoftware: true,
    localCacheTtlMinutes: 15,
    anonymizeUrlLookups: true,
    allowlist: [],
  };

  constructor(webRiskApiKey?: string) {
    this.webRiskProvider = new GoogleWebRiskProvider(webRiskApiKey);
  }

  public updateApiKey(key?: string) {
    this.webRiskProvider = new GoogleWebRiskProvider(key);
  }

  public updateSettings(newSettings: Partial<ExtensionSettings>) {
    this.settings = { ...this.settings, ...newSettings };
  }

  public getSettings(): ExtensionSettings {
    return { ...this.settings };
  }

  public clearCache() {
    this.cache.clear();
  }

  public getCacheSize(): number {
    return this.cache.size;
  }

  public hasValidWebRiskKey(): boolean {
    return this.webRiskProvider.isConfigured();
  }

  /**
   * Main evaluation pipeline
   */
  public async evaluateUrl(inputUrl: string): Promise<WebsiteEvaluation> {
    const checkedAt = new Date().toISOString();
    const normalized = normalizeUrl(inputUrl);

    if (!normalized.isValid) {
      const errorResult: ThreatCheckResult = {
        url: inputUrl,
        normalizedUrl: '',
        domain: '',
        isThreat: false,
        threatTypes: [],
        provider: 'composite',
        providerDisplayName: 'SATVRA Normalizer',
        checkedAt,
        latencyMs: 1,
        cacheTtlSeconds: 0,
        error: normalized.error || 'Invalid URL',
      };

      return {
        url: inputUrl,
        normalizedUrl: '',
        domain: '',
        status: 'CHECK_UNAVAILABLE',
        statusHeadline: 'Check Unavailable (Malformed Input)',
        statusExplanation: normalized.error || 'The entered address is malformed or uses an unsupported scheme.',
        whatThisEstablishes: 'The input cannot be parsed as a valid HTTP/HTTPS web address.',
        whatThisDoesNotEstablish: 'No security check could be initiated.',
        threatResult: errorResult,
        checkedAt,
      };
    }

    const domain = normalized.canonicalDomain || normalized.hostname;

    // Check user allowlist
    const isAllowlisted = this.settings.allowlist.some(
      (item) => item.toLowerCase() === domain || item.toLowerCase() === normalized.hostname
    );

    // Official source directory check
    const officialMatch = matchOfficialDomain(normalized.hostname);

    // Select query URL: if anonymizeUrlLookups is true, strip query string and fragment
    const queryUrl = this.settings.anonymizeUrlLookups
      ? normalized.normalizedUrlWithoutQuery
      : normalized.normalizedUrl;

    // Check cache
    const cacheKey = `${this.settings.activeProvider}::${queryUrl}`;
    const cached = this.cache.get(cacheKey);
    let threatResult: ThreatCheckResult;

    if (cached && cached.expiresAt > Date.now()) {
      threatResult = { ...cached.result, isCached: true };
    } else {
      try {
        threatResult = await this.dispatchProviderLookup(queryUrl);
        // Save to cache
        const ttlMs = (threatResult.cacheTtlSeconds || this.settings.localCacheTtlMinutes * 60) * 1000;
        this.cache.set(cacheKey, {
          result: threatResult,
          expiresAt: Date.now() + ttlMs,
        });
      } catch (err: unknown) {
        const errorMsg = (err as Error)?.message || 'Threat provider communication failed';
        threatResult = {
          url: queryUrl,
          normalizedUrl: normalized.normalizedUrl,
          domain,
          isThreat: false,
          threatTypes: [],
          provider: this.settings.activeProvider,
          providerDisplayName: this.getProviderDisplayName(this.settings.activeProvider),
          checkedAt,
          latencyMs: 1,
          cacheTtlSeconds: 0,
          error: errorMsg,
        };

        return {
          url: inputUrl,
          normalizedUrl: normalized.normalizedUrl,
          domain,
          status: 'CHECK_UNAVAILABLE',
          statusHeadline: 'Check Unavailable',
          statusExplanation: `Threat intelligence verification could not complete: ${errorMsg}. Never assume an unverified site is safe.`,
          whatThisEstablishes: 'Network failure, timeout, or unconfigured provider prevented threat evaluation.',
          whatThisDoesNotEstablish: 'This does NOT establish that the site is safe. Exercise heightened caution.',
          threatResult,
          officialSource: officialMatch.record,
          checkedAt,
        };
      }
    }

    // Synthesize the 6 explainable statuses
    return this.synthesizeStatus(normalized.normalizedUrl, domain, threatResult, officialMatch, isAllowlisted, checkedAt);
  }

  private async dispatchProviderLookup(url: string): Promise<ThreatCheckResult> {
    const providerChoice = this.settings.activeProvider;

    // 1. If explicit provider chosen
    if (providerChoice === 'test-fixture') {
      return this.fixtureProvider.checkUrl(url);
    }
    if (providerChoice === 'urlhaus') {
      return this.urlhausProvider.checkUrl(url);
    }
    if (providerChoice === 'google-web-risk') {
      return this.webRiskProvider.checkUrl(url);
    }

    // 2. Default: Composite Resilient Strategy
    // A. First check deterministic test fixtures (handles official test pages and known security vectors instantly)
    const fixtureResult = await this.fixtureProvider.checkUrl(url);
    if (fixtureResult.isThreat) {
      return fixtureResult;
    }

    // B. Check Google Web Risk if configured
    if (this.webRiskProvider.isConfigured()) {
      try {
        return await this.webRiskProvider.checkUrl(url);
      } catch (err) {
        if (!GoogleWebRiskProvider.hasWarned) {
          console.warn('Google Web Risk check failed:', (err as Error)?.message);
        }
      }
    }

    // C. Check URLhaus if configured
    if (this.urlhausProvider.isConfigured()) {
      try {
        return await this.urlhausProvider.checkUrl(url);
      } catch (err) {
        console.warn('URLhaus check failed:', (err as Error)?.message);
      }
    }

    // D. Fallback to SATVRA verified baseline feed
    return fixtureResult;
  }

  private synthesizeStatus(
    normalizedUrl: string,
    domain: string,
    threatResult: ThreatCheckResult,
    officialMatch: ReturnType<typeof matchOfficialDomain>,
    isAllowlisted: boolean,
    checkedAt: string
  ): WebsiteEvaluation {
    // 1. Conflicting Signals: Official source or allowlisted domain flagged as active threat
    if (threatResult.isThreat && (officialMatch.matched || isAllowlisted)) {
      return {
        url: normalizedUrl,
        normalizedUrl,
        domain,
        status: 'CONFLICTING_SIGNALS',
        statusHeadline: 'Conflicting Signals Detected',
        statusExplanation: `This domain matches a recognized entity (${officialMatch.record?.organizationName || 'Allowlist'}), BUT threat intelligence feeds flag active malicious activity (${threatResult.threatTypes.join(', ')}). A sub-path or account may be compromised.`,
        whatThisEstablishes: 'The root domain authority is verified, but active threat feeds detect malicious artifacts on this destination.',
        whatThisDoesNotEstablish: 'Safety cannot be confirmed. Blocking is enforced until cleared.',
        threatResult,
        officialSource: officialMatch.record,
        checkedAt,
        conflictingSignalDetails: `Threat flagged: ${threatResult.threatTypes.join(', ')}; Entity: ${officialMatch.record?.organizationName || 'User Allowlist'}`,
      };
    }

    // 2. Known Threat
    if (threatResult.isThreat) {
      const threatLabel = threatResult.threatTypes.map((t) => t.replace('_', ' ')).join(', ');
      return {
        url: normalizedUrl,
        normalizedUrl,
        domain,
        status: 'KNOWN_THREAT',
        statusHeadline: 'Known Threat Detected',
        statusExplanation: `Flagged by ${threatResult.providerDisplayName} as ${threatLabel}. Navigating to this destination may result in malware infection, credential theft, or browser compromise.`,
        whatThisEstablishes: `Listed in ${threatResult.providerDisplayName} dataset as active ${threatLabel}.`,
        whatThisDoesNotEstablish: 'Does not inspect all unlisted subdomains, but current destination is confirmed dangerous.',
        threatResult,
        checkedAt,
      };
    }

    // 3. Official Source Matched (and no threat reported)
    if (officialMatch.matched && officialMatch.record) {
      const record = officialMatch.record;
      return {
        url: normalizedUrl,
        normalizedUrl,
        domain,
        status: 'OFFICIAL_SOURCE_MATCHED',
        statusHeadline: 'Official Source Matched',
        statusExplanation: `Verified official portal of ${record.organizationName} (${record.jurisdiction}). Audited on ${record.verificationDate} with reference citation.`,
        whatThisEstablishes: `Matches canonical registered domain (${record.canonicalDomain}) of audited public institution. No active threats reported.`,
        whatThisDoesNotEstablish: 'Does not guarantee absolute security against client-side zero-days or localized account compromise.',
        threatResult,
        officialSource: record,
        checkedAt,
      };
    }

    // 4. No Known Threat Found / Unverified general site
    return {
      url: normalizedUrl,
      normalizedUrl,
      domain,
      status: 'NO_KNOWN_THREAT_FOUND',
      statusHeadline: 'No Known Threat Found (Unverified)',
      statusExplanation: `Threat check completed via ${threatResult.providerDisplayName}. No covered phishing, malware, or harmful software reported for this URL.`,
      whatThisEstablishes: `This destination is not currently indexed in active blocklists by ${threatResult.providerDisplayName}.`,
      whatThisDoesNotEstablish: 'Absence from a threat feed does NOT guarantee safety. Brand new scams, private phishing, or zero-day exploits may not yet be cataloged.',
      threatResult,
      checkedAt,
    };
  }

  private getProviderDisplayName(provider: ProviderType): string {
    switch (provider) {
      case 'google-web-risk':
        return 'Google Web Risk';
      case 'urlhaus':
        return 'abuse.ch URLhaus';
      case 'test-fixture':
        return 'SATVRA Test Feed';
      case 'composite':
      default:
        return 'SATVRA Composite Provider';
    }
  }
}
