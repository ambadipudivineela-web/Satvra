/**
 * SATVRA Web Search Engine Service
 * 
 * General-purpose web search engine with transparent trust and threat evaluation.
 * Searches broadly across the web for arbitrary queries (Python tutorials, YouTube,
 * SQL interview questions, news, etc.), prioritizes verified official sources when relevant,
 * and attaches evidence-based security evaluations to every destination.
 */

import { SearchResponse, SearchResultItem, TrustState } from './types.ts';
import { ThreatEvaluationService } from '../threatIntel/threatService.ts';
import { matchOfficialDomain, searchOfficialSources } from '../officialSources/matcher.ts';
import { normalizeUrl } from '../urlNormalizer.ts';
import { understandQuery, QueryCorrectionResult } from './queryUnderstanding.ts';
import { validateSearchApiKey } from './apiKeyValidator.ts';

export interface SearchProviderConfig {
  braveApiKey?: string;
  serperApiKey?: string;
  tavilyApiKey?: string;
  bingApiKey?: string;
}

interface RawWebResult {
  title: string;
  url: string;
  snippet: string;
}

export class WebSearchService {
  constructor(
    private threatService: ThreatEvaluationService,
    private config: SearchProviderConfig = {}
  ) {}

  public updateConfig(newConfig: Partial<SearchProviderConfig>) {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Main general web search dispatcher with query understanding and typo tolerance
   */
  public async search(query: string): Promise<SearchResponse> {
    const startTime = Date.now();
    const cleanQuery = (query || '').trim();

    if (!cleanQuery) {
      return {
        query: '',
        provider: 'None',
        totalResults: 0,
        officialCount: 0,
        threatCount: 0,
        results: [],
        latencyMs: 0,
      };
    }

    // 0. Query Understanding & Typo Tolerance
    const analysis: QueryCorrectionResult = understandQuery(cleanQuery);
    // If query contains typos/misspellings (e.g. "pythn tutrial for begginers"),
    // search the corrected phrase so user receives high-relevance web results
    const effectiveQuery = analysis.hasTypoCorrection && analysis.correctedQuery
      ? analysis.correctedQuery
      : cleanQuery;

    const evaluatedResults: SearchResultItem[] = [];
    const seenDomains = new Set<string>();
    let searchProviderName = 'Live Web Index';
    let providerError: string | undefined;

    // 1. Official Directory High-Confidence Matching
    // If the query specifically relates to an official institution (e.g. IRS, FAFSA, Passport Office, DMV, WHO, CDC, USAJOBS),
    // prioritize the official portal at the top without hiding other general web results.
    const officialDirectoryMatches = searchOfficialSources(effectiveQuery);
    const relevantOfficialMatches = officialDirectoryMatches.matches.filter(m => m.score >= 60);

    for (const match of relevantOfficialMatches.slice(0, 2)) {
      const canonicalDomain = match.record.canonicalDomain;
      seenDomains.add(canonicalDomain.toLowerCase());
      const officialUrl = `https://${canonicalDomain}`;
      const evaluation = await this.threatService.evaluateUrl(officialUrl);

      evaluatedResults.push({
        id: `official-${match.record.id}`,
        title: `${match.record.organizationName} — Official Portal`,
        url: officialUrl,
        displayUrl: `https://${canonicalDomain}`,
        domain: canonicalDomain,
        snippet: `${match.record.description} (Audited on ${match.record.verificationDate} in jurisdiction: ${match.record.jurisdiction}). ${match.matchReason}.`,
        isOfficial: true,
        officialRecord: match.record,
        evaluation,
        trustState: 'OFFICIAL_SOURCE_VERIFIED',
        trustExplanation: `Audited institutional domain for ${match.record.organizationName} (${match.record.jurisdiction}). Authority citation verified on ${match.record.verificationDate}.`,
        rank: 1,
      });
    }

    // 2. Fetch general web search results using effective query from live index / configured APIs
    let rawWebResults: RawWebResult[] = [];
    try {
      const fetchResult = await this.fetchGeneralWebResults(effectiveQuery);
      rawWebResults = fetchResult.results;
      searchProviderName = fetchResult.provider;
    } catch (err: unknown) {
      providerError = (err as Error)?.message || 'General web index search request failed';
      console.warn('[SATVRA Search]', providerError);
    }

    // 3. Process and evaluate every returned web result
    for (let i = 0; i < rawWebResults.length; i++) {
      const item = rawWebResults[i];
      const normalized = normalizeUrl(item.url);
      if (!normalized.isValid) continue;

      const domain = normalized.canonicalDomain || normalized.hostname;

      // Avoid duplicate domains if already highlighted in official sources
      if (domain && seenDomains.has(domain.toLowerCase())) {
        continue;
      }
      if (domain) {
        seenDomains.add(domain.toLowerCase());
      }

      // Evaluate threat intelligence and official registry
      const evaluation = await this.threatService.evaluateUrl(item.url);
      const officialMatch = matchOfficialDomain(normalized.hostname);

      const isThreat = evaluation.status === 'KNOWN_THREAT';
      const isOfficial = officialMatch.matched;

      // Determine honest TrustState
      let trustState: TrustState = 'UNVERIFIED';
      let trustExplanation =
        'Checked against active threat feeds. No reported malware, phishing, or harmful software found. (Note: Absence from blocklists does not guarantee absolute safety; exercise standard caution).';

      if (isThreat) {
        trustState = 'KNOWN_THREAT';
        trustExplanation = `Active security threat detected: ${evaluation.threatResult.threatTypes.join(', ')}. Navigating to this destination is unsafe.`;
      } else if (isOfficial) {
        trustState = 'OFFICIAL_SOURCE_VERIFIED';
        trustExplanation = `Audited official domain of ${officialMatch.record?.organizationName} (${officialMatch.record?.jurisdiction}).`;
      } else if (evaluation.status === 'CHECK_UNAVAILABLE') {
        trustState = 'CHECK_UNAVAILABLE';
        trustExplanation = 'Security verification feed was unavailable. Never assume an unchecked site is safe.';
      }

      evaluatedResults.push({
        id: `web-${i + 1}`,
        title: item.title,
        url: item.url,
        displayUrl: normalized.normalizedUrlWithoutQuery || item.url,
        domain: domain || normalized.hostname,
        snippet: item.snippet,
        isOfficial,
        officialRecord: officialMatch.record,
        evaluation,
        trustState,
        trustExplanation,
        rank: evaluatedResults.length + 1,
      });
    }

    // 4. Relevance-First Ranking with Trust Signal Modulation
    const relevanceTokens = effectiveQuery
      .toLowerCase()
      .split(/\s+/)
      .filter((w) => w.length > 2);

    for (const item of evaluatedResults) {
      let score = 0;
      const titleLower = item.title.toLowerCase();
      const snippetLower = item.snippet.toLowerCase();
      const domainLower = item.domain.toLowerCase();

      for (const token of relevanceTokens) {
        if (titleLower.includes(token)) score += 35;
        if (domainLower.includes(token)) score += 25;
        if (snippetLower.includes(token)) score += 15;
      }

      // Additive trust boost: institutional sources get verified prominence
      if (item.isOfficial) {
        score += 40;
      } else if (item.domain.endsWith('.edu') || item.domain.endsWith('.org')) {
        score += 15;
      }

      // Demote active known threats below clean results
      if (item.evaluation.status === 'KNOWN_THREAT') {
        score -= 200;
      }

      (item as any).relevanceScore = score;
    }

    evaluatedResults.sort((a, b) => {
      const scoreA = (a as any).relevanceScore || 0;
      const scoreB = (b as any).relevanceScore || 0;
      if (scoreA !== scoreB) return scoreB - scoreA;
      return a.rank - b.rank;
    });

    evaluatedResults.forEach((r, idx) => {
      r.rank = idx + 1;
    });

    const officialCount = evaluatedResults.filter((r) => r.isOfficial).length;
    const threatCount = evaluatedResults.filter((r) => r.evaluation.status === 'KNOWN_THREAT').length;
    const latencyMs = Math.max(1, Date.now() - startTime);

    return {
      query: cleanQuery,
      correctedQuery: analysis.correctedQuery,
      hasTypoCorrection: analysis.hasTypoCorrection,
      relatedQueries: analysis.relatedQueries,
      provider: searchProviderName,
      totalResults: evaluatedResults.length,
      officialCount,
      threatCount,
      results: evaluatedResults,
      error: evaluatedResults.length === 0 ? providerError : undefined,
      latencyMs,
    };
  }

  // Warn set to prevent duplicate console spam
  private static warnedProviders = new Set<string>();

  /**
   * Primary web search fetcher:
   * Validates configured API keys to prevent ByteString conversion errors,
   * routes to the top valid configured provider, and defaults to the robust Live Web Index.
   */
  private async fetchGeneralWebResults(query: string): Promise<{ results: RawWebResult[]; provider: string }> {
    // 1. Validate all configured API keys strictly before using in HTTP headers
    const braveVal = validateSearchApiKey('Brave', this.config.braveApiKey);
    const serperVal = validateSearchApiKey('Serper', this.config.serperApiKey);
    const tavilyVal = validateSearchApiKey('Tavily', this.config.tavilyApiKey);
    const bingVal = validateSearchApiKey('Bing', this.config.bingApiKey);

    // Report configuration / placeholder issues once in the server logs
    if (braveVal.isConfigured && !braveVal.isValid && !WebSearchService.warnedProviders.has('Brave')) {
      WebSearchService.warnedProviders.add('Brave');
      console.warn(`[SATVRA Search] BRAVE_SEARCH_API_KEY rejected: ${braveVal.error}`);
    }
    if (serperVal.isConfigured && !serperVal.isValid && !WebSearchService.warnedProviders.has('Serper')) {
      WebSearchService.warnedProviders.add('Serper');
      console.warn(`[SATVRA Search] SERPER_API_KEY rejected: ${serperVal.error}`);
    }
    if (tavilyVal.isConfigured && !tavilyVal.isValid && !WebSearchService.warnedProviders.has('Tavily')) {
      WebSearchService.warnedProviders.add('Tavily');
      console.warn(`[SATVRA Search] TAVILY_API_KEY rejected: ${tavilyVal.error}`);
    }
    if (bingVal.isConfigured && !bingVal.isValid && !WebSearchService.warnedProviders.has('Bing')) {
      WebSearchService.warnedProviders.add('Bing');
      console.warn(`[SATVRA Search] BING_SEARCH_API_KEY rejected: ${bingVal.error}`);
    }

    // 2. Use ONE configured provider first (Requirement 7)
    if (braveVal.isValid) {
      const braveResults = await this.fetchBraveSearch(query, this.config.braveApiKey!.trim());
      if (braveResults.length > 0) {
        return { results: braveResults, provider: 'Brave Web Search API' };
      }
    } else if (serperVal.isValid) {
      const serperResults = await this.fetchSerperSearch(query, this.config.serperApiKey!.trim());
      if (serperResults.length > 0) {
        return { results: serperResults, provider: 'Google Search (via Serper API)' };
      }
    } else if (tavilyVal.isValid) {
      const tavilyResults = await this.fetchTavilySearch(query, this.config.tavilyApiKey!.trim());
      if (tavilyResults.length > 0) {
        return { results: tavilyResults, provider: 'Tavily Web Search API' };
      }
    } else if (bingVal.isValid) {
      const bingResults = await this.fetchBingSearchApi(query, this.config.bingApiKey!.trim());
      if (bingResults.length > 0) {
        return { results: bingResults, provider: 'Bing Web Search API' };
      }
    }

    // 3. Default zero-config Live Web Index (Bing RSS Feed)
    // Runs when no commercial keys are configured or when configured keys are placeholders
    try {
      const liveResults = await this.fetchBingRssResults(query);
      if (liveResults.length > 0) {
        return { results: liveResults, provider: 'Live Web Index (Bing Web Index)' };
      }
    } catch (err) {
      console.warn('[SATVRA Search] Live web index error:', (err as Error)?.message);
    }

    // 4. Supplementary Wikimedia Knowledge Index fallback
    try {
      const wikiResults = await this.fetchWikipediaSearch(query);
      if (wikiResults.length > 0) {
        return { results: wikiResults, provider: 'Wikimedia Global Knowledge Index' };
      }
    } catch (err) {
      console.warn('[SATVRA Search] Wikipedia index error:', (err as Error)?.message);
    }

    throw new Error(
      'Live web search index was temporarily unreachable. Check network connectivity or configure BRAVE_SEARCH_API_KEY with a valid token in environment variables.'
    );
  }

  /**
   * Brave Search API fetcher
   */
  private async fetchBraveSearch(query: string, apiKey: string): Promise<RawWebResult[]> {
    const endpoint = `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(query)}&count=12`;
    const res = await fetch(endpoint, {
      headers: {
        'Accept': 'application/json',
        'X-Subscription-Token': apiKey,
      },
      signal: AbortSignal.timeout(6000),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Brave Search API returned HTTP ${res.status}: ${errText || res.statusText}`);
    }

    const data = await res.json();
    const results: RawWebResult[] = [];
    if (data.web && Array.isArray(data.web.results)) {
      for (const item of data.web.results) {
        if (item.url && item.title) {
          results.push({
            title: item.title,
            url: item.url,
            snippet: item.description || '',
          });
        }
      }
    }
    return results;
  }

  /**
   * Serper Google Search API fetcher
   */
  private async fetchSerperSearch(query: string, apiKey: string): Promise<RawWebResult[]> {
    const res = await fetch('https://google.serper.dev/search', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-KEY': apiKey,
      },
      body: JSON.stringify({ q: query, num: 12 }),
      signal: AbortSignal.timeout(6000),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Serper API returned HTTP ${res.status}: ${errText || res.statusText}`);
    }

    const data = await res.json();
    const results: RawWebResult[] = [];
    if (Array.isArray(data.organic)) {
      for (const item of data.organic) {
        if (item.link && item.title) {
          results.push({
            title: item.title,
            url: item.link,
            snippet: item.snippet || '',
          });
        }
      }
    }
    return results;
  }

  /**
   * Tavily Search API fetcher
   */
  private async fetchTavilySearch(query: string, apiKey: string): Promise<RawWebResult[]> {
    const res = await fetch('https://api.tavily.com/search', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({ query, max_results: 12 }),
      signal: AbortSignal.timeout(6000),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Tavily API returned HTTP ${res.status}: ${errText || res.statusText}`);
    }

    const data = await res.json();
    const results: RawWebResult[] = [];
    if (Array.isArray(data.results)) {
      for (const item of data.results) {
        if (item.url && item.title) {
          results.push({
            title: item.title,
            url: item.url,
            snippet: item.content || '',
          });
        }
      }
    }
    return results;
  }

  /**
   * Bing Search API fetcher
   */
  private async fetchBingSearchApi(query: string, apiKey: string): Promise<RawWebResult[]> {
    const endpoint = `https://api.bing.microsoft.com/v7.0/search?q=${encodeURIComponent(query)}&count=12&mkt=en-US`;
    const res = await fetch(endpoint, {
      headers: {
        'Ocp-Apim-Subscription-Key': apiKey,
        'Accept': 'application/json',
      },
      signal: AbortSignal.timeout(6000),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Bing Search API returned HTTP ${res.status}: ${errText || res.statusText}`);
    }

    const data = await res.json();
    const results: RawWebResult[] = [];
    if (data.webPages?.value && Array.isArray(data.webPages.value)) {
      for (const item of data.webPages.value) {
        if (item.url && item.name) {
          results.push({
            title: item.name,
            url: item.url,
            snippet: item.snippet || '',
          });
        }
      }
    }
    return results;
  }

  /**
   * Live Web Index (Bing RSS Feed)
   * High-reliability, structured web search results for arbitrary queries across all servers.
   */
  private async fetchBingRssResults(query: string): Promise<RawWebResult[]> {
    const url = `https://www.bing.com/search?q=${encodeURIComponent(query)}&format=rss&mkt=en-US&setlang=en-US&cc=US`;
    const res = await fetch(url, {
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
        'Accept': 'application/rss+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
      },
      signal: AbortSignal.timeout(6000),
    });

    if (!res.ok) {
      throw new Error(`Web index returned HTTP ${res.status}`);
    }

    const xml = await res.text();
    return this.parseBingRssXml(xml);
  }

  private parseBingRssXml(xml: string): RawWebResult[] {
    const results: RawWebResult[] = [];
    const items = xml.split('<item>');

    for (let i = 1; i < items.length; i++) {
      const item = items[i];
      const rawTitle = item.match(/<title>([\s\S]*?)<\/title>/)?.[1] || '';
      const rawLink = item.match(/<link>([\s\S]*?)<\/link>/)?.[1] || '';
      const rawDesc = item.match(/<description>([\s\S]*?)<\/description>/)?.[1] || '';

      const title = this.decodeHtmlEntities(rawTitle.replace(/<[^>]+>/g, '').trim());
      const url = this.decodeHtmlEntities(rawLink.trim());
      const snippet = this.decodeHtmlEntities(rawDesc.replace(/<[^>]+>/g, '').trim());

      if (url.startsWith('http://') || url.startsWith('https://')) {
        results.push({
          title: title || url,
          url,
          snippet,
        });
      }
    }

    return results;
  }

  /**
   * Wikipedia Knowledge Search Fallback
   */
  private async fetchWikipediaSearch(query: string): Promise<RawWebResult[]> {
    const url = `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(
      query
    )}&format=json&utf8=1&srlimit=8`;
    const res = await fetch(url, {
      headers: {
        'User-Agent': 'SATVRA-Search/1.0 (info@satvra.local)',
      },
      signal: AbortSignal.timeout(4000),
    });

    if (!res.ok) return [];

    const data = await res.json();
    const results: RawWebResult[] = [];
    if (data.query && Array.isArray(data.query.search)) {
      for (const item of data.query.search) {
        results.push({
          title: item.title,
          url: `https://en.wikipedia.org/wiki/${encodeURIComponent(item.title.replace(/\s+/g, '_'))}`,
          snippet: this.decodeHtmlEntities(item.snippet.replace(/<[^>]+>/g, '').trim()),
        });
      }
    }
    return results;
  }

  private decodeHtmlEntities(str: string): string {
    return str
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&#x27;/g, "'")
      .replace(/&nbsp;/g, ' ');
  }
}
