/**
 * SATVRA Web Search Engine Service
 * 
 * Executes real web searches, prioritizes audited official public sources,
 * and attaches verified threat-intelligence evaluations to each destination.
 */

import { SearchResponse, SearchResultItem } from './types.ts';
import { ThreatEvaluationService } from '../threatIntel/threatService.ts';
import { matchOfficialDomain, searchOfficialSources } from '../officialSources/matcher.ts';
import { normalizeUrl } from '../urlNormalizer.ts';

export class WebSearchService {
  constructor(private threatService: ThreatEvaluationService) {}

  /**
   * Main search dispatcher
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

    const evaluatedResults: SearchResultItem[] = [];
    const seenDomains = new Set<string>();
    let searchProviderName = 'DuckDuckGo Web Index';
    let providerError: string | undefined;

    // 1. Official Source Matching (Strict Audited Directory Search)
    const officialDirectoryMatches = searchOfficialSources(cleanQuery);
    for (const match of officialDirectoryMatches.matches.slice(0, 3)) {
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
        rank: 1,
      });
    }

    // 2. Fetch raw web results from live web search engine
    try {
      const rawWebResults = await this.fetchDuckDuckGoResults(cleanQuery);

      for (let i = 0; i < rawWebResults.length; i++) {
        const item = rawWebResults[i];
        const normalized = normalizeUrl(item.url);
        const domain = normalized.canonicalDomain || normalized.hostname;

        // Skip if this exact domain was already included in the top official highlights
        if (domain && seenDomains.has(domain.toLowerCase())) {
          continue;
        }
        if (domain) {
          seenDomains.add(domain.toLowerCase());
        }

        // Evaluate threat and official status
        const evaluation = await this.threatService.evaluateUrl(item.url);
        const officialMatch = matchOfficialDomain(normalized.hostname);

        evaluatedResults.push({
          id: `web-${i + 1}`,
          title: item.title,
          url: item.url,
          displayUrl: normalized.normalizedUrlWithoutQuery || item.url,
          domain: domain || normalized.hostname,
          snippet: item.snippet,
          isOfficial: officialMatch.matched,
          officialRecord: officialMatch.record,
          evaluation,
          rank: evaluatedResults.length + 1,
        });
      }
    } catch (err: unknown) {
      providerError = (err as Error)?.message || 'Web index search timed out';
      searchProviderName = 'SATVRA Civic Directory (External Web Index Offline)';
    }

    // 3. Sort: Prioritize audited official sources first, followed by clean unverified, placing known threats with distinct warning
    evaluatedResults.sort((a, b) => {
      if (a.isOfficial && !b.isOfficial) return -1;
      if (!a.isOfficial && b.isOfficial) return 1;
      if (a.evaluation.status === 'KNOWN_THREAT' && b.evaluation.status !== 'KNOWN_THREAT') return 1;
      if (a.evaluation.status !== 'KNOWN_THREAT' && b.evaluation.status === 'KNOWN_THREAT') return -1;
      return a.rank - b.rank;
    });

    const officialCount = evaluatedResults.filter((r) => r.isOfficial).length;
    const threatCount = evaluatedResults.filter((r) => r.evaluation.status === 'KNOWN_THREAT').length;
    const latencyMs = Math.max(1, Date.now() - startTime);

    return {
      query: cleanQuery,
      provider: searchProviderName,
      totalResults: evaluatedResults.length,
      officialCount,
      threatCount,
      results: evaluatedResults,
      error: evaluatedResults.length === 0 ? providerError : undefined,
      latencyMs,
    };
  }

  /**
   * Fetches real web results from DuckDuckGo HTML endpoint
   */
  private async fetchDuckDuckGoResults(query: string): Promise<Array<{ title: string; url: string; snippet: string }>> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 6000);

    try {
      const response = await fetch(
        `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`,
        {
          headers: {
            'User-Agent':
              'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
          },
          signal: controller.signal,
        }
      );

      clearTimeout(timer);

      if (!response.ok) {
        throw new Error(`Search provider returned HTTP ${response.status}`);
      }

      const html = await response.text();
      return this.parseDuckDuckGoHtml(html);
    } catch (err: unknown) {
      clearTimeout(timer);
      const isAbort = (err as Error)?.name === 'AbortError';
      throw new Error(isAbort ? 'Search request timed out after 6 seconds.' : ((err as Error)?.message || 'Network error'));
    }
  }

  private parseDuckDuckGoHtml(html: string): Array<{ title: string; url: string; snippet: string }> {
    const results: Array<{ title: string; url: string; snippet: string }> = [];
    const resultBlocks = html.split('class="result results_links');

    for (let i = 1; i < resultBlocks.length; i++) {
      const block = resultBlocks[i];
      const headingMatch = block.match(
        /<h2[^>]*>[\s\S]*?<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>[\s\S]*?<\/h2>/i
      );
      const snippetMatch = block.match(/<a[^>]+class=["']result__snippet["'][^>]*>([\s\S]*?)<\/a>/i);

      if (headingMatch) {
        let rawHref = headingMatch[1];
        let cleanUrl = rawHref;

        // Decode DuckDuckGo redirection link (//duckduckgo.com/l/?uddg=...)
        if (rawHref.includes('uddg=')) {
          try {
            const rawPart = rawHref.split('uddg=')[1].split('&')[0];
            cleanUrl = decodeURIComponent(rawPart);
          } catch {
            cleanUrl = rawHref;
          }
        }

        if (cleanUrl.startsWith('//')) {
          cleanUrl = 'https:' + cleanUrl;
        }

        const title = this.decodeHtmlEntities(headingMatch[2].replace(/<[^>]+>/g, '').trim());
        const snippet = snippetMatch
          ? this.decodeHtmlEntities(snippetMatch[1].replace(/<[^>]+>/g, '').trim())
          : '';

        if (cleanUrl.startsWith('http://') || cleanUrl.startsWith('https://')) {
          results.push({
            title: title || cleanUrl,
            url: cleanUrl,
            snippet,
          });
        }
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
