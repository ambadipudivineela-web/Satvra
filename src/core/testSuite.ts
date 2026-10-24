/**
 * SATVRA Automated Verification Test Suite
 * 
 * Verifies core security invariants:
 * - URL normalization & user-info stripping
 * - Homograph & Punycode detection
 * - Deceptive subdomain defense
 * - 6-state explainable status classification
 * - Fail-closed error handling (never report clean on failure)
 * - DNR dynamic rule generation
 * - Official source citations and keyword ranking
 */

import { normalizeUrl, extractCanonicalDomain } from './urlNormalizer.ts';
import { matchOfficialDomain, searchOfficialSources } from './officialSources/matcher.ts';
import { ThreatEvaluationService } from './threatIntel/threatService.ts';
import { GoogleWebRiskProvider } from './threatIntel/googleWebRiskProvider.ts';
import { generateDnrRules } from './dnrRules/ruleGenerator.ts';
import { WebSearchService } from './search/searchService.ts';
import { validateSearchApiKey } from './search/apiKeyValidator.ts';
import { understandQuery } from './search/queryUnderstanding.ts';

export interface TestCaseResult {
  suite: string;
  name: string;
  passed: boolean;
  actual?: unknown;
  expected?: unknown;
  durationMs: number;
  error?: string;
}

export interface TestSuiteSummary {
  timestamp: string;
  total: number;
  passed: number;
  failed: number;
  durationMs: number;
  tests: TestCaseResult[];
}

export async function runAllTests(): Promise<TestSuiteSummary> {
  const startTime = Date.now();
  const tests: TestCaseResult[] = [];

  function assert(suite: string, name: string, condition: boolean, actual?: unknown, expected?: unknown) {
    tests.push({
      suite,
      name,
      passed: Boolean(condition),
      actual,
      expected,
      durationMs: 1,
      error: condition ? undefined : `Assertion failed: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    });
  }

  // --- Suite 1: URL Normalization & Sanitization ---
  {
    const s = 'URL Normalization';
    // 1. Basic https scheme
    const r1 = normalizeUrl('https://example.com/path?foo=bar#hash');
    assert(s, 'Normalizes basic HTTPS URL', r1.isValid && r1.hostname === 'example.com' && r1.pathname === '/path', r1.hostname, 'example.com');

    // 2. Strips userinfo trick (https://irs.gov@evil.com)
    const r2 = normalizeUrl('https://irs.gov@evil.com/login');
    assert(s, 'Detects and neutralizes user-info trick', r2.hasUserInfoTrick && r2.hostname === 'evil.com', { hasUserInfo: r2.hasUserInfoTrick, host: r2.hostname }, { hasUserInfo: true, host: 'evil.com' });

    // 3. Normalizes port 443 and 80
    const r3 = normalizeUrl('https://example.com:443/page');
    assert(s, 'Strips default HTTPS port 443', r3.normalizedUrl === 'https://example.com/page', r3.normalizedUrl, 'https://example.com/page');

    // 4. Punycode detection
    const r4 = normalizeUrl('https://xn--pple-43d.com');
    assert(s, 'Identifies Punycode domain', r4.isPunycode && r4.hasHomographRisk, r4.isPunycode, true);

    // 5. Strips query params for anonymized lookups
    const r5 = normalizeUrl('https://bank.com/transfer?account=123&token=secret');
    assert(s, 'Produces anonymized URL without query string', r5.normalizedUrlWithoutQuery === 'https://bank.com/transfer', r5.normalizedUrlWithoutQuery, 'https://bank.com/transfer');

    // 6. Multi-part public suffix extraction (.gov.uk)
    const c1 = extractCanonicalDomain('hmrc.tax.service.gov.uk');
    assert(s, 'Extracts multi-part public suffix canonical domain (.gov.uk)', c1 === 'service.gov.uk', c1, 'service.gov.uk');

    // 7. Differentiates natural search term (government_jobs) from URL
    const r7 = normalizeUrl('government_jobs');
    assert(
      s,
      'Identifies search term "government_jobs" without malformed URL crash',
      !r7.isValid && Boolean(r7.error?.includes('search query rather than a complete website URL')),
      Boolean(r7.error?.includes('search query')),
      true
    );

    // 8. Differentiates natural multi-word search phrase from URL
    const r8 = normalizeUrl('official government job notifications');
    assert(
      s,
      'Identifies multi-word search phrase without malformed URL crash',
      !r8.isValid && Boolean(r8.error?.includes('search query')),
      Boolean(r8.error?.includes('search query')),
      true
    );
  }

  // --- Suite 2: Deceptive Subdomain & Official Source Defense ---
  {
    const s = 'Official Source Defense';
    // 1. Exact official match
    const m1 = matchOfficialDomain('irs.gov');
    assert(s, 'Exact domain matches audited official record (irs.gov)', m1.matched && m1.record?.id === 'gov-us-irs', m1.matched, true);

    // 2. Legitimate official subdomain
    const m2 = matchOfficialDomain('sa.www4.irs.gov');
    assert(s, 'Legitimate subdomain of irs.gov matches', m2.matched && m2.matchType === 'OFFICIAL_SUBDOMAIN', m2.matched, true);

    // 3. Deceptive subdomain spoofing attempt (irs.gov.attacker-domain.com)
    const m3 = matchOfficialDomain('irs.gov.attacker-domain.com');
    assert(s, 'Deceptive spoof subdomain irs.gov.attacker.com is REJECTED', !m3.matched, m3.matched, false);

    // 4. Keyword search returns relevant verified official portal
    const s1 = searchOfficialSources('fafsa');
    assert(s1.matches.length > 0 ? s : s, 'Official search for "fafsa" finds studentaid.gov', s1.matches[0]?.record.canonicalDomain === 'studentaid.gov', s1.matches[0]?.record.canonicalDomain, 'studentaid.gov');
  }

  // --- Suite 3: Explainable Threat Classification ---
  {
    const s = 'Threat Classification';
    const service = new ThreatEvaluationService();
    service.updateSettings({ activeProvider: 'test-fixture' });

    // 1. Deterministic Known Threat (Harmless Fixture)
    const e1 = await service.evaluateUrl('https://malware-test.satvra.local/phishing');
    assert(s, 'Deterministic phishing fixture yields KNOWN_THREAT', e1.status === 'KNOWN_THREAT' && e1.threatResult.threatTypes.includes('SOCIAL_ENGINEERING'), e1.status, 'KNOWN_THREAT');

    // 2. Official Source (IRS)
    const e2 = await service.evaluateUrl('https://irs.gov/refunds');
    assert(s, 'Audited official portal yields OFFICIAL_SOURCE_MATCHED', e2.status === 'OFFICIAL_SOURCE_MATCHED' && Boolean(e2.officialSource), e2.status, 'OFFICIAL_SOURCE_MATCHED');

    // 3. Unverified General Domain
    const e3 = await service.evaluateUrl('https://ordinary-independent-site.org/index.html');
    assert(s, 'Unknown domain with no threat yields NO_KNOWN_THREAT_FOUND', e3.status === 'NO_KNOWN_THREAT_FOUND', e3.status, 'NO_KNOWN_THREAT_FOUND');

    // 4. Malformed Input
    const e4 = await service.evaluateUrl('javascript:alert(1)');
    assert(s, 'Unsafe scheme yields CHECK_UNAVAILABLE', e4.status === 'CHECK_UNAVAILABLE', e4.status, 'CHECK_UNAVAILABLE');
  }

  // --- Suite 4: Fail-Closed Provider Integrity ---
  {
    const s = 'Fail-Closed Behavior';
    const service = new ThreatEvaluationService();
    // Configure with an unconfigured provider that forces an error
    service.updateSettings({ activeProvider: 'google-web-risk' }); // Unconfigured key should error

    const e = await service.evaluateUrl('https://example.com/test');
    assert(
      s,
      'Unconfigured provider fails closed to CHECK_UNAVAILABLE (never reports clean)',
      e.status === 'CHECK_UNAVAILABLE' && Boolean(e.threatResult.error),
      e.status,
      'CHECK_UNAVAILABLE'
    );

    // Verify key format validator rejects placeholders like "Your api key" and "MY_KEY"
    const isPlaceholderValid = GoogleWebRiskProvider.isValidGoogleApiKey('Your api key');
    assert(s, 'Rejects placeholder "Your api key" as invalid key format', !isPlaceholderValid, isPlaceholderValid, false);

    const isMyKeyValid = GoogleWebRiskProvider.isValidGoogleApiKey('MY_KEY');
    assert(s, 'Rejects "MY_KEY" as invalid key format', !isMyKeyValid, isMyKeyValid, false);

    // Verify key format validator accepts standard Google API key format (AIzaSy...)
    const mockGoogleKey = 'AIza' + '0123456789abcdefghijklmnopqrstuvwxy';
    const isValidFormat = GoogleWebRiskProvider.isValidGoogleApiKey(mockGoogleKey);
    assert(s, 'Accepts valid Google Cloud API key format (AIza...)', isValidFormat, isValidFormat, true);

    // Verify service instantiated with placeholder key fails closed and reports unconfigured
    const serviceWithPlaceholder = new ThreatEvaluationService('Your api key');
    assert(s, 'hasValidWebRiskKey returns false for placeholder key', !serviceWithPlaceholder.hasValidWebRiskKey(), serviceWithPlaceholder.hasValidWebRiskKey(), false);

    serviceWithPlaceholder.updateSettings({ activeProvider: 'google-web-risk' });
    const e2 = await serviceWithPlaceholder.evaluateUrl('https://example.com/test');
    assert(
      s,
      'Service with placeholder key fails closed to CHECK_UNAVAILABLE with actionable instructions',
      e2.status === 'CHECK_UNAVAILABLE' && Boolean(e2.threatResult.error?.includes('WEB_RISK_API_KEY')),
      e2.status,
      'CHECK_UNAVAILABLE'
    );
  }

  // --- Suite 5: DeclarativeNetRequest Dynamic Rules ---
  {
    const s = 'DNR Rule Generator';
    const domains = ['evil-phish.net', 'malware-drop.org'];
    const rules = generateDnrRules(domains);
    assert(s, 'Generates valid DNR redirect rules', rules.length === 2 && rules[0].action.type === 'redirect', rules.length, 2);
    assert(s, 'Rule redirects to warning.html with target param', Boolean(rules[0].action.redirect?.extensionPath?.includes('warning.html')), true, true);
  }

  // --- Suite 6: General Web Search & Trust Architecture ---
  {
    const s = 'General Web Search';
    const threatService = new ThreatEvaluationService();
    const searchService = new WebSearchService(threatService);

    // 1. General non-civic search returns real results
    const r1 = await searchService.search('Python tutorials');
    assert(s, 'Search for "Python tutorials" returns real web results', r1.results.length > 0, r1.results.length > 0, true);
    assert(s, 'Search results include valid http/https URLs', r1.results.every(r => r.url.startsWith('http://') || r.url.startsWith('https://')), true, true);
    assert(s, 'Search results include titles and snippets', r1.results.every(r => r.title.length > 0 && typeof r.snippet === 'string'), true, true);
    assert(s, 'Every search result has an evaluated trustState', r1.results.every(r => typeof r.trustState === 'string'), true, true);

    // 2. Search is not restricted to government/civic domains
    const nonGovResults = r1.results.filter(r => !r.domain.endsWith('.gov'));
    assert(s, 'Results include non-government web destinations', nonGovResults.length > 0, nonGovResults.length > 0, true);

    // 3. Official searches prioritize verified institutions
    const r2 = await searchService.search('official government job notifications');
    assert(s, 'Official queries prioritize verified official sources at rank 1', r2.officialCount > 0 && r2.results[0]?.isOfficial, true, true);
  }

  // --- Suite 7: Search Request Safety & ByteString Integrity ---
  {
    const s = 'Request Safety & ByteString Integrity';

    // 1. Rejection of Brave API key with Unicode em dash '—' (char 8212) at index 17
    const braveWithEmDash = 'Brave Search API — web search results';
    const braveRes = validateSearchApiKey('Brave', braveWithEmDash);
    assert(s, 'Rejects Brave API key containing Unicode em dash (8212 at index 17)', !braveRes.isValid && Boolean(braveRes.error?.includes('8212')), !braveRes.isValid, true);

    // 2. Rejection of Serper API key with Unicode em dash '—' (char 8212) at index 7
    const serperWithEmDash = 'Serper — Google Search results through an API';
    const serperRes = validateSearchApiKey('Serper', serperWithEmDash);
    assert(s, 'Rejects Serper API key containing Unicode em dash (8212 at index 7)', !serperRes.isValid && Boolean(serperRes.error?.includes('8212')), !serperRes.isValid, true);

    // 3. Rejection of Tavily API key with Unicode em dash '—' (char 8212)
    const tavilyWithEmDash = 'Tavily — search designed for AI and research workflows';
    const tavilyRes = validateSearchApiKey('Tavily', tavilyWithEmDash);
    assert(s, 'Rejects Tavily API key containing Unicode em dash (8212)', !tavilyRes.isValid && Boolean(tavilyRes.error?.includes('8212')), !tavilyRes.isValid, true);

    // 4. Missing / undefined / empty keys reported as not configured without error
    const emptyRes = validateSearchApiKey('Brave', '');
    const undefRes = validateSearchApiKey('Brave', undefined);
    assert(s, 'Missing or empty key reports isConfigured: false', !emptyRes.isConfigured && !undefRes.isConfigured, true, true);

    // 5. Placeholder token names rejected
    const placeholderRes = validateSearchApiKey('Brave', 'your_api_key_here_12345');
    assert(s, 'Rejects "your_api_key_here" placeholder pattern', !placeholderRes.isValid, false, false);

    // 6. Valid ByteString-safe printable ASCII API key is accepted
    const validMockKey = 'BSA_live_9837429184719284721984712984';
    const validRes = validateSearchApiKey('Brave', validMockKey);
    assert(s, 'Accepts valid printable ASCII API key', validRes.isValid && validRes.isConfigured, true, true);

    // 7. ByteString safety invariant: Header construction with valid key does not throw TypeError
    let headerConstructionSuccess = false;
    try {
      const h = new Headers({ 'X-Subscription-Token': validMockKey });
      headerConstructionSuccess = h.get('X-Subscription-Token') === validMockKey;
    } catch {
      headerConstructionSuccess = false;
    }
    assert(s, 'Valid ASCII key passes Headers ByteString validation without TypeError', headerConstructionSuccess, true, true);

    // 8. ByteString safety invariant: Raw em dash key would throw TypeError if used in Headers
    let emDashThrowsByteStringError = false;
    try {
      new Headers({ 'X-Subscription-Token': braveWithEmDash });
    } catch (e: unknown) {
      emDashThrowsByteStringError = Boolean((e as Error)?.message?.includes('ByteString') || e instanceof TypeError);
    }
    assert(s, 'Confirms raw em dash in Headers triggers ByteString TypeError (root cause verification)', emDashThrowsByteStringError, true, true);

    // 9. Full Unicode queries (e.g. Telugu) preserved and encoded safely
    const teluguQuery = 'తెలుగు వార్తలు';
    const encodedTelugu = encodeURIComponent(teluguQuery);
    assert(s, 'Telugu query encodes cleanly without character loss', decodeURIComponent(encodedTelugu) === teluguQuery, true, true);

    // 10. Natural queries with symbols and punctuation handled without error
    const symbolQuery = 'C++ & Python: beginner to advanced?!';
    const encodedSymbols = encodeURIComponent(symbolQuery);
    assert(s, 'Punctuation and symbols encode safely for search query params', decodeURIComponent(encodedSymbols) === symbolQuery, true, true);

    // 11. Search service with placeholder em-dash keys falls back safely without ByteString crash
    const threatService = new ThreatEvaluationService();
    const resilientService = new WebSearchService(threatService, {
      braveApiKey: braveWithEmDash,
      serperApiKey: serperWithEmDash,
      tavilyApiKey: tavilyWithEmDash,
    });
    const fallbackSearchRes = await resilientService.search('Python tutorials');
    assert(s, 'SearchService gracefully bypasses invalid em-dash keys and succeeds via Live Web Index', fallbackSearchRes.results.length > 0 && !fallbackSearchRes.error, true, true);

    // 12. Typo correction correctly handles misspelled queries
    const typoAnalysis = understandQuery('pythn tutrial for begginers');
    assert(s, 'Typo understanding corrects "pythn tutrial for begginers" to "Python tutorial for beginners"', typoAnalysis.hasTypoCorrection && typoAnalysis.correctedQuery === 'Python tutorial for beginners', typoAnalysis.correctedQuery, 'Python tutorial for beginners');
  }

  const durationMs = Date.now() - startTime;
  const passed = tests.filter((t) => t.passed).length;
  const failed = tests.filter((t) => !t.passed).length;

  return {
    timestamp: new Date().toISOString(),
    total: tests.length,
    passed,
    failed,
    durationMs,
    tests,
  };
}
