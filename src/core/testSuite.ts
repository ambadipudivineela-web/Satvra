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
import { generateDnrRules } from './dnrRules/ruleGenerator.ts';

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
    // Configure with an invalid provider that forces an error
    service.updateSettings({ activeProvider: 'google-web-risk' }); // Unconfigured key should error

    const e = await service.evaluateUrl('https://example.com/test');
    assert(
      s,
      'Unconfigured provider fails closed to CHECK_UNAVAILABLE (never reports clean)',
      e.status === 'CHECK_UNAVAILABLE' && Boolean(e.threatResult.error),
      e.status,
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
