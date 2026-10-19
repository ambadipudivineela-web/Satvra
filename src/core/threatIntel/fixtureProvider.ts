/**
 * SATVRA Certified Harmless Security Test Fixture Provider
 * 
 * Contains harmless deterministic fixtures for testing threat detection,
 * navigation blocking, and interstitial warning flows without navigating to
 * real live malicious infrastructure.
 */

import { ThreatIntelProvider } from './adapter.ts';
import { ThreatCheckResult, ThreatType } from '../types.ts';
import { normalizeUrl } from '../urlNormalizer.ts';

interface FixtureEntry {
  threatTypes: ThreatType[];
  evidenceCategory: string;
  rawDetails: string;
}

const HARMLESS_FIXTURE_DATABASE: Record<string, FixtureEntry> = {
  // Certified Google Safe Browsing / Web Risk harmless test URLs
  'testsafebrowsing.appspot.com/s/phishing.html': {
    threatTypes: ['SOCIAL_ENGINEERING'],
    evidenceCategory: 'Verified Harmless Phishing Test Harness',
    rawDetails: 'Reported in threat dataset: Simulated banking credential harvesting page',
  },
  'testsafebrowsing.appspot.com/s/malware.html': {
    threatTypes: ['MALWARE'],
    evidenceCategory: 'Verified Harmless Malware Test Harness',
    rawDetails: 'Reported in threat dataset: Simulated binary exploit dropper',
  },
  'testsafebrowsing.appspot.com/s/unwanted.html': {
    threatTypes: ['UNWANTED_SOFTWARE'],
    evidenceCategory: 'Verified Harmless Unwanted Software Test Harness',
    rawDetails: 'Reported in threat dataset: Bundled browser hijacker payload',
  },

  // SATVRA Internal deterministic test fixtures
  'malware-test.satvra.local/phishing': {
    threatTypes: ['SOCIAL_ENGINEERING'],
    evidenceCategory: 'Deterministic SATVRA Phishing Fixture',
    rawDetails: 'Simulated deceptive government login credential capture',
  },
  'malware-test.satvra.local/malware': {
    threatTypes: ['MALWARE'],
    evidenceCategory: 'Deterministic SATVRA Malware Fixture',
    rawDetails: 'Simulated executable payload distribution',
  },
  'malware-test.satvra.local/unwanted': {
    threatTypes: ['UNWANTED_SOFTWARE'],
    evidenceCategory: 'Deterministic SATVRA Unwanted Software Fixture',
    rawDetails: 'Simulated deceptive utility download bundle',
  },
  'phish-irs-refund.fake-tax-portal.com': {
    threatTypes: ['SOCIAL_ENGINEERING'],
    evidenceCategory: 'Documented IRS Phishing Campaign Pattern',
    rawDetails: 'Impersonating IRS tax refund portal with deceptive form capture',
  },
  'usps-reschedule-delivery-alert.net': {
    threatTypes: ['SOCIAL_ENGINEERING'],
    evidenceCategory: 'Documented Postal Smishing/Phishing Lure',
    rawDetails: 'Deceptive postal package reschedule notification capturing credit cards',
  },
};

export class FixtureThreatProvider implements ThreatIntelProvider {
  public readonly id = 'test-fixture';
  public readonly displayName = 'SATVRA Deterministic Security Test Feed';

  public isConfigured(): boolean {
    return true;
  }

  public async checkUrl(normalizedUrl: string): Promise<ThreatCheckResult> {
    const startTime = Date.now();
    const parsed = normalizeUrl(normalizedUrl);

    // Build matching keys: full normalized (without protocol), hostname + path, and hostname alone
    const hostAndPath = (parsed.hostname + parsed.pathname).replace(/\/$/, '');
    const hostOnly = parsed.hostname;

    let match: FixtureEntry | undefined = HARMLESS_FIXTURE_DATABASE[hostAndPath];
    if (!match) {
      match = HARMLESS_FIXTURE_DATABASE[hostOnly];
    }

    const latencyMs = Math.max(1, Date.now() - startTime);

    if (match) {
      return {
        url: normalizedUrl,
        normalizedUrl: parsed.normalizedUrl,
        domain: parsed.canonicalDomain || parsed.hostname,
        isThreat: true,
        threatTypes: match.threatTypes,
        provider: 'test-fixture',
        providerDisplayName: this.displayName,
        checkedAt: new Date().toISOString(),
        latencyMs,
        cacheTtlSeconds: 300,
        evidenceCategory: match.evidenceCategory,
        rawDetails: match.rawDetails,
      };
    }

    return {
      url: normalizedUrl,
      normalizedUrl: parsed.normalizedUrl,
      domain: parsed.canonicalDomain || parsed.hostname,
      isThreat: false,
      threatTypes: [],
      provider: 'test-fixture',
      providerDisplayName: this.displayName,
      checkedAt: new Date().toISOString(),
      latencyMs,
      cacheTtlSeconds: 900,
    };
  }
}
