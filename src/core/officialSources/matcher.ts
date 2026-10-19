/**
 * SATVRA Official Sources Matcher & Search Engine
 * 
 * Enforces strict domain hierarchy matching:
 * - A subdomain of a verified official domain (e.g. "sa.www4.irs.gov") MATCHES "irs.gov".
 * - A deceptive subdomain (e.g. "irs.gov.attacker-domain.com") DOES NOT MATCH "irs.gov".
 */

import { OfficialSourceRecord } from '../types.ts';
import { OFFICIAL_SOURCES_DIRECTORY } from './directory.ts';
import { extractCanonicalDomain } from '../urlNormalizer.ts';

export interface OfficialMatchResult {
  matched: boolean;
  record?: OfficialSourceRecord;
  matchType?: 'EXACT_DOMAIN' | 'OFFICIAL_SUBDOMAIN';
  explanation: string;
}

export interface OfficialSearchResult {
  query: string;
  totalResults: number;
  matches: Array<{
    record: OfficialSourceRecord;
    score: number;
    matchReason: string;
  }>;
}

/**
 * Checks whether a given hostname is a legitimate official source or a valid subdomain thereof.
 */
export function matchOfficialDomain(hostname: string): OfficialMatchResult {
  if (!hostname) {
    return {
      matched: false,
      explanation: 'No hostname provided for evaluation.',
    };
  }

  const cleanHost = hostname.toLowerCase().trim().replace(/\.+$/, '');
  const canonical = extractCanonicalDomain(cleanHost);

  // Search through directory for matching canonical domain
  for (const record of OFFICIAL_SOURCES_DIRECTORY) {
    const target = record.canonicalDomain.toLowerCase();

    // Exact match (e.g., "irs.gov" === "irs.gov")
    if (cleanHost === target) {
      return {
        matched: true,
        record,
        matchType: 'EXACT_DOMAIN',
        explanation: `Exact match for verified official source: ${record.organizationName} (${record.jurisdiction}). Audited on ${record.verificationDate}.`,
      };
    }

    // Official subdomain match (e.g., "sa.www4.irs.gov" ends with ".irs.gov")
    if (cleanHost.endsWith('.' + target)) {
      return {
        matched: true,
        record,
        matchType: 'OFFICIAL_SUBDOMAIN',
        explanation: `Valid official subdomain of ${record.canonicalDomain} (${record.organizationName}). Jurisdiction: ${record.jurisdiction}.`,
      };
    }
  }

  return {
    matched: false,
    explanation: `Domain "${canonical || cleanHost}" is not listed in SATVRA's audited official directory.`,
  };
}

/**
 * Discovers and ranks official sources matching user keywords (e.g. "tax refund", "fafsa", "driver license").
 */
export function searchOfficialSources(query: string): OfficialSearchResult {
  if (!query || !query.trim()) {
    return {
      query: '',
      totalResults: 0,
      matches: [],
    };
  }

  // Split on whitespace, underscores, hyphens, and commas so queries like government_jobs match
  const terms = query.toLowerCase().trim().split(/[\s_+,-]+/).filter(Boolean);
  const results: Array<{ record: OfficialSourceRecord; score: number; matchReason: string }> = [];

  for (const record of OFFICIAL_SOURCES_DIRECTORY) {
    let score = 0;
    const reasons: string[] = [];

    const orgLower = record.organizationName.toLowerCase();
    const domainLower = record.canonicalDomain.toLowerCase();
    const descLower = record.description.toLowerCase();
    const jurLower = record.jurisdiction.toLowerCase();
    const tagsLower = record.tags.map((t) => t.toLowerCase());

    for (const term of terms) {
      if (domainLower.includes(term)) {
        score += 50;
        reasons.push(`Domain contains "${term}"`);
      }
      if (orgLower.includes(term)) {
        score += 30;
        reasons.push(`Organization name matches "${term}"`);
      }
      if (tagsLower.some((tag) => tag.includes(term))) {
        score += 25;
        reasons.push(`Keyword topic matches "${term}"`);
      }
      if (descLower.includes(term)) {
        score += 10;
        reasons.push(`Service scope matches "${term}"`);
      }
      if (jurLower.includes(term)) {
        score += 15;
        reasons.push(`Jurisdiction matches "${term}"`);
      }
    }

    if (score > 0) {
      results.push({
        record,
        score,
        matchReason: reasons.slice(0, 2).join('; ') || 'Matched keywords',
      });
    }
  }

  // Sort by highest score first
  results.sort((a, b) => b.score - a.score);

  return {
    query,
    totalResults: results.length,
    matches: results,
  };
}
