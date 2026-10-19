/**
 * SATVRA Core Types & Status Definitions
 * Tagline: Trust What You Browse
 */

export type WebsiteStatus =
  | 'KNOWN_THREAT'
  | 'NO_KNOWN_THREAT_FOUND'
  | 'OFFICIAL_SOURCE_MATCHED'
  | 'UNVERIFIED'
  | 'CHECK_UNAVAILABLE'
  | 'CONFLICTING_SIGNALS';

export type ThreatType =
  | 'MALWARE'
  | 'SOCIAL_ENGINEERING' // Phishing
  | 'UNWANTED_SOFTWARE'
  | 'POTENTIALLY_HARMFUL_APPLICATION'
  | 'COMMAND_AND_CONTROL';

export type ProviderType =
  | 'google-web-risk'
  | 'urlhaus'
  | 'test-fixture'
  | 'local-dnr'
  | 'composite';

export interface ThreatCheckResult {
  url: string;
  normalizedUrl: string;
  domain: string;
  isThreat: boolean;
  threatTypes: ThreatType[];
  provider: ProviderType;
  providerDisplayName: string;
  checkedAt: string;
  latencyMs: number;
  cacheTtlSeconds: number;
  evidenceCategory?: string;
  rawDetails?: string;
  isCached?: boolean;
  error?: string;
}

export type ReviewStatus = 'VERIFIED' | 'MONITORED' | 'PENDING_AUDIT';

export interface OfficialSourceRecord {
  id: string;
  canonicalDomain: string; // e.g. "irs.gov", "gov.uk"
  organizationName: string;
  jurisdiction: string; // e.g. "United States (Federal)", "United Kingdom", "California"
  category: 'GOVERNMENT' | 'TAX_REVENUE' | 'SOCIAL_SERVICES' | 'EDUCATION' | 'EMPLOYMENT' | 'HEALTH_POSTAL';
  authoritativeReferenceUrl: string; // Real authoritative reference documenting this domain
  verificationDate: string; // ISO Date of audit
  reviewStatus: ReviewStatus;
  description: string;
  tags: string[];
}

export interface WebsiteEvaluation {
  url: string;
  normalizedUrl: string;
  domain: string;
  status: WebsiteStatus;
  statusHeadline: string;
  statusExplanation: string;
  whatThisEstablishes: string;
  whatThisDoesNotEstablish: string;
  threatResult: ThreatCheckResult;
  officialSource?: OfficialSourceRecord;
  checkedAt: string;
  conflictingSignalDetails?: string;
}

export interface ExtensionSettings {
  activeProvider: ProviderType;
  enableDeclarativeBlocking: boolean;
  blockPhishing: boolean;
  blockMalware: boolean;
  blockUnwantedSoftware: boolean;
  localCacheTtlMinutes: number;
  anonymizeUrlLookups: boolean; // Strip query params & fragments
  allowlist: string[];
}
