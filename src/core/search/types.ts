/**
 * SATVRA Search Service Types
 */

import { WebsiteEvaluation, OfficialSourceRecord } from '../types.ts';

export type TrustState =
  | 'OFFICIAL_SOURCE_VERIFIED'
  | 'TRUST_EVIDENCE_AVAILABLE'
  | 'UNVERIFIED'
  | 'KNOWN_THREAT'
  | 'CHECK_UNAVAILABLE';

export interface SearchResultItem {
  id: string;
  title: string;
  url: string;
  displayUrl: string;
  domain: string;
  snippet: string;
  isOfficial: boolean;
  officialRecord?: OfficialSourceRecord;
  evaluation: WebsiteEvaluation;
  trustState: TrustState;
  trustExplanation: string;
  rank: number;
}

export interface SearchResponse {
  query: string;
  correctedQuery?: string;
  hasTypoCorrection?: boolean;
  relatedQueries?: string[];
  provider: string;
  totalResults: number;
  officialCount: number;
  threatCount: number;
  results: SearchResultItem[];
  error?: string;
  latencyMs: number;
}
