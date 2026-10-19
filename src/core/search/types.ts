/**
 * SATVRA Search Service Types
 */

import { WebsiteEvaluation, OfficialSourceRecord } from '../types.ts';

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
  rank: number;
}

export interface SearchResponse {
  query: string;
  provider: string;
  totalResults: number;
  officialCount: number;
  threatCount: number;
  results: SearchResultItem[];
  error?: string;
  latencyMs: number;
}
