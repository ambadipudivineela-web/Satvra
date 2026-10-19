/**
 * SATVRA Threat Intelligence Provider Adapter Interface
 */

import { ThreatCheckResult } from '../types.ts';

export interface ThreatIntelProvider {
  readonly id: string;
  readonly displayName: string;
  isConfigured(): boolean;
  checkUrl(normalizedUrl: string): Promise<ThreatCheckResult>;
}

export class ThreatProviderError extends Error {
  constructor(
    public readonly provider: string,
    message: string,
    public readonly isTransient: boolean = true,
    public readonly statusCode?: number
  ) {
    super(`[${provider}] ${message}`);
    this.name = 'ThreatProviderError';
  }
}
