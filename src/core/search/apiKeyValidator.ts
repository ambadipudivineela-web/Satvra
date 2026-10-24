/**
 * SATVRA Search Provider API Key Validator
 * 
 * Validates search provider API keys before they are placed into HTTP headers.
 * Prevents ByteString conversion errors caused by non-ASCII characters (e.g. em dash '—' 8212),
 * smart quotes, spaces, or placeholder documentation text.
 * 
 * In accordance with RFC 7230 / RFC 9110 and the Fetch standard, HTTP header values
 * must be visible ASCII [0x21-0x7E]. Any character > 255 throws a ByteString TypeError in fetch().
 */

export interface ApiKeyValidationResult {
  isValid: boolean;
  isConfigured: boolean;
  error?: string;
}

export function validateSearchApiKey(provider: string, key?: string): ApiKeyValidationResult {
  if (!key || typeof key !== 'string') {
    return { isValid: false, isConfigured: false };
  }

  const trimmed = key.trim();
  if (trimmed.length === 0) {
    return { isValid: false, isConfigured: false };
  }

  // 1. Check for non-ASCII characters (including Unicode em dash '—' code 8212, smart quotes, etc.)
  for (let i = 0; i < trimmed.length; i++) {
    const code = trimmed.charCodeAt(i);
    if (code > 127) {
      return {
        isValid: false,
        isConfigured: true,
        error: `${provider} API key contains invalid non-ASCII character '${trimmed[i]}' (Unicode code point ${code}) at index ${i}. HTTP header values must be strictly printable ASCII.`,
      };
    }
  }

  // 2. Check for whitespace, tabs, or newlines
  if (/\s/.test(trimmed)) {
    return {
      isValid: false,
      isConfigured: true,
      error: `${provider} API key contains whitespace. API keys must be a single continuous token.`,
    };
  }

  // 3. Check for placeholder text, documentation descriptions, or accidental quotation marks
  if (
    trimmed.includes('—') ||
    trimmed.includes('–') ||
    /^(your[_\s-]?api|my[_\s-]?key|placeholder|todo|sample|demo|test_key)/i.test(trimmed) ||
    /["'«»“”‘’]/.test(trimmed) ||
    /\b(API|search|results|integration|credentials|documentation|supported)\b/i.test(trimmed)
  ) {
    return {
      isValid: false,
      isConfigured: true,
      error: `${provider} API key appears to contain placeholder or documentation text rather than an authentic API token.`,
    };
  }

  // 4. Must be strictly visible printable ASCII (ByteString safe: 0x21 to 0x7E)
  if (!/^[\x21-\x7E]+$/.test(trimmed)) {
    return {
      isValid: false,
      isConfigured: true,
      error: `${provider} API key contains characters outside the printable ASCII range.`,
    };
  }

  // 5. Minimum length check for commercial search keys
  if (trimmed.length < 15) {
    return {
      isValid: false,
      isConfigured: true,
      error: `${provider} API key is too short to be a valid token (length ${trimmed.length}).`,
    };
  }

  return { isValid: true, isConfigured: true };
}
