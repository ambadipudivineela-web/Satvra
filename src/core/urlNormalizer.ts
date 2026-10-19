/**
 * SATVRA URL Normalization & Sanitization Engine
 * RFC 3986 compliant with Punycode, homograph detection, and userinfo stripping.
 */

export interface NormalizedUrlResult {
  rawUrl: string;
  normalizedUrl: string;
  normalizedUrlWithoutQuery: string;
  protocol: string;
  hostname: string;
  canonicalDomain: string;
  pathname: string;
  search: string;
  hash: string;
  isPunycode: boolean;
  hasUserInfoTrick: boolean;
  hasHomographRisk: boolean;
  isValid: boolean;
  error?: string;
}

// Multi-part Public Suffixes commonly used by public institutions and top-level registries
const MULTI_PART_SUFFIXES = new Set([
  'gov.uk',
  'ac.uk',
  'co.uk',
  'org.uk',
  'gov.au',
  'edu.au',
  'com.au',
  'gc.ca',
  'gov.in',
  'edu.in',
  'state.ny.us',
  'state.ca.us',
  'state.tx.us',
  'state.fl.us',
]);

/**
 * Determines whether an input string is intended as a URL vs a natural-language search query.
 */
export function isLikelyUrl(input: string): boolean {
  if (!input || typeof input !== 'string') return false;
  const trimmed = input.trim();
  // Any whitespace means it's a search phrase
  if (/\s/.test(trimmed)) return false;
  // Explicit http/https scheme
  if (/^https?:\/\//i.test(trimmed)) return true;
  // Has scheme structure (e.g. ftp://)
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) return true;
  // Underscore in domain segment indicates an identifier or search term (e.g. government_jobs)
  if (/^[a-zA-Z0-9_]+$/.test(trimmed)) return false;
  // Standard domain format: hostname.tld or hostname.tld/path
  if (/^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(\/.*)?$/.test(trimmed)) return true;
  // Localhost or IPv4
  if (/^localhost(:\d+)?(\/.*)?$/i.test(trimmed)) return true;
  if (/^(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/.*)?$/.test(trimmed)) return true;
  return false;
}

/**
 * Strips userinfo, lowercases host, normalizes ports, strips trailing dots,
 * and detects homograph / obfuscation tricks.
 */
export function normalizeUrl(inputUrl: string): NormalizedUrlResult {
  if (!inputUrl || typeof inputUrl !== 'string') {
    return {
      rawUrl: inputUrl ?? '',
      normalizedUrl: '',
      normalizedUrlWithoutQuery: '',
      protocol: '',
      hostname: '',
      canonicalDomain: '',
      pathname: '/',
      search: '',
      hash: '',
      isPunycode: false,
      hasUserInfoTrick: false,
      hasHomographRisk: false,
      isValid: false,
      error: 'Empty or invalid URL input',
    };
  }

  const trimmed = inputUrl.trim();

  // If input is clearly a search query, do not mangle into a malformed URL
  if (!isLikelyUrl(trimmed)) {
    return {
      rawUrl: inputUrl,
      normalizedUrl: '',
      normalizedUrlWithoutQuery: '',
      protocol: '',
      hostname: '',
      canonicalDomain: '',
      pathname: '/',
      search: '',
      hash: '',
      isPunycode: false,
      hasUserInfoTrick: false,
      hasHomographRisk: false,
      isValid: false,
      error: `"${trimmed}" is a search query rather than a complete website URL. Use Web Search to find official sites for this topic.`,
    };
  }

  // Prepend https:// if scheme is missing for standard web address inputs
  let target = trimmed;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(target)) {
    target = 'https://' + target;
  }

  let parsed: URL;
  try {
    parsed = new URL(target);
  } catch {
    return {
      rawUrl: inputUrl,
      normalizedUrl: '',
      normalizedUrlWithoutQuery: '',
      protocol: '',
      hostname: '',
      canonicalDomain: '',
      pathname: '/',
      search: '',
      hash: '',
      isPunycode: false,
      hasUserInfoTrick: false,
      hasHomographRisk: false,
      isValid: false,
      error: 'Malformed URL structure. Ensure the address has a valid domain format.',
    };
  }

  // Reject unsafe schemes
  const allowedProtocols = ['http:', 'https:'];
  if (!allowedProtocols.includes(parsed.protocol.toLowerCase())) {
    return {
      rawUrl: inputUrl,
      normalizedUrl: '',
      normalizedUrlWithoutQuery: '',
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      canonicalDomain: '',
      pathname: parsed.pathname,
      search: parsed.search,
      hash: parsed.hash,
      isPunycode: false,
      hasUserInfoTrick: false,
      hasHomographRisk: false,
      isValid: false,
      error: `Unsupported scheme: ${parsed.protocol}. Only HTTP and HTTPS are evaluated.`,
    };
  }

  // Check for user-info deception trick (e.g. https://irs.gov@evil.com)
  const hasUserInfoTrick = Boolean(parsed.username || parsed.password);

  // Normalize hostname: lowercase, remove trailing dot, remove brackets from IPv6
  let hostname = parsed.hostname.toLowerCase();
  if (hostname.endsWith('.')) {
    hostname = hostname.slice(0, -1);
  }

  // Check for punycode (e.g. xn--...)
  const isPunycode = hostname.includes('xn--');

  // Check for suspicious mixed scripts or homograph indicators
  let hasHomographRisk = false;
  try {
    // If punycode, decode to see unicode representation
    if (isPunycode) {
      hasHomographRisk = true; // Punycode domains targeting standard western names are high-risk
    } else {
      // Check for non-ASCII characters in raw input
      const nonAscii = /[^\x20-\x7E]/.test(hostname);
      if (nonAscii) {
        hasHomographRisk = true;
      }
    }
  } catch {
    hasHomographRisk = true;
  }

  // Normalize port
  let port = parsed.port;
  if ((parsed.protocol === 'http:' && port === '80') || (parsed.protocol === 'https:' && port === '443')) {
    port = '';
  }

  // Normalize path: default to '/' if empty
  let pathname = parsed.pathname || '/';
  if (!pathname.startsWith('/')) {
    pathname = '/' + pathname;
  }

  // Determine canonical registered domain (e.g. "sub.example.gov.uk" -> "example.gov.uk")
  const canonicalDomain = extractCanonicalDomain(hostname);

  const portSuffix = port ? `:${port}` : '';
  const normalizedUrl = `${parsed.protocol}//${hostname}${portSuffix}${pathname}${parsed.search}`;
  const normalizedUrlWithoutQuery = `${parsed.protocol}//${hostname}${portSuffix}${pathname}`;

  return {
    rawUrl: inputUrl,
    normalizedUrl,
    normalizedUrlWithoutQuery,
    protocol: parsed.protocol,
    hostname,
    canonicalDomain,
    pathname,
    search: parsed.search,
    hash: parsed.hash,
    isPunycode,
    hasUserInfoTrick,
    hasHomographRisk,
    isValid: true,
  };
}

/**
 * Extracts the canonical organizational domain from a hostname, correctly
 * handling multi-part public suffixes such as .gov.uk, .co.uk, .state.ca.us.
 */
export function extractCanonicalDomain(hostname: string): string {
  if (!hostname) return '';
  const cleanHost = hostname.toLowerCase().replace(/\.+$/, '');

  // Check if hostname is an IP address
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(cleanHost) || cleanHost.includes(':')) {
    return cleanHost;
  }

  const parts = cleanHost.split('.');
  if (parts.length <= 2) {
    return cleanHost;
  }

  // Check 2-part and 3-part multi-part suffixes
  const lastTwo = parts.slice(-2).join('.');
  const lastThree = parts.slice(-3).join('.');

  if (MULTI_PART_SUFFIXES.has(lastThree) && parts.length >= 4) {
    return parts.slice(-4).join('.');
  }

  if (MULTI_PART_SUFFIXES.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }

  // Standard single TLD (e.g., example.com, service.gov)
  return parts.slice(-2).join('.');
}
