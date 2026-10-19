/**
 * Chrome Manifest V3 declarativeNetRequest Rule Generator
 * 
 * Generates declarativeNetRequest rules for blocking or redirecting
 * known threats to the SATVRA interstitial warning page.
 */

export interface DnrRule {
  id: number;
  priority: number;
  action: {
    type: 'redirect' | 'block';
    redirect?: {
      extensionPath?: string;
      regexSubstitution?: string;
      url?: string;
    };
  };
  condition: {
    urlFilter?: string;
    regexFilter?: string;
    resourceTypes: Array<
      | 'main_frame'
      | 'sub_frame'
      | 'stylesheet'
      | 'script'
      | 'image'
      | 'font'
      | 'object'
      | 'xmlhttprequest'
      | 'ping'
      | 'other'
    >;
    requestDomains?: string[];
  };
}

/**
 * Builds declarativeNetRequest rules for known threat domains.
 */
export function generateDnrRules(threatDomains: string[]): DnrRule[] {
  let ruleId = 1000;
  const rules: DnrRule[] = [];

  for (const domain of threatDomains) {
    if (!domain || !domain.trim()) continue;
    const cleanDomain = domain.toLowerCase().trim().replace(/^https?:\/\//, '').split('/')[0];

    rules.push({
      id: ruleId++,
      priority: 1,
      action: {
        type: 'redirect',
        redirect: {
          extensionPath: `/warning.html?blockedDomain=${encodeURIComponent(cleanDomain)}`,
        },
      },
      condition: {
        urlFilter: `||${cleanDomain}^`,
        resourceTypes: ['main_frame', 'sub_frame'],
      },
    });
  }

  return rules;
}
