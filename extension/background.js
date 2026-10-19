/**
 * SATVRA Chrome MV3 Background Service Worker
 * 
 * Handles navigation interception, badge status updates,
 * declarativeNetRequest rule synchronization, and message dispatch.
 */

// In-memory tab evaluations cache
const tabEvaluations = new Map();

// Badge styles per status
const BADGE_CONFIG = {
  KNOWN_THREAT: { text: '!', color: '#DC2626' },
  CONFLICTING_SIGNALS: { text: '!', color: '#EA580C' },
  OFFICIAL_SOURCE_MATCHED: { text: 'GOV', color: '#059669' },
  NO_KNOWN_THREAT_FOUND: { text: 'OK', color: '#475569' },
  UNVERIFIED: { text: '?', color: '#64748B' },
  CHECK_UNAVAILABLE: { text: 'ERR', color: '#B91C1C' },
};

/**
 * Normalizes input URL in extension context
 */
function normalizeTabUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return null;
    }
    return {
      url: rawUrl,
      hostname: parsed.hostname.toLowerCase(),
      protocol: parsed.protocol,
      pathname: parsed.pathname,
    };
  } catch {
    return null;
  }
}

/**
 * Updates extension action badge on active tab
 */
function updateBadge(tabId, status) {
  const cfg = BADGE_CONFIG[status] || { text: '', color: '#475569' };
  chrome.action.setBadgeText({ tabId, text: cfg.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color });
}

// Intercept navigation
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only process main window frame

  const normalized = normalizeTabUrl(details.url);
  if (!normalized) {
    updateBadge(details.tabId, 'UNVERIFIED');
    return;
  }

  // Check if navigating to SATVRA's warning page
  if (details.url.includes('/warning.html')) {
    updateBadge(details.tabId, 'KNOWN_THREAT');
    return;
  }

  // Fetch evaluation from SATVRA backend proxy or local evaluation
  try {
    // In live extension mode, communicate with local SATVRA proxy or public endpoint
    const response = await fetch('http://localhost:3000/api/threat-intel/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: details.url }),
    });

    if (response.ok) {
      const evaluation = await response.json();
      tabEvaluations.set(details.tabId, evaluation);
      updateBadge(details.tabId, evaluation.status);

      // If threat detected, dynamically register DNR rule to block further loads
      if (evaluation.status === 'KNOWN_THREAT' && chrome.declarativeNetRequest) {
        syncDynamicDnrRule(normalized.hostname);
      }
    } else {
      updateBadge(details.tabId, 'CHECK_UNAVAILABLE');
    }
  } catch (err) {
    console.warn('[SATVRA] Background check error:', err);
    updateBadge(details.tabId, 'CHECK_UNAVAILABLE');
  }
});

// Dynamic DNR Rule Sync
async function syncDynamicDnrRule(hostname) {
  try {
    const ruleId = Math.floor(Math.random() * 80000) + 10000;
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [
        {
          id: ruleId,
          priority: 2,
          action: {
            type: 'redirect',
            redirect: {
              extensionPath: `/warning.html?blockedDomain=${encodeURIComponent(hostname)}`,
            },
          },
          condition: {
            urlFilter: `||${hostname}^`,
            resourceTypes: ['main_frame'],
          },
        },
      ],
    });
  } catch (e) {
    console.error('[SATVRA] Error adding dynamic DNR rule:', e);
  }
}

// Clean up closed tabs
chrome.tabs.onRemoved.addListener((tabId) => {
  tabEvaluations.delete(tabId);
});

// Message listener for popup communication
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_TAB_EVALUATION') {
    const evalData = tabEvaluations.get(message.tabId);
    sendResponse({ evaluation: evalData || null });
    return true;
  }

  if (message.type === 'REFRESH_EVALUATION') {
    // Force re-check
    fetch('http://localhost:3000/api/threat-intel/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: message.url, forceRefresh: true }),
    })
      .then((res) => res.json())
      .then((data) => {
        tabEvaluations.set(message.tabId, data);
        updateBadge(message.tabId, data.status);
        sendResponse({ success: true, evaluation: data });
      })
      .catch((err) => {
        sendResponse({ success: false, error: err.message });
      });
    return true;
  }
});
