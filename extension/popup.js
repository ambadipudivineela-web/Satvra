/**
 * SATVRA Extension Popup Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  // Elements
  const tabBtnSearch = document.getElementById('tab-btn-search');
  const tabBtnInspect = document.getElementById('tab-btn-inspect');
  const tabBtnOfficial = document.getElementById('tab-btn-official');
  const tabBtnPrivacy = document.getElementById('tab-btn-privacy');

  const viewSearch = document.getElementById('view-search');
  const viewInspect = document.getElementById('view-inspect');
  const viewOfficial = document.getElementById('view-official');
  const viewPrivacy = document.getElementById('view-privacy');

  const popupSearchForm = document.getElementById('popup-search-form');
  const popupSearchInput = document.getElementById('popup-search-input');
  const popupSearchResults = document.getElementById('popup-search-results');

  const activeDomainEl = document.getElementById('active-domain');
  const canonicalDomainEl = document.getElementById('canonical-domain');
  const checkedTimestampEl = document.getElementById('checked-timestamp');
  const domainSchemeEl = document.getElementById('domain-scheme');

  const statusCard = document.getElementById('status-card');
  const statusHeadline = document.getElementById('status-headline');
  const statusExplanation = document.getElementById('status-explanation');
  const whatEstablishes = document.getElementById('what-establishes');
  const whatNotEstablishes = document.getElementById('what-not-establishes');
  const providerName = document.getElementById('provider-name');
  const latencyText = document.getElementById('latency-text');

  const officialSourceBox = document.getElementById('official-source-box');
  const officialOrgName = document.getElementById('official-org-name');
  const officialJurisdiction = document.getElementById('official-jurisdiction');
  const officialDesc = document.getElementById('official-desc');
  const officialAuditDate = document.getElementById('official-audit-date');
  const officialRefLink = document.getElementById('official-ref-link');

  const btnRefresh = document.getElementById('btn-refresh');
  const officialSearchInput = document.getElementById('official-search-input');
  const officialResultsList = document.getElementById('official-results-list');
  const btnClearCache = document.getElementById('btn-clear-cache');

  // Tab Navigation Handling
  function switchTab(targetView, targetBtn) {
    [viewSearch, viewInspect, viewOfficial, viewPrivacy].forEach((v) => v.classList.add('hidden'));
    [tabBtnSearch, tabBtnInspect, tabBtnOfficial, tabBtnPrivacy].forEach((b) => {
      b.classList.remove('active');
      b.setAttribute('aria-selected', 'false');
    });

    targetView.classList.remove('hidden');
    targetBtn.classList.add('active');
    targetBtn.setAttribute('aria-selected', 'true');
  }

  tabBtnSearch.addEventListener('click', () => switchTab(viewSearch, tabBtnSearch));
  tabBtnInspect.addEventListener('click', () => switchTab(viewInspect, tabBtnInspect));
  tabBtnOfficial.addEventListener('click', () => {
    switchTab(viewOfficial, tabBtnOfficial);
    loadOfficialSources('');
  });
  tabBtnPrivacy.addEventListener('click', () => switchTab(viewPrivacy, tabBtnPrivacy));

  // Web Search in Popup
  async function performPopupSearch(q) {
    if (!q || !q.trim()) return;
    popupSearchResults.innerHTML = '<div class="text-xs text-muted py-3 text-center">Searching web and verifying sources...</div>';
    try {
      const res = await fetch(`http://localhost:3000/api/search?q=${encodeURIComponent(q.trim())}`);
      const data = await res.json();
      if (!data.results || data.results.length === 0) {
        popupSearchResults.innerHTML = `<div class="text-xs text-muted py-3 text-center">No results found for "${q}".</div>`;
        return;
      }
      popupSearchResults.innerHTML = data.results.slice(0, 5).map(item => `
        <div class="result-item" style="border-color: ${item.isOfficial ? '#059669' : '#374151'}">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span class="result-domain" style="color:${item.isOfficial ? '#34d399' : '#06b6d4'}">${item.domain}</span>
            <span class="text-xs" style="color:${item.isOfficial ? '#34d399' : '#9ca3af'}">${item.isOfficial ? 'OFFICIAL' : 'UNVERIFIED'}</span>
          </div>
          <div class="result-org"><a href="${item.url}" target="_blank" style="color:#fff; text-decoration:none;">${item.title}</a></div>
          <p class="text-xs text-muted" style="margin-top:2px;">${item.snippet}</p>
        </div>
      `).join('');
    } catch (e) {
      popupSearchResults.innerHTML = `<div class="text-xs text-muted py-3 text-center">Search error: ${e.message}</div>`;
    }
  }

  popupSearchForm.addEventListener('submit', (e) => {
    e.preventDefault();
    performPopupSearch(popupSearchInput.value);
  });

  // Get active tab from Chrome
  let currentTab = null;
  if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs[0]) {
        currentTab = tabs[0];
      }
    } catch (e) {
      console.warn('Could not query active tab:', e);
    }
  }

  // Fallback demo tab if outside chrome extension context
  const activeUrl = currentTab?.url || 'https://irs.gov/refunds';

  async function loadTabStatus(forceRefresh = false) {
    try {
      const parsed = new URL(activeUrl);
      activeDomainEl.textContent = parsed.hostname;
      domainSchemeEl.textContent = parsed.protocol.replace(':', '').toUpperCase();
    } catch {
      activeDomainEl.textContent = activeUrl;
    }

    // Call local SATVRA backend or background worker
    try {
      const res = await fetch('http://localhost:3000/api/threat-intel/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: activeUrl, forceRefresh }),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      renderEvaluation(data);
    } catch (e) {
      renderError(e.message);
    }
  }

  function renderEvaluation(evaluation) {
    canonicalDomainEl.textContent = evaluation.domain || 'N/A';
    checkedTimestampEl.textContent = new Date(evaluation.checkedAt).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });

    statusHeadline.textContent = evaluation.statusHeadline;
    statusExplanation.textContent = evaluation.statusExplanation;
    whatEstablishes.textContent = evaluation.whatThisEstablishes;
    whatNotEstablishes.textContent = evaluation.whatThisDoesNotEstablish;

    providerName.textContent = evaluation.threatResult.providerDisplayName || 'SATVRA Threat Engine';
    latencyText.textContent = `${evaluation.threatResult.latencyMs || 5}ms`;

    // Status variant classes
    statusCard.className = 'status-card';
    if (evaluation.status === 'KNOWN_THREAT') {
      statusCard.classList.add('status-threat');
    } else if (evaluation.status === 'OFFICIAL_SOURCE_MATCHED') {
      statusCard.classList.add('status-official');
    } else if (evaluation.status === 'CONFLICTING_SIGNALS') {
      statusCard.classList.add('status-conflict');
    } else if (evaluation.status === 'CHECK_UNAVAILABLE') {
      statusCard.classList.add('status-error');
    } else {
      statusCard.classList.add('status-unverified');
    }

    // Official Source Record Box
    if (evaluation.officialSource) {
      const src = evaluation.officialSource;
      officialSourceBox.classList.remove('hidden');
      officialOrgName.textContent = src.organizationName;
      officialJurisdiction.textContent = src.jurisdiction;
      officialDesc.textContent = src.description;
      officialAuditDate.textContent = src.verificationDate;
      officialRefLink.href = src.authoritativeReferenceUrl;
    } else {
      officialSourceBox.classList.add('hidden');
    }
  }

  function renderError(msg) {
    statusHeadline.textContent = 'Check Unavailable';
    statusExplanation.textContent = `Could not connect to SATVRA security engine: ${msg}. Threat status unverified.`;
    whatEstablishes.textContent = 'Provider communication failed.';
    whatNotEstablishes.textContent = 'Site safety cannot be confirmed.';
    statusCard.className = 'status-card status-error';
  }

  btnRefresh.addEventListener('click', () => {
    statusHeadline.textContent = 'Re-checking...';
    loadTabStatus(true);
  });

  // Official Sources Search
  async function loadOfficialSources(query = '') {
    try {
      const res = await fetch(`http://localhost:3000/api/official-sources?q=${encodeURIComponent(query)}`);
      const data = await res.json();
      renderOfficialList(data.matches || []);
    } catch {
      officialResultsList.innerHTML = '<div class="text-xs text-muted">Unable to load official directory.</div>';
    }
  }

  function renderOfficialList(matches) {
    if (!matches || matches.length === 0) {
      officialResultsList.innerHTML =
        '<div class="text-xs text-muted py-4 text-center">No matching official records found in audited directory.</div>';
      return;
    }

    officialResultsList.innerHTML = matches
      .map(
        (m) => `
        <div class="result-item">
          <div class="flex justify-between items-center">
            <span class="result-domain">${m.record.canonicalDomain}</span>
            <span class="text-xs text-muted">${m.record.jurisdiction}</span>
          </div>
          <div class="result-org">${m.record.organizationName}</div>
          <p class="text-xs text-muted mb-2">${m.record.description}</p>
          <div class="box-footer">
            <span class="text-xs text-muted">Audited: ${m.record.verificationDate}</span>
            <a href="https://${m.record.canonicalDomain}" target="_blank" class="link-btn">Visit Official Site &rarr;</a>
          </div>
        </div>
      `
      )
      .join('');
  }

  officialSearchInput.addEventListener('input', (e) => {
    loadOfficialSources(e.target.value);
  });

  btnClearCache.addEventListener('click', async () => {
    try {
      await fetch('http://localhost:3000/api/threat-intel/clear-cache', { method: 'POST' });
      btnClearCache.textContent = 'Cache Cleared!';
      setTimeout(() => {
        btnClearCache.textContent = 'Clear Local Cache & Rules';
      }, 2000);
      loadTabStatus(true);
    } catch (e) {
      console.error(e);
    }
  });

  // Initial load
  loadTabStatus();
});
