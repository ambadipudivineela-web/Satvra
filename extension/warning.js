/**
 * SATVRA Interstitial Warning Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const blockedDomain = urlParams.get('blockedDomain') || urlParams.get('url') || 'unverified-destination';
  const threatType = urlParams.get('threatType') || 'malicious content';

  const blockedTargetEl = document.getElementById('blocked-target-domain');
  const threatTypeBadge = document.getElementById('threat-type-badge');
  const btnReturnSafety = document.getElementById('btn-return-safety');
  const btnSearchOfficial = document.getElementById('btn-search-official');
  const checkConfirmRisk = document.getElementById('check-confirm-risk');
  const btnProceedUnsafe = document.getElementById('btn-proceed-unsafe');

  if (blockedTargetEl) {
    blockedTargetEl.textContent = blockedDomain;
  }

  if (threatTypeBadge) {
    threatTypeBadge.textContent = threatType.toUpperCase();
  }

  btnReturnSafety.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'about:blank';
    }
  });

  btnSearchOfficial.addEventListener('click', () => {
    // Open SATVRA official directory search
    window.location.href = 'http://localhost:3000/#official-directory';
  });

  checkConfirmRisk.addEventListener('change', (e) => {
    btnProceedUnsafe.disabled = !e.target.checked;
  });

  btnProceedUnsafe.addEventListener('click', () => {
    const proceedConfirm = confirm(
      'WARNING: You are about to bypass SATVRA protection to visit a known threat. Continue at your own risk?'
    );
    if (proceedConfirm) {
      const destination = blockedDomain.startsWith('http') ? blockedDomain : `https://${blockedDomain}`;
      window.location.href = destination;
    }
  });
});
