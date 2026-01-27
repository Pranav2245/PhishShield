// background.js - PhishShield Service Worker

const API_BASE = 'http://localhost:5000';

// Listen for installation
chrome.runtime.onInstalled.addListener(() => {
    console.log('🛡️ PhishShield extension installed');
});

// Listen for messages from content scripts or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'checkUrl') {
        checkUrl(request.url).then(sendResponse);
        return true; // Keep channel open for async response
    }
});

// Check URL against PhishShield API
async function checkUrl(url) {
    try {
        const response = await fetch(`${API_BASE}/api/scan-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            throw new Error('API error');
        }

        return await response.json();
    } catch (err) {
        console.error('PhishShield API error:', err);
        return { error: 'Unable to check URL' };
    }
}

// Optional: Intercept navigation to warn about suspicious sites
chrome.webNavigation?.onBeforeNavigate?.addListener(async (details) => {
    // Only check main frame navigation
    if (details.frameId !== 0) return;

    const url = details.url;

    // Skip chrome:// and extension pages
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) return;

    // Quick check (can be expanded for real-time protection)
    // Note: This is commented out to avoid slowing down navigation
    // Uncomment for more aggressive protection
    /*
    try {
      const result = await checkUrl(url);
      if (result.is_phishing) {
        // Could show a warning page here
        console.warn('🛡️ PhishShield: Suspicious site detected:', url);
      }
    } catch (err) {
      // Silent fail
    }
    */
});

console.log('🛡️ PhishShield service worker started');
