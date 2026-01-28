// content.js - PhishShield Content Script
// Runs on all websites to scan and highlight suspicious links

const API_BASE = 'http://localhost:8080';
let isScanning = false;
let scannedLinks = new Map();

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'scanAllLinks') {
        const links = document.querySelectorAll('a[href]');
        scanAllLinksOnPage(links);
        sendResponse({ success: true, linkCount: links.length });
    }
    return true;
});

// Scan all links on the page
async function scanAllLinksOnPage(links) {
    if (isScanning) return;
    isScanning = true;

    showNotification('🔍 Scanning links...', 'info');

    let scanned = 0;
    let suspicious = 0;

    for (const link of links) {
        const href = link.href;

        // Skip already scanned, javascript:, mailto:, tel:, and anchor links
        if (!href ||
            href.startsWith('javascript:') ||
            href.startsWith('mailto:') ||
            href.startsWith('tel:') ||
            href.startsWith('#') ||
            scannedLinks.has(href)) {
            continue;
        }

        try {
            const result = await scanLink(href);
            scannedLinks.set(href, result);

            // Highlight based on risk
            highlightLink(link, result);

            if (result.risk_level === 'High') {
                suspicious++;
            }

            scanned++;

            // Rate limiting - avoid overwhelming the server
            await sleep(100);
        } catch (err) {
            console.error('PhishShield: Error scanning', href, err);
        }
    }

    isScanning = false;

    if (suspicious > 0) {
        showNotification(`⚠️ Found ${suspicious} suspicious links out of ${scanned} scanned`, 'warning');
    } else {
        showNotification(`✅ Scanned ${scanned} links - No threats detected`, 'success');
    }
}

// Scan a single link
async function scanLink(url) {
    try {
        const response = await fetch(`${API_BASE}/api/url-report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            throw new Error('Scan failed');
        }

        return await response.json();
    } catch (err) {
        return { risk_level: 'Unknown', risk_score: 0 };
    }
}

// Highlight a link based on scan result
function highlightLink(link, result) {
    // Remove any existing PhishShield styling
    link.classList.remove('phishshield-safe', 'phishshield-caution', 'phishshield-danger');

    if (result.risk_level === 'High') {
        link.classList.add('phishshield-danger');
        addTooltip(link, result, 'danger');
    } else if (result.risk_level === 'Medium') {
        link.classList.add('phishshield-caution');
        addTooltip(link, result, 'caution');
    } else if (result.risk_level === 'Low') {
        link.classList.add('phishshield-safe');
    }
}

// Add tooltip to link
function addTooltip(link, result, type) {
    // Create tooltip if it doesn't exist
    let tooltip = link.querySelector('.phishshield-tooltip');
    if (!tooltip) {
        tooltip = document.createElement('div');
        tooltip.className = 'phishshield-tooltip';
        link.style.position = 'relative';
        link.appendChild(tooltip);
    }

    const riskFactors = result.all_risk_factors || [];
    const factorsHtml = riskFactors.length > 0
        ? `<div class="phishshield-factors">${riskFactors.slice(0, 3).join('<br>')}</div>`
        : '';

    tooltip.innerHTML = `
    <div class="phishshield-tooltip-header">
      ${type === 'danger' ? '⚠️ Suspicious Link' : '⚡ Caution'}
    </div>
    <div class="phishshield-tooltip-score">
      Risk Score: ${result.risk_score}/100
    </div>
    ${factorsHtml}
  `;
}

// Show notification banner
function showNotification(message, type) {
    // Remove existing notification
    const existing = document.getElementById('phishshield-notification');
    if (existing) existing.remove();

    const notification = document.createElement('div');
    notification.id = 'phishshield-notification';
    notification.className = `phishshield-notification phishshield-notification-${type}`;
    notification.innerHTML = `
    <span class="phishshield-notification-icon">🛡️</span>
    <span class="phishshield-notification-text">${message}</span>
    <button class="phishshield-notification-close" onclick="this.parentElement.remove()">×</button>
  `;

    document.body.appendChild(notification);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.style.opacity = '0';
            setTimeout(() => notification.remove(), 300);
        }
    }, 5000);
}

// Utility function for delay
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Scan links on hover (optional - lightweight)
document.addEventListener('mouseover', async (e) => {
    const link = e.target.closest('a[href]');
    if (!link || !link.href || scannedLinks.has(link.href)) return;

    // Skip internal links
    if (link.href.startsWith('javascript:') ||
        link.href.startsWith('mailto:') ||
        link.href.startsWith('#')) return;

    // Quick check on hover (non-blocking)
    try {
        const response = await fetch(`${API_BASE}/api/scan-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: link.href })
        });

        if (response.ok) {
            const result = await response.json();
            if (result.is_phishing) {
                link.classList.add('phishshield-danger');
                scannedLinks.set(link.href, { risk_level: 'High', risk_score: 80 });
            }
        }
    } catch (err) {
        // Silent fail on hover check
    }
});

console.log('🛡️ PhishShield content script loaded');
