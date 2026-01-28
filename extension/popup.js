// popup.js - PhishShield Extension Popup Logic

const API_BASE = 'http://localhost:8080';

// Elements
let currentUrlEl, scanCurrentBtn, customUrlInput, scanCustomBtn;
let resultSection, resultCard, resultIcon, resultVerdict, resultScore;
let riskFactors, riskList, loading, error, errorMessage;
let scanLinksBtn, serverStatus, statusDot, statusText;

document.addEventListener('DOMContentLoaded', init);

function init() {
  // Get DOM elements
  currentUrlEl = document.getElementById('currentUrl');
  scanCurrentBtn = document.getElementById('scanCurrentBtn');
  customUrlInput = document.getElementById('customUrl');
  scanCustomBtn = document.getElementById('scanCustomBtn');
  resultSection = document.getElementById('resultSection');
  resultCard = document.getElementById('resultCard');
  resultIcon = document.getElementById('resultIcon');
  resultVerdict = document.getElementById('resultVerdict');
  resultScore = document.getElementById('resultScore');
  riskFactors = document.getElementById('riskFactors');
  riskList = document.getElementById('riskList');
  loading = document.getElementById('loading');
  error = document.getElementById('error');
  errorMessage = document.getElementById('errorMessage');
  scanLinksBtn = document.getElementById('scanLinksBtn');
  serverStatus = document.getElementById('serverStatus');
  statusDot = document.getElementById('statusDot');
  statusText = document.getElementById('statusText');

  // Get current tab URL
  getCurrentTabUrl();

  // Check server status
  checkServerStatus();

  // Event listeners
  scanCurrentBtn.addEventListener('click', scanCurrentPage);
  scanCustomBtn.addEventListener('click', scanCustomUrl);
  scanLinksBtn.addEventListener('click', scanAllLinks);

  customUrlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') scanCustomUrl();
  });
}

async function getCurrentTabUrl() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      currentUrlEl.textContent = tab.url;
    } else {
      currentUrlEl.textContent = 'Unable to get URL';
    }
  } catch (err) {
    currentUrlEl.textContent = 'Error getting URL';
  }
}

async function checkServerStatus() {
  try {
    const response = await fetch(`${API_BASE}/api/health`, {
      method: 'GET',
      mode: 'cors'
    });
    if (response.ok) {
      statusDot.classList.add('online');
      statusDot.classList.remove('offline');
      statusText.textContent = 'Server online';
    } else {
      throw new Error('Server not responding');
    }
  } catch (err) {
    statusDot.classList.add('offline');
    statusDot.classList.remove('online');
    statusText.textContent = 'Server offline - Start Flask app';
  }
}

async function scanUrl(url) {
  showLoading();
  hideError();
  hideResult();

  try {
    // Use the detailed URL report API
    const response = await fetch(`${API_BASE}/api/url-report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      mode: 'cors',
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error('Server error');
    }

    const data = await response.json();
    showResult(data);
  } catch (err) {
    showError('Unable to scan URL. Make sure the PhishShield server is running.');
  } finally {
    hideLoading();
  }
}

function scanCurrentPage() {
  const url = currentUrlEl.textContent;
  if (url && url !== 'Loading...' && !url.startsWith('chrome://')) {
    scanUrl(url);
  } else {
    showError('Cannot scan this page');
  }
}

function scanCustomUrl() {
  let url = customUrlInput.value.trim();
  if (!url) {
    showError('Please enter a URL');
    return;
  }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'http://' + url;
  }
  scanUrl(url);
}

async function scanAllLinks() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.id) {
      // Send message to content script to scan all links
      chrome.tabs.sendMessage(tab.id, { action: 'scanAllLinks' }, (response) => {
        if (chrome.runtime.lastError) {
          showError('Unable to scan links on this page');
        } else if (response && response.success) {
          showError(`Scanning ${response.linkCount} links...`);
          // Close popup after initiating scan
          setTimeout(() => window.close(), 1500);
        }
      });
    }
  } catch (err) {
    showError('Error scanning links');
  }
}

function showResult(data) {
  resultSection.style.display = 'block';

  // Set icon and styling based on risk level
  if (data.risk_level === 'High') {
    resultIcon.textContent = '⚠️';
    resultIcon.className = 'result-icon danger';
    resultVerdict.textContent = 'Suspicious';
  } else if (data.risk_level === 'Medium') {
    resultIcon.textContent = '⚡';
    resultIcon.className = 'result-icon warning';
    resultVerdict.textContent = 'Caution';
  } else {
    resultIcon.textContent = '✓';
    resultIcon.className = 'result-icon safe';
    resultVerdict.textContent = 'Likely Safe';
  }

  resultScore.textContent = `Risk Score: ${data.risk_score}/100 (${data.risk_level})`;

  // Show risk factors
  if (data.all_risk_factors && data.all_risk_factors.length > 0) {
    riskFactors.style.display = 'block';
    riskList.innerHTML = data.all_risk_factors
      .map(factor => `<div class="risk-item">${factor}</div>`)
      .join('');
  } else {
    riskFactors.style.display = 'none';
  }
}

function hideResult() {
  resultSection.style.display = 'none';
}

function showLoading() {
  loading.style.display = 'flex';
}

function hideLoading() {
  loading.style.display = 'none';
}

function showError(message) {
  error.style.display = 'block';
  errorMessage.textContent = message;
}

function hideError() {
  error.style.display = 'none';
}
