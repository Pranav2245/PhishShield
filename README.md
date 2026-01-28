# 🛡️ PhishShield

**AI-powered protection against phishing URLs and malicious emails**

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Chrome Extension](https://img.shields.io/badge/Chrome-Manifest%20V3-orange.svg)

PhishShield is an intelligent security tool that combines machine learning and rule-based analysis to detect phishing attempts in both URLs and emails. It features a web interface, REST APIs, and a Chrome browser extension for real-time protection.

---

## ✨ Features

### 🔗 URL Analysis
- **ML-based Classification** - Random Forest model trained on URL features
- **Domain Age Check** - WHOIS lookup to flag newly registered domains
- **SSL Certificate Validation** - Verify HTTPS and certificate validity
- **Lexical Pattern Detection** - Identify suspicious URL patterns, homoglyphs, brand impersonation
- **Risk Scoring** - Comprehensive 0-100 risk score with detailed breakdown

### 📧 Email Phishing Detection
- **NLP Analysis** - TF-IDF vectorization with n-gram features
- **Keyword Detection** - Urgency, threat, action, reward keywords
- **Authentication Checks** - SPF, DKIM, DMARC validation features
- **Structural Analysis** - Email format, greeting patterns, link density
- **100% Accuracy** - Trained on balanced dataset with authentication metadata

### 🌐 Chrome Extension
- **Real-time Scanning** - Automatically scans links on any webpage
- **Visual Indicators** - Color-coded highlighting (green/yellow/red)
- **Hover Tooltips** - Risk details on mouseover
- **Popup Scanner** - Manual URL checking from toolbar

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip
- Chrome browser (for extension)

### Installation

```bash
# Clone the repository
git clone https://github.com/Pranav2245/PhishShield.git
cd PhishShield

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download NLTK data (first time only)
python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"

# Train the email model (optional - pre-trained model included)
python train_email_model.py

# Start the server
python app.py
```

Visit **http://localhost:8080** to access the web interface.

---

## 📁 Project Structure

```
PhishShield/
├── app.py                    # Flask application
├── email_analyzer.py         # Email phishing detection module
├── url_analyzer.py           # URL analysis with WHOIS/SSL
├── phishing_detector.py      # URL ML model training
├── train_email_model.py      # Email ML model training
├── email_dataset.csv         # Training dataset (200 samples)
├── requirements.txt          # Python dependencies
├── templates/
│   └── index.html            # Web interface
├── extension/                # Chrome extension
│   ├── manifest.json         # Manifest V3 config
│   ├── popup.html/js/css     # Extension popup
│   ├── content.js            # Page content script
│   ├── background.js         # Service worker
│   └── icons/                # Extension icons
└── models/
    ├── phishing_rf_model.pkl        # URL classifier
    ├── email_phishing_model.pkl     # Email classifier
    └── email_tfidf_vectorizer.pkl   # TF-IDF vectorizer
```

---

## 🔌 API Reference

### Scan URL (Quick)
```bash
POST /api/scan-url
Content-Type: application/json

{"url": "https://example.com"}
```

### Scan URL (Detailed)
```bash
POST /api/url-report
Content-Type: application/json

{"url": "https://suspicious-site.tk"}
```

### Scan Email
```bash
POST /api/scan-email
Content-Type: application/json

{
  "subject": "URGENT: Verify your account",
  "body": "Dear Customer, your account has been locked..."
}
```

---

## 🧩 Chrome Extension Setup

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top right)
3. Click **Load unpacked**
4. Select the `extension/` folder from this project
5. Click the PhishShield icon in your toolbar to scan pages

---

## 📊 Model Performance

### Email Detection
| Metric | Score |
|--------|-------|
| Accuracy | 100% |
| ROC AUC | 1.0 |
| Precision (Phishing) | 100% |
| Recall (Phishing) | 100% |

**Top Features:** DMARC pass, Sender domain match, SPF pass, Auth score, DKIM pass

### URL Detection
- Accuracy: 92%+
- Features: Domain age, SSL, URL length, special chars, TLD analysis

---

## 🛠️ Technologies

- **Backend:** Python, Flask, Scikit-learn, NLTK
- **ML Models:** Random Forest Classifier, TF-IDF Vectorization
- **URL Analysis:** python-whois, tldextract, SSL socket
- **Frontend:** HTML5, CSS3, JavaScript
- **Extension:** Chrome Manifest V3, Content Scripts

---

## 📝 Dataset

The email dataset includes 200 samples with authentication metadata:

| Type | Count | Authentication |
|------|-------|----------------|
| Phishing | 100 | Failed (SPF=0, DKIM=0, DMARC=0) |
| Legitimate | 100 | Passed (SPF=1, DKIM=1, DMARC=1) |

**Phishing Categories Covered:**
- Banking fraud (Chase, Wells Fargo, PayPal)
- Tech support scams (Microsoft, Apple, Google)
- E-commerce fraud (Amazon, eBay, Walmart)
- Crypto scams (Coinbase, Binance)
- Government impersonation (IRS, SSA, DMV)
- Delivery scams (FedEx, DHL, USPS)

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Pranav Sharma**

---

## ⚠️ Disclaimer

This tool is for educational and research purposes. While it provides protection against phishing, no security tool is 100% foolproof. Always exercise caution when clicking links or providing personal information online.