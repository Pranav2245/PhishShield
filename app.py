# app.py
"""
PhishShield - Phishing Detection Web Application
Provides URL and Email scanning endpoints with a web interface.
"""

from flask import Flask, request, render_template, jsonify
from flask_cors import CORS
import joblib
import re
from urllib.parse import urlparse
import tldextract
import pandas as pd

# Import analyzers
from email_analyzer import EmailPhishingDetector
from url_analyzer import URLAnalyzer

app = Flask(__name__)
CORS(app)  # Enable CORS for browser extension

# Model file paths
URL_MODEL_FILE = "phishing_rf_model.pkl"
EMAIL_MODEL_FILE = "email_phishing_model.pkl"

# Load URL model
try:
    url_model = joblib.load(URL_MODEL_FILE)
    print(f"✅ Loaded URL model: {URL_MODEL_FILE}")
except Exception as e:
    print(f"⚠️ URL model not loaded (train first): {e}")
    url_model = None

# Initialize analyzers
email_detector = EmailPhishingDetector()
url_analyzer = URLAnalyzer()


def extract_features_df(url: str):
    """Extract features from URL for classification."""
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    features = {
        'url_length': len(url),
        'path_length': len(parsed.path),
        'query_length': len(parsed.query),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_slashes': url.count('/'),
        'has_ip': 1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url) else 0,
        'has_at': 1 if '@' in url else 0,
        'has_www': 1 if parsed.netloc.lower().startswith('www') else 0,
        'has_https': 1 if parsed.scheme == 'https' else 0,
        'num_subdomains': ext.subdomain.count('.') + 1 if ext.subdomain else 0,
        'subdomain_length': len(ext.subdomain),
        'domain_length': len(ext.domain),
        'tld_length': len(ext.suffix),
        'keyword_login': 1 if 'login' in url.lower() else 0,
        'keyword_secure': 1 if 'secure' in url.lower() else 0,
        'keyword_account': 1 if 'account' in url.lower() else 0,
        'keyword_update': 1 if 'update' in url.lower() else 0,
        'is_long_url': 1 if len(url) > 75 else 0,
        'count_digits': len(re.findall(r'\d', url))
    }
    return pd.DataFrame([features])


# ============== WEB ROUTES ==============

@app.route("/", methods=["GET", "POST"])
def index():
    """Main web interface."""
    status = None
    url = ""
    email_result = None
    url_report = None
    active_tab = "url"  # Default tab
    
    if request.method == "POST":
        # Check which form was submitted
        if "url" in request.form:
            active_tab = "url"
            url = request.form.get("url", "").strip()
            detailed = request.form.get("detailed", "") == "on"
            
            if url and not url.startswith(("http://", "https://")):
                url = "http://" + url
            
            if not url:
                status = "Please enter a URL."
            elif detailed:
                # Run comprehensive analysis
                try:
                    url_report = url_analyzer.get_comprehensive_report(url)
                    status = url_report.get('verdict', 'Unknown')
                except Exception as e:
                    status = f"Error analyzing URL: {e}"
            elif url_model is None:
                status = "Model not available. Run training first."
            else:
                try:
                    X = extract_features_df(url)
                    pred = int(url_model.predict(X)[0])
                    status = "Untrusted" if pred == 1 else "Trusted"
                except Exception as e:
                    status = f"Error analyzing URL: {e}"
        
        elif "email_subject" in request.form:
            active_tab = "email"
            subject = request.form.get("email_subject", "").strip()
            body = request.form.get("email_body", "").strip()
            
            if not subject and not body:
                email_result = {"error": "Please enter email subject or body."}
            else:
                email_result = email_detector.analyze_email(subject, body)
                email_result['subject'] = subject
                email_result['body'] = body
    
    return render_template("index.html", 
                          status=status, 
                          url=url, 
                          email_result=email_result,
                          url_report=url_report,
                          active_tab=active_tab)


# ============== API ROUTES ==============

@app.route("/api/scan-url", methods=["POST"])
def api_scan_url():
    """
    API endpoint for URL scanning.
    
    Request JSON: {"url": "https://example.com"}
    Response JSON: {"url": "...", "is_phishing": true/false, "verdict": "Trusted/Untrusted"}
    """
    data = request.get_json()
    
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400
    
    url = data["url"].strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400
    
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    if url_model is None:
        return jsonify({"error": "URL model not available. Run training first."}), 503
    
    try:
        X = extract_features_df(url)
        pred = int(url_model.predict(X)[0])
        proba = url_model.predict_proba(X)[0]
        confidence = float(max(proba))
        
        return jsonify({
            "url": url,
            "is_phishing": pred == 1,
            "verdict": "Untrusted" if pred == 1 else "Trusted",
            "confidence": round(confidence, 2),
            "risk_level": "High" if pred == 1 and confidence > 0.8 else ("Medium" if pred == 1 else "Low")
        })
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@app.route("/api/url-report", methods=["POST"])
def api_url_report():
    """
    API endpoint for comprehensive URL analysis.
    
    Request JSON: {"url": "https://example.com"}
    Response JSON: Full analysis report including domain age, SSL, lexical patterns
    """
    data = request.get_json()
    
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400
    
    url = data["url"].strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400
    
    try:
        report = url_analyzer.get_comprehensive_report(url)
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@app.route("/api/scan-email", methods=["POST"])
def api_scan_email():
    """
    API endpoint for email scanning.
    
    Request JSON: {"subject": "...", "body": "..."}
    Response JSON: {"is_phishing": true/false, "risk_score": 0-100, "indicators": [...]}
    """
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Missing request body"}), 400
    
    subject = data.get("subject", "").strip()
    body = data.get("body", "").strip()
    
    if not subject and not body:
        return jsonify({"error": "Provide at least 'subject' or 'body'"}), 400
    
    try:
        result = email_detector.analyze_email(subject, body)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@app.route("/api/health", methods=["GET"])
def api_health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "url_model_loaded": url_model is not None,
        "email_model_loaded": email_detector.model is not None,
        "whois_available": url_analyzer.whois_available
    })


if __name__ == "__main__":
    print("\n" + "="*50)
    print("🛡️  PhishShield Server Starting")
    print("="*50)
    print("📍 Web Interface: http://localhost:5000/")
    print("📧 Email API: POST /api/scan-email")
    print("🔗 URL API: POST /api/scan-url")
    print("📊 URL Report: POST /api/url-report")
    print("="*50 + "\n")
    app.run(debug=True)
