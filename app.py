# app.py
from flask import Flask, request, render_template
import joblib, re
from urllib.parse import urlparse
import tldextract
import pandas as pd

app = Flask(__name__)
MODEL_FILE = "phishing_rf_model.pkl"

# Try to load the trained model; app still runs if model missing (shows helpful message)
try:
    model = joblib.load(MODEL_FILE)
    print("Loaded model:", MODEL_FILE)
except Exception as e:
    print("Model load failed (train the model first):", e)
    model = None

def extract_features_df(url: str):
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

@app.route("/", methods=["GET","POST"])
def index():
    status = None   # "Trusted" or "Untrusted" or message
    url = ""
    if request.method == "POST":
        url = request.form.get("url","").strip()
        if url and not url.startswith(("http://","https://")):
            url = "http://" + url  # naive normalization
        if not url:
            status = "Please enter a URL."
        elif model is None:
            status = "Model not available. Run training first."
        else:
            try:
                X = extract_features_df(url)
                pred = int(model.predict(X)[0])
                status = "Untrusted" if pred == 1 else "Trusted"
            except Exception as e:
                status = f"Error analyzing URL: {e}"
    return render_template("index.html", status=status, url=url)

if __name__ == "__main__":
    app.run(debug=True)
