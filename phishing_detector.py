# phishing_detector.py
import re
import joblib
import pandas as pd
import tldextract
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

def extract_features(url: str):
    if not isinstance(url, str):
        url = str(url)
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    return {
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

def load_dataset(path):
    df = pd.read_csv(path)
    if 'url' not in df.columns or 'label' not in df.columns:
        raise ValueError("CSV must contain 'url' and 'label' columns.")
    df = df.dropna(subset=['url','label'])
    return df

def make_feature_matrix(urls):
    return pd.DataFrame([extract_features(u) for u in urls])

def main(dataset_path="phishing_dataset.csv", out_model="phishing_rf_model.pkl"):
    print("Loading dataset:", dataset_path)
    df = load_dataset(dataset_path)
    X = make_feature_matrix(df['url'])
    y = df['label'].astype(int)

    if len(df) < 4:
        raise ValueError("Dataset too small to train. Need at least a few samples.")

    strat = y if len(set(y)) > 1 else None
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=strat)

    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('rf', RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1))
    ])

    print("Training model...")
    pipeline.fit(X_train, y_train)

    print("Evaluating on test set...")
    preds = pipeline.predict(X_test)
    probs = pipeline.predict_proba(X_test)[:,1] if hasattr(pipeline, "predict_proba") else None

    print("Classification report:")
    print(classification_report(y_test, preds, zero_division=0))
    if probs is not None and len(set(y_test))>1:
        print("ROC AUC:", round(roc_auc_score(y_test, probs),4))

    joblib.dump(pipeline, out_model)
    print("Saved trained model to:", out_model)

if __name__ == "__main__":
    main()
