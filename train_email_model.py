# train_email_model.py
"""
Training script for the Email Phishing Detection Model.
Uses TF-IDF vectorization combined with custom features.
"""

import pandas as pd
import numpy as np
import pickle
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score
from sklearn.pipeline import Pipeline

# Import feature extraction from email_analyzer
from email_analyzer import (
    EmailPhishingDetector,
    URGENCY_KEYWORDS, THREAT_KEYWORDS, ACTION_KEYWORDS,
    SENSITIVE_KEYWORDS, REWARD_KEYWORDS, IMPERSONATION_KEYWORDS
)


def preprocess_text(text):
    """Clean text for TF-IDF processing."""
    if not isinstance(text, str):
        text = str(text) if text else ""
    
    text = text.lower()
    text = re.sub(r'<[^>]+>', ' ', text)  # Remove HTML
    text = re.sub(r'https?://\S+|www\.\S+', ' ', text)  # Remove URLs
    text = re.sub(r'\S+@\S+\.\S+', ' ', text)  # Remove emails
    text = re.sub(r'[^\w\s]', ' ', text)  # Remove special chars
    text = re.sub(r'\s+', ' ', text).strip()  # Normalize whitespace
    
    return text


def extract_manual_features(subject, body, spf_pass=1, dkim_pass=1, dmarc_pass=1, sender_domain_match=1):
    """Extract manual features for each email including authentication."""
    combined = f"{subject} {body}"
    text_lower = combined.lower()
    
    features = {
        # Keyword counts
        'urgency_count': sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower),
        'threat_count': sum(1 for kw in THREAT_KEYWORDS if kw in text_lower),
        'action_count': sum(1 for kw in ACTION_KEYWORDS if kw in text_lower),
        'sensitive_count': sum(1 for kw in SENSITIVE_KEYWORDS if kw in text_lower),
        'reward_count': sum(1 for kw in REWARD_KEYWORDS if kw in text_lower),
        'impersonation_count': sum(1 for kw in IMPERSONATION_KEYWORDS if kw in text_lower),
        
        # Structural features
        'url_count': len(re.findall(r'https?://\S+|www\.\S+', combined)),
        'exclamation_count': min(combined.count('!'), 10),
        'caps_word_count': min(len(re.findall(r'\b[A-Z]{2,}\b', combined)), 10),
        'has_urgent_subject': int(any(kw in subject.lower() for kw in ['urgent', 'immediately', 'action required'])),
        'has_generic_greeting': int(bool(re.search(r'dear (customer|user|member|valued)', body.lower()))),
        'money_mentions': min(len(re.findall(r'\$[\d,]+|\d+\s*(dollars?|usd)', text_lower)), 5),
        'subject_length': len(subject),
        'body_length': len(body),
        'word_count': len(combined.split()),
        
        # Authentication features (critical for detecting spoofed emails)
        'spf_pass': int(spf_pass),
        'dkim_pass': int(dkim_pass),
        'dmarc_pass': int(dmarc_pass),
        'sender_domain_match': int(sender_domain_match),
        'auth_score': int(spf_pass) + int(dkim_pass) + int(dmarc_pass) + int(sender_domain_match),
    }
    
    return list(features.values())


def load_and_prepare_data(dataset_path='email_dataset.csv'):
    """Load dataset and prepare features."""
    print(f"Loading dataset: {dataset_path}")
    df = pd.read_csv(dataset_path)
    
    # Ensure required columns exist
    required_cols = ['subject', 'body', 'label']
    for col in required_cols:
        if col not in df.columns:
            raise ValueError(f"Dataset must contain '{col}' column")
    
    # Clean data
    df = df.dropna(subset=['subject', 'body', 'label'])
    df['label'] = df['label'].astype(int)
    
    print(f"Loaded {len(df)} samples ({df['label'].sum()} phishing, {len(df) - df['label'].sum()} legitimate)")
    
    return df


def train_model(dataset_path='email_dataset.csv', 
                model_output='email_phishing_model.pkl',
                vectorizer_output='email_tfidf_vectorizer.pkl'):
    """Train the email phishing detection model."""
    
    # Load data
    df = load_and_prepare_data(dataset_path)
    
    # Combine subject and body for text processing
    df['combined_text'] = df['subject'] + ' ' + df['body']
    df['clean_text'] = df['combined_text'].apply(preprocess_text)
    
    # Extract manual features including authentication
    print("Extracting manual features with authentication...")
    
    # Check if authentication columns exist
    has_auth = all(col in df.columns for col in ['spf_pass', 'dkim_pass', 'dmarc_pass', 'sender_domain_match'])
    if has_auth:
        print("✓ Authentication features detected in dataset")
    else:
        print("⚠ No authentication columns - using defaults")
    
    manual_features = []
    for _, row in df.iterrows():
        if has_auth:
            features = extract_manual_features(
                row['subject'], row['body'],
                spf_pass=row.get('spf_pass', 1),
                dkim_pass=row.get('dkim_pass', 1),
                dmarc_pass=row.get('dmarc_pass', 1),
                sender_domain_match=row.get('sender_domain_match', 1)
            )
        else:
            features = extract_manual_features(row['subject'], row['body'])
        manual_features.append(features)
    manual_features = np.array(manual_features)
    
    # Create TF-IDF vectorizer
    print("Creating TF-IDF features...")
    tfidf = TfidfVectorizer(
        max_features=500,  # Limit vocabulary size
        ngram_range=(1, 2),  # Unigrams and bigrams
        min_df=2,  # Minimum document frequency
        stop_words='english'
    )
    
    tfidf_features = tfidf.fit_transform(df['clean_text']).toarray()
    print(f"TF-IDF features shape: {tfidf_features.shape}")
    
    # Combine features
    X = np.hstack([tfidf_features, manual_features])
    y = df['label'].values
    
    print(f"Combined features shape: {X.shape}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    print(f"Training set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    # Train Random Forest
    print("\nTraining Random Forest classifier...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    
    clf.fit(X_train, y_train)
    
    # Evaluate
    print("\n" + "="*50)
    print("MODEL EVALUATION")
    print("="*50)
    
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    
    if len(set(y_test)) > 1:
        print(f"ROC AUC: {roc_auc_score(y_test, y_prob):.4f}")
    
    # Feature importance (for manual features)
    n_tfidf = tfidf_features.shape[1]
    manual_feature_names = [
        'urgency_count', 'threat_count', 'action_count', 'sensitive_count',
        'reward_count', 'impersonation_count', 'url_count', 'exclamation_count',
        'caps_word_count', 'has_urgent_subject', 'has_generic_greeting',
        'money_mentions', 'subject_length', 'body_length', 'word_count',
        'spf_pass', 'dkim_pass', 'dmarc_pass', 'sender_domain_match', 'auth_score'
    ]
    
    manual_importances = clf.feature_importances_[n_tfidf:]
    print("\nTop Manual Feature Importances:")
    for name, imp in sorted(zip(manual_feature_names, manual_importances), 
                            key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {name}: {imp:.4f}")
    
    # Save model and vectorizer
    print(f"\nSaving model to: {model_output}")
    with open(model_output, 'wb') as f:
        pickle.dump(clf, f)
    
    print(f"Saving vectorizer to: {vectorizer_output}")
    with open(vectorizer_output, 'wb') as f:
        pickle.dump(tfidf, f)
    
    print("\n✅ Training complete!")
    
    return clf, tfidf


if __name__ == "__main__":
    train_model()
