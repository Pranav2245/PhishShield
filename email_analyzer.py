# email_analyzer.py
"""
NLP-based Email Phishing Detector
Uses TF-IDF vectorization, keyword analysis, and pattern detection
to identify phishing emails.
"""

import re
import pickle
import os
import numpy as np
from collections import Counter

# Phishing indicator keywords organized by category
URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'asap', 'right away', 'expire', 'expires',
    'expiring', 'suspended', 'suspend', 'limited time', 'act now',
    'don\'t delay', 'within 24 hours', 'within 48 hours', 'deadline'
]

THREAT_KEYWORDS = [
    'suspend', 'terminate', 'delete', 'close', 'block', 'locked',
    'unauthorized', 'illegal', 'fraud', 'compromised', 'breach',
    'violation', 'restrict', 'disabled', 'deactivate'
]

ACTION_KEYWORDS = [
    'verify', 'confirm', 'update', 'validate', 'click here', 'click below',
    'login', 'log in', 'sign in', 'reset password', 'change password',
    'enter your', 'provide your', 'submit', 'fill out'
]

SENSITIVE_KEYWORDS = [
    'password', 'credit card', 'ssn', 'social security', 'bank account',
    'pin', 'cvv', 'account number', 'routing number', 'tax id',
    'mother\'s maiden', 'date of birth', 'driver\'s license'
]

REWARD_KEYWORDS = [
    'winner', 'won', 'congratulations', 'selected', 'lucky', 'prize',
    'reward', 'free', 'gift', 'bonus', 'claim', 'inheritance', 'lottery'
]

IMPERSONATION_KEYWORDS = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix',
    'bank of america', 'wells fargo', 'chase', 'irs', 'fedex', 'ups',
    'dhl', 'usps', 'facebook', 'instagram', 'whatsapp'
]


class EmailPhishingDetector:
    """
    Detects phishing emails using NLP feature extraction and ML classification.
    """
    
    def __init__(self, model_path='email_phishing_model.pkl', 
                 vectorizer_path='email_tfidf_vectorizer.pkl'):
        self.model_path = model_path
        self.vectorizer_path = vectorizer_path
        self.model = None
        self.vectorizer = None
        self._load_model()
    
    def _load_model(self):
        """Load trained model and vectorizer if available."""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                print(f"Loaded email model: {self.model_path}")
            
            if os.path.exists(self.vectorizer_path):
                with open(self.vectorizer_path, 'rb') as f:
                    self.vectorizer = pickle.load(f)
                print(f"Loaded vectorizer: {self.vectorizer_path}")
        except Exception as e:
            print(f"Could not load email model: {e}")
    
    def preprocess_text(self, text):
        """Clean and normalize text for analysis."""
        if not isinstance(text, str):
            text = str(text) if text else ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', text)
        
        # Remove URLs but count them first
        url_count = len(re.findall(r'https?://\S+|www\.\S+', text))
        text = re.sub(r'https?://\S+|www\.\S+', ' [URL] ', text)
        
        # Remove email addresses but count them
        email_count = len(re.findall(r'\S+@\S+\.\S+', text))
        text = re.sub(r'\S+@\S+\.\S+', ' [EMAIL] ', text)
        
        # Remove special characters but keep spaces
        text = re.sub(r'[^\w\s\[\]]', ' ', text)
        
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text, url_count, email_count
    
    def extract_keyword_features(self, text):
        """Extract keyword-based features from text."""
        text_lower = text.lower()
        
        features = {
            'urgency_count': sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower),
            'threat_count': sum(1 for kw in THREAT_KEYWORDS if kw in text_lower),
            'action_count': sum(1 for kw in ACTION_KEYWORDS if kw in text_lower),
            'sensitive_count': sum(1 for kw in SENSITIVE_KEYWORDS if kw in text_lower),
            'reward_count': sum(1 for kw in REWARD_KEYWORDS if kw in text_lower),
            'impersonation_count': sum(1 for kw in IMPERSONATION_KEYWORDS if kw in text_lower),
        }
        
        return features
    
    def extract_structural_features(self, subject, body):
        """Extract structural features from email."""
        combined = f"{subject} {body}"
        clean_text, url_count, email_count = self.preprocess_text(combined)
        
        # Count exclamation marks (urgency indicator)
        exclamation_count = combined.count('!')
        
        # Count ALL CAPS words (urgency indicator)
        caps_words = len(re.findall(r'\b[A-Z]{2,}\b', combined))
        
        # Check for suspicious patterns
        has_urgent_subject = any(kw in subject.lower() for kw in ['urgent', 'important', 'action required', 'immediately'])
        has_greeting = bool(re.search(r'^(dear|hello|hi|greetings)', body.lower().strip()))
        has_generic_greeting = bool(re.search(r'dear (customer|user|member|valued)', body.lower()))
        
        # Money mentions
        money_mentions = len(re.findall(r'\$[\d,]+|\d+\s*(dollars?|usd)', combined.lower()))
        
        features = {
            'url_count': url_count,
            'email_count': email_count,
            'exclamation_count': min(exclamation_count, 10),  # Cap at 10
            'caps_word_count': min(caps_words, 10),
            'has_urgent_subject': int(has_urgent_subject),
            'has_greeting': int(has_greeting),
            'has_generic_greeting': int(has_generic_greeting),
            'money_mentions': min(money_mentions, 5),
            'subject_length': len(subject),
            'body_length': len(body),
            'word_count': len(combined.split()),
        }
        
        return features, clean_text
    
    def extract_all_features(self, subject, body):
        """Extract all features for classification."""
        structural_features, clean_text = self.extract_structural_features(subject, body)
        keyword_features = self.extract_keyword_features(f"{subject} {body}")
        
        # Combine all features
        all_features = {**structural_features, **keyword_features}
        
        return all_features, clean_text
    
    def calculate_risk_score(self, features):
        """Calculate a risk score based on features (0-100)."""
        score = 0
        
        # Keyword weights
        score += features.get('urgency_count', 0) * 8
        score += features.get('threat_count', 0) * 10
        score += features.get('action_count', 0) * 5
        score += features.get('sensitive_count', 0) * 15
        score += features.get('reward_count', 0) * 12
        score += features.get('impersonation_count', 0) * 10
        
        # Structural weights
        score += features.get('exclamation_count', 0) * 2
        score += features.get('caps_word_count', 0) * 2
        score += features.get('has_urgent_subject', 0) * 10
        score += features.get('has_generic_greeting', 0) * 15
        score += features.get('money_mentions', 0) * 8
        
        # URL suspicion (multiple URLs can be suspicious)
        if features.get('url_count', 0) > 3:
            score += 10
        
        # Cap at 100
        return min(score, 100)
    
    def get_detected_indicators(self, subject, body):
        """Get list of detected phishing indicators."""
        combined = f"{subject} {body}".lower()
        indicators = []
        
        # Check each category
        for kw in URGENCY_KEYWORDS:
            if kw in combined:
                indicators.append(f"🚨 Urgency: '{kw}'")
                break  # Only report one per category
        
        for kw in THREAT_KEYWORDS:
            if kw in combined:
                indicators.append(f"⚠️ Threat: '{kw}'")
                break
        
        for kw in ACTION_KEYWORDS:
            if kw in combined:
                indicators.append(f"👆 Action request: '{kw}'")
                break
        
        for kw in SENSITIVE_KEYWORDS:
            if kw in combined:
                indicators.append(f"🔐 Sensitive data request: '{kw}'")
                break
        
        for kw in REWARD_KEYWORDS:
            if kw in combined:
                indicators.append(f"🎁 Suspicious reward: '{kw}'")
                break
        
        for kw in IMPERSONATION_KEYWORDS:
            if kw in combined:
                indicators.append(f"🎭 Brand mention: '{kw}'")
                break
        
        # Check structural issues
        if re.search(r'dear (customer|user|member|valued)', combined):
            indicators.append("📧 Generic greeting (not personalized)")
        
        if combined.count('!') > 3:
            indicators.append("❗ Excessive exclamation marks")
        
        return indicators
    
    def analyze_email(self, subject, body):
        """
        Main analysis function. Returns classification result and details.
        
        Returns:
            dict with keys: is_phishing, confidence, risk_score, indicators, features
        """
        # Extract features
        features, clean_text = self.extract_all_features(subject, body)
        
        # Calculate rule-based risk score
        risk_score = self.calculate_risk_score(features)
        
        # Get detected indicators
        indicators = self.get_detected_indicators(subject, body)
        
        # Use ML model if available, otherwise use rule-based
        if self.model is not None and self.vectorizer is not None:
            try:
                # Get TF-IDF features
                tfidf_features = self.vectorizer.transform([clean_text]).toarray()[0]
                
                # Combine with manual features
                manual_feature_values = list(features.values())
                combined_features = np.concatenate([tfidf_features, manual_feature_values])
                
                # Predict
                prediction = self.model.predict([combined_features])[0]
                confidence = self.model.predict_proba([combined_features])[0].max()
                
                is_phishing = bool(prediction == 1)
            except Exception as e:
                print(f"ML prediction failed, using rule-based: {e}")
                is_phishing = risk_score >= 40
                confidence = min(risk_score / 100 + 0.3, 0.95)
        else:
            # Rule-based classification
            is_phishing = risk_score >= 40
            confidence = min(risk_score / 100 + 0.3, 0.95)
        
        return {
            'is_phishing': is_phishing,
            'confidence': round(confidence, 2),
            'risk_score': risk_score,
            'risk_level': 'High' if risk_score >= 60 else ('Medium' if risk_score >= 30 else 'Low'),
            'indicators': indicators,
            'features': features,
            'verdict': 'Phishing' if is_phishing else 'Legitimate'
        }


# Convenience function for quick analysis
def analyze_email(subject, body):
    """Quick analysis function."""
    detector = EmailPhishingDetector()
    return detector.analyze_email(subject, body)


if __name__ == "__main__":
    # Test with sample emails
    detector = EmailPhishingDetector()
    
    # Test phishing email
    phishing_subject = "URGENT: Your account will be suspended!"
    phishing_body = """
    Dear Valued Customer,
    
    We have detected unauthorized access to your PayPal account. 
    Your account will be suspended within 24 hours unless you verify your information.
    
    Click here immediately to confirm your identity: http://paypa1-secure.com/verify
    
    You must provide your password and credit card details to restore access.
    
    Thank you,
    PayPal Security Team
    """
    
    print("=== Phishing Email Test ===")
    result = detector.analyze_email(phishing_subject, phishing_body)
    print(f"Verdict: {result['verdict']}")
    print(f"Risk Score: {result['risk_score']}/100 ({result['risk_level']})")
    print(f"Confidence: {result['confidence']}")
    print("Indicators found:")
    for ind in result['indicators']:
        print(f"  - {ind}")
    
    print("\n=== Legitimate Email Test ===")
    legit_subject = "Your order has shipped"
    legit_body = """
    Hi John,
    
    Great news! Your order #12345 has shipped and is on its way.
    
    You can track your package using the link in your account dashboard.
    
    Estimated delivery: January 30, 2026
    
    Thanks for shopping with us!
    
    Best regards,
    Customer Service
    """
    
    result = detector.analyze_email(legit_subject, legit_body)
    print(f"Verdict: {result['verdict']}")
    print(f"Risk Score: {result['risk_score']}/100 ({result['risk_level']})")
    print(f"Confidence: {result['confidence']}")
