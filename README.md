🎯 PhishShield – AI-Powered Phishing URL Detection
🔐 PhishShield is a lightweight, fast, and intelligent phishing-URL detection system.
Paste any URL → instantly know whether it’s 🟢 Trusted or 🔴 Untrusted.
Built using Python, Flask, and a Machine Learning model (Random Forest) trained on URL features.

🚀 Live Features
✨ Copy-paste a URL and scan instantly
⚡ Fast classification using ML
🎨 Modern hacker-themed animated UI
🛡️ Shows clear visual icons for trusted/untrusted URLs
🧠 Built-in feature extraction (URL length, dots, keywords, IP use, etc.)
💾 Supports external model downloading (via MODEL_URL)

🧠 How It Works
PhishShield uses several URL-based features:
🔸 URL length
🔸 Number of dots
🔸 Presence of IP address
🔸 Suspicious keywords (login, secure, account)
🔸 Hyphen count
🔸 Subdomain depth
These are sent into a Random Forest Classifier, which predicts either:
🟢 Trusted
🔴 Untrusted

💡 Future Improvements
Here are upgrade ideas:
🔍 Integrate Google Safe Browsing API
📡 Add live WHOIS & SSL certificate analysis
🧠 Switch ML model → XGBoost / LightGBM
📈 Add accuracy dashboard on admin page
🌐 Dockerize for faster deployment
