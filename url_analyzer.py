# url_analyzer.py
"""
Enhanced URL Analysis Module for PhishShield
Provides domain age lookup, SSL certificate validation, and lexical pattern detection.
"""

import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
import tldextract

# Try to import python-whois (optional - graceful fallback if not installed)
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️ python-whois not installed. Domain age lookup disabled.")


# Common brand names for impersonation detection
BRAND_NAMES = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix',
    'instagram', 'twitter', 'linkedin', 'dropbox', 'chase', 'wellsfargo',
    'bankofamerica', 'citibank', 'usbank', 'capitalone', 'americanexpress',
    'visa', 'mastercard', 'ebay', 'walmart', 'target', 'costco', 'bestbuy',
    'spotify', 'adobe', 'zoom', 'slack', 'github', 'gitlab', 'steam',
    'epicgames', 'playstation', 'xbox', 'nintendo', 'venmo', 'cashapp',
    'coinbase', 'binance', 'kraken', 'fedex', 'ups', 'usps', 'dhl'
]

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = [
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'click',
    'link', 'info', 'online', 'site', 'website', 'space', 'pw', 'cc',
    'buzz', 'surf', 'cam', 'kim', 'men', 'download', 'stream', 'racing'
]

# Common phishing URL patterns
PHISHING_PATTERNS = [
    r'secure.*login', r'login.*secure', r'account.*verify', r'verify.*account',
    r'update.*info', r'confirm.*identity', r'suspended', r'locked',
    r'\.tk$', r'\.ml$', r'\.ga$', r'bit\.ly', r'tinyurl', r'goo\.gl',
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address
    r'@',  # @ symbol in URL
    r'-{2,}',  # Multiple hyphens
    r'[0-9]+[a-z]+[0-9]+',  # Mixed numbers and letters (e.g., paypa1)
]


class URLAnalyzer:
    """
    Comprehensive URL analyzer with domain age, SSL, and lexical analysis.
    """
    
    def __init__(self):
        self.whois_available = WHOIS_AVAILABLE
    
    def get_domain_age(self, domain):
        """
        Get domain age using WHOIS lookup.
        Returns dict with age_days, creation_date, and status.
        """
        result = {
            'available': False,
            'age_days': None,
            'creation_date': None,
            'expiration_date': None,
            'registrar': None,
            'status': 'unknown',
            'is_new': None,  # Less than 30 days old
            'is_suspicious': None  # Less than 365 days old
        }
        
        if not self.whois_available:
            result['status'] = 'whois_not_installed'
            return result
        
        try:
            w = whois.whois(domain)
            
            if w.creation_date:
                # Handle list or single date
                creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                
                if isinstance(creation, datetime):
                    # Make timezone-aware if needed
                    if creation.tzinfo is None:
                        creation = creation.replace(tzinfo=timezone.utc)
                    
                    now = datetime.now(timezone.utc)
                    age = now - creation
                    
                    result['available'] = True
                    result['age_days'] = age.days
                    result['creation_date'] = creation.strftime('%Y-%m-%d')
                    result['is_new'] = age.days < 30
                    result['is_suspicious'] = age.days < 365
                    result['status'] = 'success'
            
            if w.expiration_date:
                expiration = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                if isinstance(expiration, datetime):
                    result['expiration_date'] = expiration.strftime('%Y-%m-%d')
            
            if w.registrar:
                result['registrar'] = str(w.registrar)
                
        except Exception as e:
            result['status'] = f'error: {str(e)[:50]}'
        
        return result
    
    def check_ssl_certificate(self, url):
        """
        Check SSL certificate validity, issuer, and expiration.
        """
        result = {
            'has_ssl': False,
            'is_valid': False,
            'issuer': None,
            'subject': None,
            'expires': None,
            'days_until_expiry': None,
            'is_expired': None,
            'is_self_signed': None,
            'status': 'unknown'
        }
        
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path.split('/')[0]
        
        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        if not hostname:
            result['status'] = 'invalid_hostname'
            return result
        
        # Check if HTTPS
        result['has_ssl'] = parsed.scheme == 'https'
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    result['is_valid'] = True
                    result['status'] = 'valid'
                    
                    # Extract issuer
                    if cert.get('issuer'):
                        issuer_parts = dict(x[0] for x in cert['issuer'])
                        result['issuer'] = issuer_parts.get('organizationName', 'Unknown')
                    
                    # Extract subject
                    if cert.get('subject'):
                        subject_parts = dict(x[0] for x in cert['subject'])
                        result['subject'] = subject_parts.get('commonName', 'Unknown')
                    
                    # Check expiration
                    if cert.get('notAfter'):
                        expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        expires = expires.replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        
                        result['expires'] = expires.strftime('%Y-%m-%d')
                        result['days_until_expiry'] = (expires - now).days
                        result['is_expired'] = expires < now
                    
                    # Check for self-signed
                    result['is_self_signed'] = result['issuer'] == result['subject']
                    
        except ssl.SSLCertVerificationError as e:
            result['status'] = 'invalid_certificate'
            result['is_valid'] = False
        except socket.timeout:
            result['status'] = 'connection_timeout'
        except socket.gaierror:
            result['status'] = 'dns_resolution_failed'
        except ConnectionRefusedError:
            result['status'] = 'connection_refused'
        except Exception as e:
            result['status'] = f'error: {str(e)[:50]}'
        
        return result
    
    def analyze_lexical_patterns(self, url):
        """
        Analyze URL for suspicious lexical patterns and brand impersonation.
        """
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        
        result = {
            'suspicious_patterns': [],
            'brand_impersonation': [],
            'has_ip_address': False,
            'has_suspicious_tld': False,
            'has_at_symbol': False,
            'excessive_subdomains': False,
            'excessive_hyphens': False,
            'homoglyph_detected': False,
            'url_length_suspicious': False,
            'risk_factors': []
        }
        
        url_lower = url.lower()
        domain = ext.domain.lower()
        full_domain = f"{ext.subdomain}.{ext.domain}.{ext.suffix}".lower().strip('.')
        
        # Check for IP address
        if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            result['has_ip_address'] = True
            result['risk_factors'].append('URL uses IP address instead of domain name')
        
        # Check for suspicious TLD
        if ext.suffix.lower() in SUSPICIOUS_TLDS:
            result['has_suspicious_tld'] = True
            result['risk_factors'].append(f'Suspicious TLD: .{ext.suffix}')
        
        # Check for @ symbol
        if '@' in url:
            result['has_at_symbol'] = True
            result['risk_factors'].append('@ symbol in URL (can hide real destination)')
        
        # Check for excessive subdomains
        subdomain_count = ext.subdomain.count('.') + 1 if ext.subdomain else 0
        if subdomain_count > 3:
            result['excessive_subdomains'] = True
            result['risk_factors'].append(f'Excessive subdomains ({subdomain_count})')
        
        # Check for excessive hyphens
        hyphen_count = full_domain.count('-')
        if hyphen_count > 3:
            result['excessive_hyphens'] = True
            result['risk_factors'].append(f'Excessive hyphens in domain ({hyphen_count})')
        
        # Check URL length
        if len(url) > 100:
            result['url_length_suspicious'] = True
            result['risk_factors'].append(f'Unusually long URL ({len(url)} chars)')
        
        # Check for brand impersonation
        for brand in BRAND_NAMES:
            # Check if brand appears in URL but domain is NOT the official brand
            if brand in url_lower:
                # Check for typosquatting/homoglyphs
                if brand in domain or brand in ext.subdomain.lower():
                    # Check if it's the real domain
                    common_real_domains = [
                        f'{brand}.com', f'{brand}.net', f'{brand}.org',
                        f'www.{brand}.com', f'{brand}.co'
                    ]
                    if full_domain not in [d.lower() for d in common_real_domains]:
                        result['brand_impersonation'].append(brand)
                        result['risk_factors'].append(f'Possible {brand.title()} impersonation')
        
        # Check for homoglyphs (character substitution)
        homoglyph_patterns = {
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
            '@': 'a', '$': 's'
        }
        for char, letter in homoglyph_patterns.items():
            if char in domain:
                original = domain.replace(char, letter)
                if original in BRAND_NAMES:
                    result['homoglyph_detected'] = True
                    result['risk_factors'].append(f'Homoglyph detected: {char}→{letter} (may be impersonating {original})')
        
        # Check for common phishing patterns
        for pattern in PHISHING_PATTERNS:
            if re.search(pattern, url_lower):
                result['suspicious_patterns'].append(pattern)
        
        return result
    
    def calculate_risk_score(self, domain_info, ssl_info, lexical_info):
        """
        Calculate overall risk score (0-100) based on all analysis.
        """
        score = 0
        
        # Domain age factors
        if domain_info.get('is_new'):
            score += 25
        elif domain_info.get('is_suspicious'):
            score += 15
        
        # SSL factors
        if not ssl_info.get('has_ssl'):
            score += 15
        if ssl_info.get('is_valid') == False and ssl_info.get('status') != 'unknown':
            score += 20
        if ssl_info.get('is_self_signed'):
            score += 15
        if ssl_info.get('is_expired'):
            score += 20
        
        # Lexical factors
        if lexical_info.get('has_ip_address'):
            score += 20
        if lexical_info.get('has_suspicious_tld'):
            score += 15
        if lexical_info.get('has_at_symbol'):
            score += 20
        if lexical_info.get('brand_impersonation'):
            score += 25
        if lexical_info.get('homoglyph_detected'):
            score += 20
        if lexical_info.get('excessive_subdomains'):
            score += 10
        if lexical_info.get('excessive_hyphens'):
            score += 10
        if lexical_info.get('url_length_suspicious'):
            score += 5
        
        return min(score, 100)
    
    def get_comprehensive_report(self, url):
        """
        Generate a comprehensive URL analysis report.
        """
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        
        # Run all analyses
        domain_info = self.get_domain_age(domain)
        ssl_info = self.check_ssl_certificate(url)
        lexical_info = self.analyze_lexical_patterns(url)
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(domain_info, ssl_info, lexical_info)
        
        # Determine verdict
        if risk_score >= 60:
            risk_level = 'High'
            verdict = 'Suspicious'
        elif risk_score >= 30:
            risk_level = 'Medium'
            verdict = 'Caution'
        else:
            risk_level = 'Low'
            verdict = 'Likely Safe'
        
        # Elevate to Critical if SSL certificate is invalid
        if ssl_info.get('is_valid') == False and ssl_info.get('status') in ['invalid_certificate', 'error']:
            risk_level = 'Critical'
            verdict = 'Critical'
        elif ssl_info.get('is_expired'):
            risk_level = 'Critical'
            verdict = 'Critical'
        elif ssl_info.get('is_self_signed'):
            risk_level = 'Critical'
            verdict = 'Critical'
        
        return {
            'url': url,
            'domain': domain,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'verdict': verdict,
            'domain_analysis': domain_info,
            'ssl_analysis': ssl_info,
            'lexical_analysis': lexical_info,
            'all_risk_factors': lexical_info.get('risk_factors', [])
        }


# Convenience function
def analyze_url(url):
    """Quick URL analysis function."""
    analyzer = URLAnalyzer()
    return analyzer.get_comprehensive_report(url)


if __name__ == "__main__":
    analyzer = URLAnalyzer()
    
    # Test with a legitimate URL
    print("=" * 60)
    print("Testing: https://www.google.com")
    print("=" * 60)
    report = analyzer.get_comprehensive_report("https://www.google.com")
    print(f"Verdict: {report['verdict']}")
    print(f"Risk Score: {report['risk_score']}/100 ({report['risk_level']})")
    print(f"SSL Valid: {report['ssl_analysis'].get('is_valid')}")
    print(f"SSL Issuer: {report['ssl_analysis'].get('issuer')}")
    
    # Test with a suspicious URL pattern
    print("\n" + "=" * 60)
    print("Testing: http://paypa1-secure-login.tk/verify-account")
    print("=" * 60)
    report = analyzer.get_comprehensive_report("http://paypa1-secure-login.tk/verify-account")
    print(f"Verdict: {report['verdict']}")
    print(f"Risk Score: {report['risk_score']}/100 ({report['risk_level']})")
    print("Risk Factors:")
    for factor in report['all_risk_factors']:
        print(f"  - {factor}")
