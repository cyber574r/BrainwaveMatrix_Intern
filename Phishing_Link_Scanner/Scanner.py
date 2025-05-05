import re
import math
import tldextract
from urllib.parse import urlparse
from collections import defaultdict

# ======== Configuration ========
COMMON_BRANDS = {
    'facebook': ['faceb00k', 'facebok', 'fac3book', 'fb-login'],
    'paypal': ['paypa1', 'paypai', 'paypai'],
    'amazon': ['amaz0n', 'amzon', 'amz0n'],
    'google': ['g00gle', 'go0gle', 'googlee'],
    'microsoft': ['micr0soft', 'mircosoft', 'ms-login'],
    'netflix': ['netfl1x', 'netflixx', 'n3tflix'],
    'bank': ['b4nk', 'bankk', 'online-bank'],
    'apple': ['app1e', 'aple', 'apple-id']
}

SUSPICIOUS_TLDS = ['.buzz','.tk','.gq','.ml','.ga','.cf','.xyz','.top']
SENSITIVE_PATHS = ['login','verify','secure','account','confirm','password','update', 'malware', 'phishing']

# ======== Helper Functions ========
def calculate_entropy(text):
    """Calculate Shannon entropy for string"""
    if not text:
        return 0
    entropy = 0
    for char in set(text):
        p_x = float(text.count(char)) / len(text)
        entropy += - p_x * math.log(p_x, 2)
    return round(entropy, 2)

def check_typosquatting(domain):
    """Detect brand impersonation with typos"""
    domain = domain.lower()
    for brand, variants in COMMON_BRANDS.items():
        # Check exact brand match (legitimate)
        if domain == f"www.{brand}.com" or domain == f"{brand}.com":
            return None  
        # Check variants (malicious)
        for variant in variants:
            if variant in domain:
                return f"Brand impersonation ({variant} vs {brand})"
    return None

# ======== Core Detection ========
def analyze_url(url):
    """Comprehensive URL analysis with threat classification"""
    findings = defaultdict(list)
    
    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://', 'www')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path.lower()
        ext = tldextract.extract(url)
        
        # 1. Critical Checks (Malicious Indicators)
        # Typosquatting detection
        ts_result = check_typosquatting(domain)
        if ts_result:
            findings['critical'].append(ts_result)
        
        # Suspicious TLDs
        if any(tld in domain for tld in SUSPICIOUS_TLDS):
            findings['critical'].append(f"Suspicious TLD ({ext.suffix})")
        
        # IP address usage
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}', domain):
            findings['critical'].append("Uses IP address instead of domain")
        
        # 2. Suspicious Indicators
        # Sensitive paths
        if any(keyword in path for keyword in SENSITIVE_PATHS):
            findings['suspicious'].append(f"Sensitive path detected ({path})")
        
        # Subdomain checks
        if '-login.' in domain or '-secure.' in domain:
            findings['suspicious'].append("Suspicious subdomain structure")
        
        # Entropy analysis
        if calculate_entropy(ext.domain) > 3.5:
            findings['suspicious'].append(f"High domain entropy ({calculate_entropy(ext.domain)})")
        
        # 3. Security Warnings
        if parsed.scheme != 'https':
            findings['warnings'].append("No HTTPS encryption")
        
        if len(path) > 60:
            findings['warnings'].append("Unusually long URL path")
            
    except Exception as e:
        findings['errors'].append(f"Analysis error: {str(e)}")
    
    return findings

def classify_threat(findings):
    """Determine threat level based on findings"""
    if findings.get('critical'):
        return "MALICIOUS"
    elif findings.get('suspicious'):
        return "SUSPICIOUS"
    elif findings.get('warnings'):
        return "LOW_RISK"
    else:
        return "CLEAN"

# ======== Reporting ========
def generate_report(url, findings, threat_level):
    """Generate human-readable report"""
    print(f"\n{'='*50}\nScanning: {url}")
    print(f"\nThreat Level: {threat_level.replace('_', ' ').title()}")
    
    if threat_level == "CLEAN":
        print("\n✅ This link is clean and legitimate")
        return
    
    if threat_level == "MALICIOUS":
        print("\n🚨 This link is MALICIOUS because:")
        for issue in findings['critical']:
            print(f"  ✖ {issue}")
    
    if threat_level == "SUSPICIOUS":
        print("\n⚠ This link is SUSPICIOUS because:")
        for issue in findings['suspicious']:
            print(f"  • {issue}")
    
    if findings.get('warnings'):
        print("\nSecurity Notes:")
        for note in findings['warnings']:
            print(f"  ! {note}")

# ======== Main Function ========
def main():
    print("🔍 Advanced Phishing URL Scanner")
    print("Enter URLs to scan (one per line). Type 'done' to finish.\n")
    
    urls = []
    while True:
        try:
            url = input("URL: ").strip()
            if url.lower() == 'done':
                break
            if url:  # Skip empty inputs
                urls.append(url)
        except (KeyboardInterrupt, EOFError):
            print("\nScan cancelled by user")
            return
    
    if not urls:
        print("No URLs provided")
        return
    
    print("\n=== Scan Results ===")
    for url in set(urls):  # Remove duplicates
        findings = analyze_url(url)
        threat_level = classify_threat(findings)
        generate_report(url, findings, threat_level)

if __name__ == "__main__":
    main()