import math
import requests
import hashlib

def is_password_breached(password):
    """Check if password exists in HaveIBeenPwned's database."""
    try:
        # Hash the password using SHA-1 (required by HIBP API)
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        # Query HIBP API
        api_url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(api_url, timeout=5)  # Timeout to avoid hanging
        
        # Check if the suffix (remaining hash) exists in the response
        return suffix in response.text
    except (requests.RequestException, ValueError):
        return False  # Assume password is safe if API fails

def password_strength(password):
    """Calculate password strength score (0-100)."""
    # Check length
    length = len(password)
    if length < 8:
        return "Password must be above 8 characters and above!!"
    
    # Check character variety
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    # Calculate entropy (bits)
    charset = 0
    if has_lower: charset += 26
    if has_upper: charset += 26
    if has_digit: charset += 10
    if has_special: charset += 32
    entropy = len(password) * math.log2(charset) if charset else 0
    
    # Check if password is common (simplified example)
    common_passwords = ["123456", "password", "qwerty", "123456789"]
    is_common = password.lower() in common_passwords
    
    # Check if breached (using HIBP API)
    is_breached = is_password_breached(password)
    
    # Calculate score (0-100)
    score = 0
    score += min(length, 20) * 3  # Max 60 for length
    score += 10 * (has_upper + has_lower + has_digit + has_special)  # Max 40
    if is_common: score -= 30
    if is_breached: score -= 50
    
    # Classify strength
    if score >= 80: return "Strong Password✅"
    elif score >= 60: return "Moderate Password⚠️"
    elif score >= 40: return "Weak Password❌"
    else: return "Very Weak (Breached/Common) 🚨"

# Example usage
if __name__ == "__main__":
    password = input("Enter your password to check it's strength: ")
    print(password_strength(password))