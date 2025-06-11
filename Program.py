import re

def is_phishing_url(url):
    print(f"\nChecking URL: {url}")

    # Rule 1: Check for IP address in URL
    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        print("⚠️  Contains IP address")
        return True

    # Rule 2: Check for multiple hyphens
    if '--' in url:
        print("⚠️  Contains multiple hyphens")
        return True

    # Rule 3: Suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
    for tld in suspicious_tlds:
        if url.endswith(tld):
            print(f"⚠️  Suspicious TLD: {tld}")
            return True

    # Rule 4: Very long URLs
    if len(url) > 75:
        print("⚠️  URL is unusually long")
        return True

    print("✅ Safe URL")
    return False


# Sample test URLs
urls = [
    "http://192.168.1.1/login",
    "http://example--secure.tk",
    "https://www.google.com",
    "http://very-long-url-example.com/with/a/very/long/path/that/goes/on/and/on/and/on",
    "http://secure-login.ga"
]

for url in urls:
    result = is_phishing_url(url)