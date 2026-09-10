import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    ("urgent", 8), ("immediately", 7), ("verify", 6), ("verification", 6),
    ("suspended", 10), ("password", 9), ("otp", 10), ("bank", 5),
    ("login", 6), ("click here", 8), ("account will be", 6),
    ("security alert", 8), ("confirm your", 6), ("limited time", 6),
]

def add_signal(signals, name, points):
    signals.append({"name": name, "points": points})

def get_urls(text):
    return re.findall(r'https?://[^\s\'"<>]+', text, flags=re.I)

def analyze_input(content: str, input_type: str = "auto"):
    text = content.strip()
    lower = text.lower()
    score = 0
    signals = []

    urls = get_urls(text)

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.hostname or ""

        if parsed.scheme.lower() == "http":
            score += 12
            add_signal(signals, "Connection is not secure (HTTP)", 12)

        if len(domain) > 28:
            score += 7
            add_signal(signals, "Long domain name", 7)

        if domain.count(".") >= 3:
            score += 8
            add_signal(signals, "Multiple subdomains detected", 8)

        if "-" in domain:
            score += 5
            add_signal(signals, "Hyphenated domain pattern", 5)

        if re.search(r"\d{3,}", domain):
            score += 7
            add_signal(signals, "Unusual numeric domain pattern", 7)

        if re.search(r"(login|verify|secure|account|update|bank|signin|password)", domain):
            score += 10
            add_signal(signals, "Sensitive keyword in domain", 10)

        if "@" in url:
            score += 12
            add_signal(signals, "Obfuscated URL structure", 12)

    for word, points in SUSPICIOUS_WORDS:
        if word in lower:
            score += points
            add_signal(signals, f'Suspicious language: "{word}"', points)

    if re.search(r"(bit\.ly|tinyurl|t\.co|goo\.gl|shorturl)", lower):
        score += 12
        add_signal(signals, "URL shortener detected", 12)

    if re.search(r"(free|winner|prize|gift|refund|claim now)", lower):
        score += 9
        add_signal(signals, "Possible lure or reward language", 9)

    if re.search(r"https?://.*\.(zip|exe|scr|bat)(\b|$)", lower):
        score += 18
        add_signal(signals, "Potentially dangerous file link", 18)

    score = min(score, 100)

    if score >= 65:
        classification = "PHISHING"
        action = "QUARANTINE / BLOCK"
        severity = "high"
    elif score >= 35:
        classification = "SUSPICIOUS"
        action = "WARN / REVIEW"
        severity = "medium"
    else:
        classification = "LEGITIMATE"
        action = "ALLOW"
        severity = "low"

    # De-duplicate signal names
    unique = []
    seen = set()
    for signal in signals:
        if signal["name"] not in seen:
            seen.add(signal["name"])
            unique.append(signal)

    return {
        "score": score,
        "classification": classification,
        "severity": severity,
        "recommended_action": action,
        "signals": unique,
        "urls_found": len(urls),
        "input_length": len(text),
        "analysis_engine": "Phishing Guard AI — Explainable Rule Engine",
    }
