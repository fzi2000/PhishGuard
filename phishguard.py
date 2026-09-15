import re
from urllib.parse import urlparse


# ============================================================
# SECURITY KNOWLEDGE
# ============================================================

SUSPICIOUS_URL_WORDS = [
    "login", "signin", "verify", "verification",
    "account", "secure", "security", "update",
    "password", "confirm", "bank", "payment",
    "wallet", "billing", "authorize", "credential",
    "unlock", "suspended", "validate"
]

URGENCY_WORDS = [
    "urgent",
    "immediately",
    "as soon as possible",
    "action required",
    "act now",
    "warning",
    "expires",
    "suspended",
    "final notice",
    "within 24 hours"
]

CREDENTIAL_WORDS = [
    "password",
    "username",
    "login",
    "credential",
    "pin",
    "security code",
    "verification code",
    "otp",
    "bank account",
    "credit card"
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly"
]

FREE_EMAIL_PROVIDERS = [
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com"
]

# Brands commonly impersonated in phishing
BRANDS = {
    "microsoft": [
        "microsoft.com",
        "office.com",
        "live.com"
    ],
    "paypal": [
        "paypal.com"
    ],
    "amazon": [
        "amazon.com",
        "amazon.ae"
    ],
    "apple": [
        "apple.com",
        "icloud.com"
    ],
    "google": [
        "google.com",
        "googlemail.com"
    ],
    "dhl": [
        "dhl.com"
    ],
    "netflix": [
        "netflix.com"
    ],
    "linkedin": [
        "linkedin.com"
    ]
}


# ============================================================
# IOC EXTRACTION
# ============================================================

def extract_urls(text):
    """Extract HTTP/HTTPS URLs from an email."""
    
    if not text:
        return []

    pattern = r'https?://[^\s<>"\']+'

    return re.findall(pattern, text)


def extract_domains(text):
    """Extract domains from URLs."""

    urls = extract_urls(text)

    domains = []

    for url in urls:

        try:
            parsed = urlparse(url)

            domain = parsed.netloc.lower()

            if domain.startswith("www."):
                domain = domain[4:]

            if domain and domain not in domains:
                domains.append(domain)

        except Exception:
            pass

    return domains


def extract_email_addresses(text):
    """Extract email addresses from the message."""

    if not text:
        return []

    pattern = r'[\w\.-]+@[\w\.-]+\.\w+'

    emails = re.findall(pattern, text)

    return list(dict.fromkeys(emails))


# ============================================================
# URL ANALYSIS
# ============================================================

def has_ip(domain):

    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    return bool(re.match(pattern, domain))


def analyze_url(url):

    score = 0
    reasons = []

    original_url = url

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    url = url.lower()

    parsed = urlparse(url)

    domain = parsed.netloc

    # Remove port
    domain = domain.split(":")[0]

    # HTTPS check
    if parsed.scheme != "https":

        score += 15

        reasons.append(
            "URL does not use HTTPS"
        )

    # IP address
    if has_ip(domain):

        score += 30

        reasons.append(
            "URL uses an IP address instead of a domain"
        )

    # Suspicious keywords
    found_words = []

    for word in SUSPICIOUS_URL_WORDS:

        if word in url:

            found_words.append(word)

    if found_words:

        score += min(len(found_words) * 5, 25)

        reasons.append(
            "Suspicious URL keywords: "
            + ", ".join(found_words)
        )

    # Long URL
    if len(url) > 100:

        score += 15

        reasons.append(
            "Unusually long URL"
        )

    # @ symbol
    if "@" in url:

        score += 20

        reasons.append(
            "URL contains '@' symbol"
        )

    # Many subdomains
    if domain.count(".") >= 3:

        score += 15

        reasons.append(
            "Large number of subdomains"
        )

    # URL shortener
    if domain in SHORTENERS:

        score += 20

        reasons.append(
            "URL uses a URL shortening service"
        )

    # Multiple hyphens
    if domain.count("-") >= 3:

        score += 10

        reasons.append(
            "Domain contains many hyphens"
        )

    score = min(score, 100)

    return {
        "url": original_url,
        "domain": domain,
        "score": score,
        "reasons": reasons
    }


def analyze_urls(text):

    urls = extract_urls(text)

    results = [
        analyze_url(url)
        for url in urls
    ]

    if not results:

        return {
            "count": 0,
            "max_score": 0,
            "results": []
        }

    return {
        "count": len(results),
        "max_score": max(
            result["score"]
            for result in results
        ),
        "results": results
    }


# ============================================================
# SOCIAL ENGINEERING ANALYSIS
# ============================================================

def analyze_language(text):

    text = text.lower()

    score = 0

    reasons = []

    # --------------------------------------------------------
    # Urgency
    # --------------------------------------------------------

    found_urgency = []

    for word in URGENCY_WORDS:

        if word in text:
            found_urgency.append(word)

    if found_urgency:

        score += min(
            len(found_urgency) * 8,
            30
        )

        reasons.append(
            "Urgency or pressure language detected"
        )

    # --------------------------------------------------------
    # Credential harvesting
    # --------------------------------------------------------

    found_credentials = []

    for word in CREDENTIAL_WORDS:

        if word in text:
            found_credentials.append(word)

    if found_credentials:

        score += min(
            len(found_credentials) * 8,
            35
        )

        reasons.append(
            "Possible credential or sensitive-information request"
        )

    # --------------------------------------------------------
    # Excessive exclamation marks
    # --------------------------------------------------------

    if text.count("!") >= 3:

        score += 10

        reasons.append(
            "Excessive use of exclamation marks"
        )

    # --------------------------------------------------------
    # Account verification
    # --------------------------------------------------------

    verification_patterns = [

        "verify your account",
        "confirm your account",
        "update your account",
        "account has been suspended",
        "click here to verify",
        "confirm your identity",
        "reset your password"

    ]

    found_patterns = []

    for pattern in verification_patterns:

        if pattern in text:

            found_patterns.append(pattern)

    if found_patterns:

        score += 20

        reasons.append(
            "Account verification language detected"
        )

    score = min(score, 100)

    return score, reasons


# ============================================================
# SENDER ANALYSIS
# ============================================================

def analyze_sender(sender):

    score = 0

    reasons = []

    if not sender:

        return score, reasons

    sender = sender.lower().strip()

    match = re.search(
        r'[\w\.-]+@[\w\.-]+\.\w+',
        sender
    )

    if not match:

        return score, reasons

    email = match.group(0)

    domain = email.split("@")[-1]

    # Numbers in domain
    if any(char.isdigit() for char in domain):

        score += 10

        reasons.append(
            "Sender domain contains numbers"
        )

    # Multiple hyphens
    if domain.count("-") >= 2:

        score += 15

        reasons.append(
            "Sender domain contains multiple hyphens"
        )

    # Security-related domain names
    suspicious_domain_words = [

        "secure",
        "verify",
        "login",
        "account",
        "support",
        "update",
        "alert"

    ]

    found = []

    for word in suspicious_domain_words:

        if word in domain:

            found.append(word)

    if found:

        score += 15

        reasons.append(
            "Sender domain contains security-related keywords"
        )

    # Public email provider
    if domain in FREE_EMAIL_PROVIDERS:

        score += 5

        reasons.append(
            "Sender uses a public email provider"
        )

    score = min(score, 100)

    return score, reasons


# ============================================================
# BRAND IMPERSONATION
# ============================================================

def detect_brand_impersonation(text, sender):

    text_lower = text.lower()

    sender_lower = sender.lower()

    detected = []

    reasons = []

    sender_match = re.search(
        r'[\w\.-]+@([\w\.-]+\.\w+)',
        sender_lower
    )

    sender_domain = ""

    if sender_match:

        sender_domain = sender_match.group(1)

    for brand, legitimate_domains in BRANDS.items():

        # Is the brand mentioned?
        if brand in text_lower:

            detected.append(brand)

            # Does sender belong to legitimate domain?
            legitimate = any(
                sender_domain == domain
                or sender_domain.endswith("." + domain)
                for domain in legitimate_domains
            )

            if not legitimate:

                reasons.append(
                    f"Possible {brand.title()} impersonation"
                )

    if reasons:

        return 30, detected, reasons

    return 0, detected, reasons


# ============================================================
# ATTACK CLASSIFICATION
# ============================================================

def classify_attack(
    text,
    url_analysis,
    language_score,
    sender_score,
    impersonation_score
):

    text_lower = text.lower()

    attacks = []

    # Credential phishing
    credential_terms = [
        "password",
        "login",
        "credential",
        "verify your account",
        "reset your password",
        "username"
    ]

    if any(
        term in text_lower
        for term in credential_terms
    ):

        attacks.append(
            "Credential Phishing"
        )

    # Financial fraud
    financial_terms = [
        "invoice",
        "payment",
        "bank",
        "transfer",
        "wire",
        "credit card",
        "refund"
    ]

    if any(
        term in text_lower
        for term in financial_terms
    ):

        attacks.append(
            "Financial / Payment Fraud"
        )

    # Account takeover
    account_terms = [
        "account suspended",
        "account locked",
        "verify your account",
        "security alert",
        "unusual login"
    ]

    if any(
        term in text_lower
        for term in account_terms
    ):

        attacks.append(
            "Account Takeover Attempt"
        )

    # Malicious link
    if url_analysis["max_score"] >= 40:

        attacks.append(
            "Malicious Link Delivery"
        )

    # Social engineering
    if language_score >= 40:

        attacks.append(
            "Social Engineering"
        )

    # Impersonation
    if impersonation_score > 0:

        attacks.append(
            "Brand Impersonation"
        )

    if not attacks:

        attacks.append(
            "No obvious attack pattern detected"
        )

    return list(dict.fromkeys(attacks))


# ============================================================
# MITRE ATT&CK MAPPING
# ============================================================

def map_mitre_techniques(attacks):

    mapping = {

        "Credential Phishing": {
            "id": "T1566.002",
            "name": "Phishing: Spearphishing Link"
        },

        "Malicious Link Delivery": {
            "id": "T1566.002",
            "name": "Phishing: Spearphishing Link"
        },

        "Social Engineering": {
            "id": "T1566",
            "name": "Phishing"
        },

        "Brand Impersonation": {
            "id": "T1036",
            "name": "Masquerading"
        },

        "Account Takeover Attempt": {
            "id": "T1078",
            "name": "Valid Accounts"
        },

        "Financial / Payment Fraud": {
            "id": "T1657",
            "name": "Financial Theft"
        }
    }

    techniques = []

    for attack in attacks:

        if attack in mapping:

            technique = mapping[attack]

            if technique not in techniques:

                techniques.append(technique)

    return techniques


# ============================================================
# RISK ENGINE
# ============================================================

def calculate_risk(
    ml_probability,
    url_score,
    sender_score,
    language_score,
    impersonation_score=0
):

    final_score = (

        ml_probability * 40

        + url_score * 20 / 100

        + sender_score * 10 / 100

        + language_score * 15 / 100

        + impersonation_score * 15 / 100

    )

    # Convert URL/sender/language components
    # to percentage contribution correctly

    final_score = (

        ml_probability * 40

        + url_score * 0.20

        + sender_score * 0.10

        + language_score * 0.15

        + impersonation_score * 0.15

    )

    final_score = min(
        round(final_score, 1),
        100
    )

    if final_score >= 70:

        verdict = "HIGH RISK"
        action = "BLOCK"
        severity = "high"

    elif final_score >= 40:

        verdict = "SUSPICIOUS"
        action = "REVIEW"
        severity = "medium"

    else:

        verdict = "LOW RISK"
        action = "ALLOW"
        severity = "low"

    return (
        final_score,
        verdict,
        action,
        severity
    )


# ============================================================
# FULL SECURITY INVESTIGATION
# ============================================================

def investigate_email(
    sender,
    subject,
    body,
    ml_probability
):

    email_text = (
        subject
        + " "
        + body
    )

    # URL investigation
    url_analysis = analyze_urls(
        email_text
    )

    # Language investigation
    language_score, language_reasons = (
        analyze_language(email_text)
    )

    # Sender investigation
    sender_score, sender_reasons = (
        analyze_sender(sender)
    )

    # Brand impersonation
    impersonation_score, brands, impersonation_reasons = (
        detect_brand_impersonation(
            email_text,
            sender
        )
    )

    # Attack classification
    attacks = classify_attack(
        email_text,
        url_analysis,
        language_score,
        sender_score,
        impersonation_score
    )

    # MITRE mapping
    mitre = map_mitre_techniques(
        attacks
    )

    # Risk correlation
    final_score, verdict, action, severity = (
        calculate_risk(
            ml_probability,
            url_analysis["max_score"],
            sender_score,
            language_score,
            impersonation_score
        )
    )

    # ========================================================
    # IOC COLLECTION
    # ========================================================

    iocs = {

        "email_addresses":
            extract_email_addresses(
                email_text
            ),

        "urls":
            extract_urls(
                email_text
            ),

        "domains":
            extract_domains(
                email_text
            )

    }

    # ========================================================
    # SECURITY INDICATORS
    # ========================================================

    indicators = []

    indicators.extend(
        language_reasons
    )

    indicators.extend(
        sender_reasons
    )

    indicators.extend(
        impersonation_reasons
    )

    for result in url_analysis["results"]:

        indicators.extend(
            result["reasons"]
        )

    indicators = list(
        dict.fromkeys(indicators)
    )

    return {

        "risk_score": final_score,

        "verdict": verdict,

        "action": action,

        "severity": severity,

        "ml_probability":
            round(
                ml_probability * 100,
                1
            ),

        "url_analysis":
            url_analysis,

        "sender_score":
            sender_score,

        "language_score":
            language_score,

        "impersonation_score":
            impersonation_score,

        "brands_detected":
            brands,

        "attacks":
            attacks,

        "mitre":
            mitre,

        "iocs":
            iocs,

        "indicators":
            indicators

    }