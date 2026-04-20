"""
url_features.py
PhishGuard — URL Feature Extraction Module
Kraken'X 2026 Hackathon

Extracts handcrafted features from URLs for phishing detection.
Compatible with scikit-learn pipelines.
"""

import re
import math
from urllib.parse import urlparse


# ──────────────────────────────────────────────
# SUSPICIOUS KEYWORD LISTS
# ──────────────────────────────────────────────

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update", "confirm", "account",
    "banking", "paypal", "password", "credential", "signin", "wallet",
    "alert", "suspend", "unlock", "validate", "authorize", "support"
]

TRUSTED_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".io"}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "buff.ly", "is.gd", "rebrand.ly", "short.io", "cutt.ly"
}


# ──────────────────────────────────────────────
# HELPER FUNCTIONS
# ──────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (high entropy = random-looking = suspicious)."""
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def _is_ip_address(hostname: str) -> int:
    """Return 1 if hostname is a raw IP address."""
    pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    return int(bool(pattern.match(hostname)))


def _count_subdomains(hostname: str) -> int:
    """Count number of subdomains (dots minus 1 for domain.tld)."""
    parts = hostname.split(".")
    return max(0, len(parts) - 2)


# ──────────────────────────────────────────────
# MAIN FEATURE EXTRACTOR
# ──────────────────────────────────────────────

def extract_url_features(url: str) -> dict:
    """
    Extract a feature dictionary from a single URL string.

    Parameters
    ----------
    url : str
        Raw URL string (e.g. "http://secure-login.paypal.verify.com/account")

    Returns
    -------
    dict
        Feature dictionary with numeric values, ready for ML model input.
    """
    features = {}

    # ── Parse URL ──
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        full = url.lower()
    except Exception:
        # Return zeroed features on parse failure
        return {k: 0 for k in _feature_keys()}

    # ── Length-based features ──
    features["url_length"] = len(url)
    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    # ── Symbol-based features ──
    features["count_dots"] = url.count(".")
    features["count_hyphens"] = url.count("-")
    features["count_underscores"] = url.count("_")
    features["count_slashes"] = url.count("/")
    features["count_at"] = url.count("@")          # @ in URL = big red flag
    features["count_equals"] = url.count("=")
    features["count_question"] = url.count("?")
    features["count_percent"] = url.count("%")      # URL encoding abuse
    features["count_digits"] = sum(c.isdigit() for c in url)
    features["digit_ratio"] = features["count_digits"] / max(len(url), 1)

    # ── Structural features ──
    features["is_https"] = int(parsed.scheme == "https")
    features["is_ip_address"] = _is_ip_address(hostname)
    features["num_subdomains"] = _count_subdomains(hostname)
    features["has_port"] = int(parsed.port is not None)
    features["is_shortener"] = int(hostname in SHORTENERS)

    # ── TLD features ──
    tld = "." + hostname.split(".")[-1] if "." in hostname else ""
    features["is_trusted_tld"] = int(tld in TRUSTED_TLDS)
    features["tld_length"] = len(tld)

    # ── Keyword features ──
    features["phishing_keyword_count"] = sum(
        kw in full for kw in PHISHING_KEYWORDS
    )
    features["has_login_keyword"] = int("login" in full or "signin" in full)
    features["has_verify_keyword"] = int("verify" in full or "confirm" in full)
    features["has_secure_keyword"] = int("secure" in full or "security" in full)
    features["has_update_keyword"] = int("update" in full or "validate" in full)

    # ── Brand spoofing signals ──
    BRANDS = ["paypal", "google", "facebook", "amazon", "apple",
              "microsoft", "netflix", "instagram", "twitter", "bank"]
    features["brand_in_subdomain"] = int(
        any(b in hostname.replace(hostname.split(".")[-2] + "." + hostname.split(".")[-1], "")
            for b in BRANDS) if hostname.count(".") >= 2 else 0
    )
    features["brand_in_path"] = int(any(b in path.lower() for b in BRANDS))

    # ── Entropy features ──
    features["hostname_entropy"] = round(_shannon_entropy(hostname), 4)
    features["path_entropy"] = round(_shannon_entropy(path), 4)

    # ── Double slash / redirect ──
    features["has_double_slash_redirect"] = int("//" in path)
    features["has_hex_encoding"] = int("%2" in url or "%3" in url)

    return features


def _feature_keys() -> list:
    """Return list of all feature names (for consistent column ordering)."""
    sample = extract_url_features("http://example.com")
    return list(sample.keys())


def extract_features_batch(urls: list) -> list:
    """
    Extract features for a list of URLs.

    Parameters
    ----------
    urls : list of str

    Returns
    -------
    list of dict
    """
    return [extract_url_features(url) for url in urls]


# ──────────────────────────────────────────────
# QUICK TEST (run directly: python url_features.py)
# ──────────────────────────────────────────────

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=python",                         # Legit
        "http://paypal-secure-login.verify-account.com/update/password",  # Phishing
        "http://192.168.1.1/admin/login.php",                             # IP-based
        "https://bit.ly/3xPhish",                                         # Shortener
        "http://amazon.com.secure-update.net/signin",                     # Brand spoof
    ]

    print(f"{'URL':<55} {'Phish KWs':>10} {'Subdomains':>12} {'Is IP':>6} {'HTTPS':>6} {'Entropy':>8}")
    print("-" * 100)
    for url in test_urls:
        f = extract_url_features(url)
        print(
            f"{url[:54]:<55} "
            f"{f['phishing_keyword_count']:>10} "
            f"{f['num_subdomains']:>12} "
            f"{f['is_ip_address']:>6} "
            f"{f['is_https']:>6} "
            f"{f['hostname_entropy']:>8.3f}"
        )
