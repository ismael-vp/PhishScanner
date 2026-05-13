import logging
import math
import re
from typing import Any
from urllib.parse import urlparse

import tldextract

from services.utils import calculate_risk_level, levenshtein_similarity

logger = logging.getLogger(__name__)

MAX_URL_LENGTH = 2048
ENTROPY_THRESHOLD = 0.85
LEVENSHTEIN_THRESHOLD = 0.80
MIN_WORD_LENGTH = 4

SUSPICIOUS_KEYWORDS: list[tuple[str, int, str]] = [
    ("login", 15, "Login"),
    ("verify", 15, "Verify"),
    ("secure", 10, "Secure"),
    ("account", 10, "Account"),
    ("update", 10, "Update"),
    ("auth", 10, "Auth"),
    ("signin", 15, "Signin"),
    ("billing", 10, "Billing"),
    ("confirm", 10, "Confirm"),
    ("support", 5, "Support"),
    ("wallet", 10, "Wallet"),
    ("recovery", 10, "Recovery"),
    ("clone", 15, "Clone"),
    ("authenticate", 10, "Authenticate"),
    ("validation", 10, "Validation"),
    ("security", 5, "Security"),
    ("payment", 10, "Payment"),
    ("bank", 10, "Bank"),
    ("crypto", 10, "Crypto"),
]

ABUSED_FREE_HOSTING: list[tuple[str, int]] = [
    ("github.io", 25),
    ("gitlab.io", 25),
    ("herokuapp.com", 25),
    ("vercel.app", 25),
    ("netlify.app", 25),
    ("firebaseapp.com", 25),
    ("web.app", 25),
    ("glitch.me", 25),
    ("repl.co", 25),
    ("000webhostapp.com", 30),
    ("blogspot.com", 20),
    ("weebly.com", 20),
    ("wixsite.com", 20),
    ("wordpress.com", 20),
    ("pages.dev", 25),
    ("workers.dev", 25),
    ("surge.sh", 25),
    ("neocities.org", 20),
    ("tripod.com", 20),
    ("angelfire.com", 20),
]

TARGET_BRANDS: list[tuple[str, set[str], set[str]]] = [
    ("google", {"com", "co.uk", "de", "fr", "es", "it", "co.jp", "com.br", "com.mx", "co.in"}, {"googleapis", "googleusercontent", "gstatic", "youtube", "googlevideo"}),
    ("facebook", {"com", "co.uk", "de", "fr", "es"}, {"fbcdn", "instagram", "whatsapp"}),
    ("amazon", {"com", "co.uk", "de", "fr", "es", "it", "co.jp", "com.br", "com.mx", "in", "ca", "com.au"}, {"aws", "cloudfront"}),
    ("apple", {"com", "co.uk"}, {"icloud", "me", "mzstatic"}),
    ("microsoft", {"com", "co.uk", "de", "fr", "es"}, {"azure", "office", "live", "hotmail", "outlook", "skype", "bing", "msn"}),
    ("netflix", {"com", "co.uk", "de", "fr", "es", "co.jp"}, set()),
    ("paypal", {"com", "co.uk", "de", "fr", "es", "it", "co.jp", "com.br", "com.mx"}, set()),
    ("bankofamerica", {"com"}, set()),
    ("chase", {"com"}, set()),
    ("wellsfargo", {"com"}, set()),
    ("citibank", {"com"}, set()),
    ("hsbc", {"com", "co.uk"}, set()),
    ("barclays", {"co.uk"}, set()),
    ("santander", {"com", "co.uk", "es"}, set()),
    ("bbva", {"com", "es"}, set()),
]

# levenshtein_distance y _levenshtein_similarity se importan desde services.utils
# (lru_cache compartida, 10 000 slots, sin duplicación de memoria)

def _validate_url(url: str) -> str:
    """Valida y normaliza una URL."""
    if not url or not isinstance(url, str):
        raise ValueError("URL inválida")
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        raise ValueError("URL demasiado larga")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Esquema no soportado: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError("URL sin hostname")

    return url

def _calculate_normalized_entropy(text: str) -> float:
    """Calcula la entropía de Shannon normalizada (0.0 - 1.0)."""
    if not text:
        return 0.0
    length = len(text)
    if length <= 1:
        return 0.0

    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    max_entropy = math.log2(length)
    return entropy / max_entropy if max_entropy > 0 else 0.0

def _detect_free_hosting(hostname: str) -> tuple[bool, list[str], int]:
    """Detecta si el hostname usa un hosting gratuito abusado."""
    for domain, score in ABUSED_FREE_HOSTING:
        if hostname == domain or hostname.endswith("." + domain):
            return True, [f"ABUSED_FREE_HOSTING ({domain})"], score
    return False, [], 0

def _detect_brand_impersonation(hostname: str, path: str) -> tuple[list[str], int]:
    """Detecta suplantación de marca en hostname o path."""
    flags: list[str] = []
    score = 0
    hostname_lower = hostname.lower()
    path_lower = path.lower()

    # tldextract una única vez fuera del bucle (evita 14 llamadas por URL)
    extracted = tldextract.extract(hostname_lower)

    for brand, official_tlds, official_subdomains in TARGET_BRANDS:
        brand_lower = brand.lower()
        in_hostname = brand_lower in hostname_lower
        in_path = brand_lower in path_lower

        if not in_hostname and not in_path:
            continue

        is_official = False

        if extracted.domain == brand_lower and extracted.suffix in official_tlds:
            is_official = True
        if extracted.subdomain in official_subdomains:
            is_official = True
        if extracted.domain in official_subdomains:
            is_official = True

        if is_official:
            continue

        if in_hostname:
            flags.append(f"BRAND_IMPERSONATION_IN_HOSTNAME ({brand})")
            score += 45
        elif in_path:
            flags.append(f"BRAND_IMPERSONATION_IN_PATH ({brand})")
            score += 35
        break

    return flags, score

def _detect_entropy_and_dga(subdomain: str) -> tuple[list[str], int]:
    """Detecta subdominios con alta entropía (posible DGA)."""
    if not subdomain or len(subdomain) < 5:
        return [], 0

    norm_entropy = _calculate_normalized_entropy(subdomain)
    has_consecutive_numbers = bool(re.search(r"\d{4,}", subdomain))

    if norm_entropy > ENTROPY_THRESHOLD or has_consecutive_numbers:
        confidence = f"entropy={norm_entropy:.2f}" if norm_entropy > ENTROPY_THRESHOLD else "consecutive_numbers"
        return [f"HIGH_ENTROPY_SUBDOMAIN ({confidence})"], 15

    return [], 0

def _detect_suspicious_keywords(subdomain: str, path: str) -> tuple[list[str], int]:
    """Detecta keywords sospechosas y typos de keywords."""
    combined = f"{subdomain} {path}".lower()
    words = re.split(r"[^a-z0-9]", combined)

    found: list[str] = []
    total_score = 0

    for word in words:
        if not word or len(word) < MIN_WORD_LENGTH:
            continue

        for kw, score, label in SUSPICIOUS_KEYWORDS:
            if word == kw:
                found.append(label)
                total_score += score
                break
        else:
            for kw, score, label in SUSPICIOUS_KEYWORDS:
                sim = levenshtein_similarity(word, kw)
                if sim >= LEVENSHTEIN_THRESHOLD and word != kw:
                    found.append(f"{label} (typo: {word})")
                    total_score += score
                    break

    if not found:
        return [], 0

    unique_found = list(dict.fromkeys(found))
    flags = [f"SUSPICIOUS_KEYWORD ({kw})" for kw in unique_found]
    return flags, min(total_score, 50)

class URLStructureAnalyzer:
    """Analizador avanzado de estructura de URLs."""

    def analyze(self, url: str) -> dict[str, Any]:
        """Analiza una URL y retorna riesgo y flags."""
        try:
            url = _validate_url(url)
        except ValueError as exc:
            logger.warning(f"URL rechazada: {exc}")
            return {"risk_score": 0, "level": "LOW", "flags": [f"ERROR: {exc}"]}

        parsed = urlparse(url)
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        path = parsed.path.lower() if parsed.path else ""

        extracted = tldextract.extract(hostname)
        subdomain = extracted.subdomain

        flags: list[str] = []
        risk_score = 0

        is_free_hosting, fh_flags, fh_score = _detect_free_hosting(hostname)
        flags.extend(fh_flags)
        risk_score += fh_score

        bi_flags, bi_score = _detect_brand_impersonation(hostname, path)
        flags.extend(bi_flags)
        risk_score += bi_score

        entropy_target = subdomain if not is_free_hosting else extracted.domain
        ent_flags, ent_score = _detect_entropy_and_dga(entropy_target)
        flags.extend(ent_flags)
        risk_score += ent_score

        kw_flags, kw_score = _detect_suspicious_keywords(subdomain, path)
        flags.extend(kw_flags)
        risk_score += kw_score

        risk_score = max(0, min(risk_score, 100))
        level = calculate_risk_level(risk_score)

        return {"risk_score": risk_score, "level": level, "flags": flags}
