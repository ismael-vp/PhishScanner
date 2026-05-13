import asyncio
import functools
import logging
import re
from typing import Optional, List, Set, Tuple

import tldextract

from models.osint_models import TyposquattingData
from services.utils import TARGET_BRANDS

logger = logging.getLogger(__name__)

MAX_HOSTNAME_LENGTH = 253
MIN_DOMAIN_LENGTH = 3

HOMOGLYPHS: dict[str, Set[str]] = {
    "a": {"а", "ạ", "ą", "ä", "à", "á"},
    "b": {"Ь", "в"},
    "c": {"с", "ϲ", "ċ"},
    "d": {"ԁ", "đ"},
    "e": {"е", "ẹ", "ė", "ĕ"},
    "g": {"ɡ", "ģ"},
    "h": {"һ", "հ"},
    "i": {"і", "ị", "į", "ï", "ì", "í"},
    "j": {"ј", "ʝ"},
    "k": {"κ", "к"},
    "l": {"ӏ", "ḷ", "ł"},
    "m": {"м", "ṃ"},
    "n": {"ո", "ṅ", "ņ"},
    "o": {"о", "ο", "ọ", "ӧ", "ò", "ó"},
    "p": {"р", "ρ", "ṗ"},
    "q": {"ԛ"},
    "r": {"г", "ṛ"},
    "s": {"ѕ", "ṡ", "ş"},
    "t": {"т", "ṭ"},
    "u": {"υ", "ս", "ü", "ù", "ú"},
    "v": {"ν", "ṽ"},
    "w": {"ԝ", "ẉ"},
    "x": {"х", "ҳ"},
    "y": {"у", "ý", "ÿ"},
    "z": {"ᴢ", "ż"},
}

_HOMOGLYPH_REVERSE: dict[str, str] = {}
for ascii_char, variants in HOMOGLYPHS.items():
    for variant in variants:
        _HOMOGLYPH_REVERSE[variant] = ascii_char

SUSPICIOUS_PREFIXES = {
    "secure-", "login-", "signin-", "account-", "verify-", "confirm-",
    "update-", "auth-", "security-", "billing-", "payment-",
}
SUSPICIOUS_SUFFIXES = {
    "-secure", "-login", "-signin", "-verify", "-confirm",
    "-update", "-auth", "-security", "-billing", "-payment",
    "-support", "-help", "-service",
}

@functools.lru_cache(maxsize=10000)
def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calcula la distancia de Levenshtein entre dos strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def _levenshtein_similarity(s1: str, s2: str) -> float:
    """Retorna similarity 0.0-1.0 basado en distancia de Levenshtein."""
    if not s1 and not s2:
        return 1.0
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    distance = _levenshtein_distance(s1, s2)
    return 1.0 - (distance / max_len)

def _detect_homoglyphs(domain: str) -> Tuple[bool, Optional[str], float]:
    """Detecta si el dominio usa caracteres homoglifos."""
    normalized = []
    has_homoglyph = False
    for char in domain:
        if char in _HOMOGLYPH_REVERSE:
            normalized.append(_HOMOGLYPH_REVERSE[char])
            has_homoglyph = True
        else:
            normalized.append(char)

    if not has_homoglyph:
        return False, None, 0.0

    normalized_domain = "".join(normalized)
    for brand in TARGET_BRANDS:
        if normalized_domain == brand:
            return True, brand, 0.95
        sim = _levenshtein_similarity(normalized_domain, brand)
        if sim >= 0.90:
            return True, brand, 0.90

    return False, None, 0.0

def _detect_levenshtein_typos(domain: str) -> Tuple[bool, Optional[str], float]:
    """Detecta typos basados en distancia de Levenshtein."""
    best_match = None
    best_confidence = 0.0

    for brand in TARGET_BRANDS:
        if domain == brand:
            continue

        sim = _levenshtein_similarity(domain, brand)
        threshold = 0.85 if len(brand) >= 6 else 0.80

        if sim >= threshold and sim > best_confidence:
            best_confidence = sim
            best_match = brand

    if best_match:
        return True, best_match, best_confidence
    return False, None, 0.0

def _detect_bitsquatting(domain: str) -> Tuple[bool, Optional[str], float]:
    """Detecta bitsquatting: un solo bit flip."""
    for brand in TARGET_BRANDS:
        if len(domain) != len(brand):
            continue
        if domain == brand:
            continue

        diff_count = 0
        for c1, c2 in zip(domain, brand):
            if c1 != c2:
                diff_count += 1
                xor = ord(c1) ^ ord(c2)
                if xor & (xor - 1) != 0:
                    diff_count = 999
                    break

        if diff_count == 1:
            return True, brand, 0.92

    return False, None, 0.0

def _detect_prefix_suffix(domain: str) -> Tuple[bool, Optional[str], float]:
    """Detecta si el dominio es una marca conocida con prefijo/sufijo sospechoso."""
    for brand in TARGET_BRANDS:
        if domain == brand:
            continue

        if domain.startswith(brand):
            suffix = domain[len(brand):]
            if any(suffix.startswith(s) for s in ("-", ".")):
                remainder = suffix[1:] if suffix.startswith(("-", ".")) else suffix
                if any(remainder.startswith(sp.replace("-", "")) for sp in SUSPICIOUS_SUFFIXES):
                    return True, brand, 0.75
                if len(remainder) <= 3 and len(remainder) > 0:
                    return True, brand, 0.65

        if domain.endswith(brand):
            prefix = domain[:-len(brand)]
            if any(prefix.endswith(p.replace("-", "")) for p in SUSPICIOUS_PREFIXES):
                return True, brand, 0.75
            if len(prefix) <= 3 and len(prefix) > 0:
                return True, brand, 0.65

    return False, None, 0.0

def _detect_tld_swap(domain: str, original_tld: str) -> Tuple[bool, Optional[str], float]:
    """Detecta cambio de TLD sospechoso."""
    common_tlds = {"com", "net", "org", "io", "app"}
    if original_tld in common_tlds:
        return False, None, 0.0

    for brand in TARGET_BRANDS:
        if domain == brand:
            return True, brand, 0.70

    return False, None, 0.0

def _validate_hostname(hostname: str) -> str:
    """Valida y normaliza el hostname."""
    if not hostname or not isinstance(hostname, str):
        raise ValueError("Hostname inválido")
    hostname = hostname.strip().lower()
    if not hostname:
        raise ValueError("Hostname vacío")
    if len(hostname) > MAX_HOSTNAME_LENGTH:
        raise ValueError(f"Hostname demasiado largo: {len(hostname)}")
    import ipaddress
    try:
        ipaddress.ip_address(hostname)
        raise ValueError("No se aceptan IPs")
    except ValueError:
        pass
    return hostname

class TyposquattingScanner:
    """Escáner de typosquatting con múltiples heurísticas."""

    _cache: dict[str, Optional[TyposquattingData]] = {}
    _cache_max_size = 1000

    @staticmethod
    def _extract_root_domain(hostname: str) -> Tuple[str, str]:
        """Extrae el nombre de dominio raíz y el TLD."""
        extracted = tldextract.extract(hostname)
        return extracted.domain, extracted.suffix

    @staticmethod
    async def check_typosquatting(hostname: str) -> Optional[TyposquattingData]:
        """Analiza un hostname en busca de typosquatting."""
        try:
            hostname = _validate_hostname(hostname)
        except ValueError as exc:
            logger.warning(f"Validación rechazada: {exc}")
            return None

        if hostname in TyposquattingScanner._cache:
            return TyposquattingScanner._cache[hostname]

        try:
            result = await asyncio.to_thread(
                TyposquattingScanner._check_typosquatting_sync,
                hostname
            )
        except Exception as exc:
            logger.error(f"Error en TyposquattingScanner: {exc}")
            result = None

        if len(TyposquattingScanner._cache) >= TyposquattingScanner._cache_max_size:
            keys_to_remove = list(TyposquattingScanner._cache.keys())[:TyposquattingScanner._cache_max_size // 2]
            for k in keys_to_remove:
                del TyposquattingScanner._cache[k]

        TyposquattingScanner._cache[hostname] = result
        return result

    @staticmethod
    def _check_typosquatting_sync(hostname: str) -> Optional[TyposquattingData]:
        """Versión síncrona del análisis."""
        main_domain, tld = TyposquattingScanner._extract_root_domain(hostname)

        if len(main_domain) < MIN_DOMAIN_LENGTH:
            return None

        detectors = [
            ("homoglyph", _detect_homoglyphs),
            ("bitsquatting", _detect_bitsquatting),
            ("levenshtein", _detect_levenshtein_typos),
            ("prefix_suffix", _detect_prefix_suffix),
            ("tld_swap", lambda d: _detect_tld_swap(d, tld)),
        ]

        for technique, detector in detectors:
            detected, brand, confidence = detector(main_domain)
            if detected and brand:
                logger.info(f"Typosquatting detectado: {hostname} -> {brand} ({technique})")
                return TyposquattingData(
                    is_typosquatting=True,
                    target_brand=brand,
                    confidence=confidence,
                    technique=technique,
                )

        return None