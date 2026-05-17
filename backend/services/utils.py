import asyncio
import functools
import hashlib
import ipaddress
import json
import logging
import math
import os
import socket
from collections import Counter
from typing import Any
from urllib.parse import urlparse

import filetype
import httpx

logger = logging.getLogger(__name__)

def _load_list_from_env(env_var: str, default: list[str]) -> list[str]:
    """Carga una lista desde variable de entorno (JSON) o usa defaults."""
    env_value = os.getenv(env_var, "").strip()
    if env_value:
        try:
            parsed = json.loads(env_value)
            if isinstance(parsed, list) and all(isinstance(x, str) for x in parsed):
                return [x.lower().strip() for x in parsed if x.strip()]
        except json.JSONDecodeError:
            logger.warning(f"{env_var} no es JSON válido.")
    return default

TARGET_BRANDS = _load_list_from_env("TARGET_BRANDS", [
    "google", "microsoft", "amazon", "netflix", "paypal", "apple", "facebook",
    "instagram", "linkedin", "binance", "yahoo", "santander", "bbva", "caixabank",
    "outlook", "gmail", "twitter", "x", "chase", "wellsfargo", "bankofamerica",
    "citibank", "hsbc", "mastercard", "visa", "amex", "discover", "spotify",
    "tiktok", "snapchat", "telegram", "whatsapp"
])

ABUSED_FREE_HOSTING = _load_list_from_env("ABUSED_FREE_HOSTING", [
    "github.io", "gitlab.io", "vercel.app", "netlify.app", "firebaseapp.com",
    "web.app", "pages.dev", "workers.dev", "herokuapp.com", "azurewebsites.net",
    "glitch.me", "repl.co", "000webhostapp.com", "blogspot.com", "weebly.com",
    "wixsite.com", "wordpress.com", "surge.sh", "neocities.org", "duckdns.org",
    "ngrok.io", "serveo.net", "localtunnel.me", "trycloudflare.com", "pagekite.me"
])

DANGEROUS_EXTENSIONS: set[str] = {
    ".exe", ".dll", ".bat", ".cmd", ".sh", ".bin", ".scr", ".msi", ".com", ".pif",
    ".gadget", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".ps1",
    ".ps1xml", ".ps2", ".ps2xml", ".psc1", ".psc2", ".py", ".pyc", ".pyo", ".pyw",
    ".pyz", ".jar", ".class", ".war", ".ear", ".apk", ".dex", ".so", ".elf",
    ".docm", ".dotm", ".xlsm", ".xlam", ".pptm", ".potm", ".ppam", ".ppsm", ".sldm",
    ".iso", ".img", ".dmg", ".vmdk", ".zip", ".rar", ".7z", ".tar", ".gz"
}

# ---------------------------------------------------------------------------
# Levenshtein compartido (evita duplicación en url_structure_analyzer y
# typosquatting_scanner que antes tenían sus propias copias).
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=10_000)
def levenshtein_distance(s1: str, s2: str) -> int:
    """Calcula la distancia de Levenshtein entre dos strings (cacheada)."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions  = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def levenshtein_similarity(s1: str, s2: str) -> float:
    """Retorna similitud 0.0-1.0 basada en distancia de Levenshtein."""
    if not s1 and not s2:
        return 1.0
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    return 1.0 - (levenshtein_distance(s1, s2) / max_len)


# ---------------------------------------------------------------------------
# Nivel de riesgo compartido (evita duplicación en heuristic_scanner y
# url_structure_analyzer).
# ---------------------------------------------------------------------------

def calculate_risk_level(score: int) -> str:
    """Convierte score numérico a nivel de riesgo textual."""
    if score >= 70:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# SSRF protection — versiones síncrona y asíncrona.
# ---------------------------------------------------------------------------

def _is_reserved_ip(ip_str: str) -> bool:
    """Retorna True si la IP es privada/reservada/loopback/etc."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any([
            ip_obj.is_private, ip_obj.is_loopback, ip_obj.is_reserved,
            ip_obj.is_link_local, ip_obj.is_multicast, ip_obj.is_unspecified,
        ])
    except ValueError:
        return False


def is_safe_url(url: str) -> bool:
    """Valida que una URL sea pública para prevenir SSRF (versión síncrona).

    ⚠️  Hace resolución DNS bloqueante. Usar is_safe_url_async() dentro de
    corrutinas para no bloquear el event loop.
    """
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        hostname = hostname.lower().strip()
        if len(hostname) > 253:
            return False

        # ── Comprobar IP literal ──────────────────────────────────────────
        try:
            if _is_reserved_ip(hostname):
                return False
            ipaddress.ip_address(hostname)  # era IP válida y pública
            return True
        except ValueError:
            pass  # no era IP → seguir con resolución DNS

        # ── Resolución DNS síncrona ───────────────────────────────────────
        addr_info = socket.getaddrinfo(hostname, None)
        for _, _, _, _, sockaddr in addr_info:
            if _is_reserved_ip(sockaddr[0]):
                # 🔒 No loggear la IP interna resuelta (fuga de info)
                _h = hashlib.sha256(hostname.encode()).hexdigest()[:12]
                logger.info(f"SSRF bloqueado: hostname_hash={_h}")
                return False
        return True
    except Exception:
        return False


async def is_safe_url_async(url: str) -> bool:
    """Versión async de is_safe_url — no bloquea el event loop.

    Realiza la resolución DNS usando el event loop de asyncio en lugar de
    socket.getaddrinfo() síncrono.
    """
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        hostname = hostname.lower().strip()
        if len(hostname) > 253:
            return False

        # ── Comprobar IP literal (no necesita DNS) ────────────────────────
        try:
            if _is_reserved_ip(hostname):
                return False
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            pass

        # ── Resolución DNS no bloqueante ──────────────────────────────────
        loop = asyncio.get_event_loop()
        addr_info = await loop.getaddrinfo(hostname, None)
        for _, _, _, _, sockaddr in addr_info:
            if _is_reserved_ip(sockaddr[0]):
                _h = hashlib.sha256(hostname.encode()).hexdigest()[:12]
                logger.info(f"SSRF bloqueado (async): hostname_hash={_h}")
                return False
        return True
    except Exception:
        return False

def calculate_shannon_entropy(data: bytes) -> float:
    """Calcula la entropía de Shannon."""
    if not data:
        return 0.0
    length = len(data)
    occurrences = Counter(data)
    entropy = 0.0
    for count in occurrences.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def calculate_normalized_entropy(data: bytes) -> float:
    """Calcula la entropía de Shannon normalizada (0.0 - 1.0)."""
    return calculate_shannon_entropy(data) / 8.0

def format_size(size_bytes: int) -> str:
    """Formatea tamaño en bytes a unidades legibles."""
    if size_bytes < 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_bytes)
    idx = 0
    while size >= 1024.0 and idx < len(units) - 1:
        size /= 1024.0
        idx += 1
    return f"{size:.1f} {units[idx]}"

def _get_file_extension(filename: str) -> str:
    if not filename or not isinstance(filename, str):
        return ""
    return os.path.splitext(os.path.basename(filename).lower())[1]

def _detect_dangerous_extension(filename: str) -> tuple[bool, str | None]:
    """Detecta extensiones peligrosas, incluyendo dobles extensiones."""
    ext = _get_file_extension(filename)
    if ext in DANGEROUS_EXTENSIONS:
        return True, ext
    parts = os.path.basename(filename).lower().split(".")
    if len(parts) >= 3:
        double_ext = "." + parts[-2] + "." + parts[-1]
        if double_ext in DANGEROUS_EXTENSIONS:
            return True, double_ext
    return False, None

def calculate_file_forensics(file_bytes: bytes, filename: str) -> dict[str, Any]:
    """Analiza un archivo y retorna métricas forenses."""
    if not file_bytes:
        raise ValueError("Datos de archivo vacíos")

    file_size = len(file_bytes)
    normalized_entropy = calculate_normalized_entropy(file_bytes)
    mime_type = "application/octet-stream"

    try:
        kind = filetype.guess(file_bytes)
        if kind:
            mime_type = kind.mime
    except Exception:  # noqa: S110
        pass

    is_dangerous, dangerous_ext = _detect_dangerous_extension(filename)
    entropy_alerts = []
    if normalized_entropy > 0.95:
        entropy_alerts.append("ALTA_ENTROPIA: Posible comprimido/cifrado")
    elif normalized_entropy > 0.90:
        entropy_alerts.append("ENTROPIA_ELEVADA: Posible ofuscación")

    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),  # noqa: S324 — usado para fingerprinting, no seguridad
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
        "file_size": format_size(file_size),
        "file_type": mime_type,
        "entropy_normalized": round(normalized_entropy, 4),
        "extension_alert": f"PELIGROSA: {dangerous_ext}" if is_dangerous else None,
        "entropy_alerts": entropy_alerts,
    }


async def resolve_redirect_chain(url: str, timeout: float = 8.0, max_redirects: int = 10) -> list[str]:
    """Sigue las redirecciones de una URL de forma segura y devuelve la cadena completa de URLs resueltas."""
    if not url:
        return []

    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not await is_safe_url_async(url):
        return [url]

    redirect_chain = [url]
    current_url = url
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    try:
        async with httpx.AsyncClient(verify=True, follow_redirects=False, timeout=timeout, headers=headers) as client:
            for _ in range(max_redirects):
                try:
                    response = await client.head(current_url, timeout=timeout)
                    if response.status_code in (405, 501, 400):
                        async with client.stream("GET", current_url, timeout=timeout) as resp:
                            status_code = resp.status_code
                            resp_headers = resp.headers
                    else:
                        status_code = response.status_code
                        resp_headers = response.headers
                except Exception:
                    async with client.stream("GET", current_url, timeout=timeout) as resp:
                        status_code = resp.status_code
                        resp_headers = resp.headers

                if status_code in (301, 302, 303, 307, 308):
                    location = resp_headers.get("location")
                    if not location:
                        break
                    from urllib.parse import urljoin
                    next_url = urljoin(current_url, location)
                    if not await is_safe_url_async(next_url):
                        break
                    if next_url in redirect_chain:
                        break
                    redirect_chain.append(next_url)
                    current_url = next_url
                else:
                    break
    except Exception as exc:
        logger.warning(f"Error al resolver redirecciones para {url}: {exc}")

    if not redirect_chain:
        redirect_chain = [url]

    return redirect_chain
