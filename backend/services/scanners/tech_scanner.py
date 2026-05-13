import asyncio
import logging
import os
import re
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from models.osint_models import PrivacyData, TechData
from services.utils import is_safe_url

logger = logging.getLogger(__name__)

MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024
MAX_HTML_FOR_MODEL = 200_000
HTTP_TIMEOUT = 10.0
USER_AGENT = os.getenv(
    "TECH_SCANNER_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
)

TRACKER_PATTERNS: list[tuple[str, list[str]]] = [
    ("doubleclick.net", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("google-analytics.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("googletagmanager.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("facebook.net", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("facebook.com/tr/", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("adnxs.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("adsnative.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("hotjar.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("scorecardresearch.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("bing.com/pixel", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("taboola.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("outbrain.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("rubiconproject.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("pubmatic.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("criteo.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("tiktok.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("ads-twitter.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("snap.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("pinterest.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("amazon-adsystem.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("redditstatic.com/ads", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("yandex.ru/metrika", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("clarity.ms", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("mouseflow.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("segment.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
    ("mixpanel.com", ["Cookies de Terceros", "Rastreo Publicitario"]),
]

STORAGE_PATTERNS: list[tuple[str, str]] = [
    ("localstorage", "Almacenamiento Local (LocalStorage)"),
    ("window.localstorage", "Almacenamiento Local (LocalStorage)"),
    ("sessionstorage", "Almacenamiento de Sesión (SessionStorage)"),
    ("window.sessionstorage", "Almacenamiento de Sesión (SessionStorage)"),
    ("indexeddb", "Base de Datos Local (IndexedDB)"),
    ("window.indexeddb", "Base de Datos Local (IndexedDB)"),
]

DATA_LINKED_REGEX: list[tuple[re.Pattern, str]] = [
    (re.compile(r'''type=["']email["']''', re.I), "Correo Electrónico"),
    (re.compile(r'''name=["']email["']''', re.I), "Correo Electrónico"),
    (re.compile(r'''type=["']tel["']''', re.I), "Número de Teléfono"),
    (re.compile(r'''name=["'](phone|tel)["']''', re.I), "Número de Teléfono"),
]

DATA_LINKED_SIMPLE: list[tuple[str, str]] = [
    ("accounts.google.com/gsi/client", "Perfil de Google"),
    ("gapi.auth2", "Perfil de Google"),
    ("connect.facebook.net", "Perfil de Facebook"),
    ("appleid.apple.com/appleauth", "Perfil de Apple"),
    ("js.stripe.com", "Datos Financieros (Stripe)"),
    ("elements", "Datos Financieros (Stripe)"),
    ("paypalobjects.com", "Datos Financieros (PayPal)"),
    ("paypal.com/sdk", "Datos Financieros (PayPal)"),
]

DEVICE_ACCESS_PATTERNS: list[tuple[str, str]] = [
    ("getusermedia", "Cámara y Micrófono"),
    ("enumeratedevices", "Cámara y Micrófono"),
    ("requestpermission", "Notificaciones Push"),
    ("navigator.clipboard.readtext", "Portapapeles (Copiar/Pegar)"),
    ("navigator.clipboard.read", "Portapapeles (Copiar/Pegar)"),
    ("navigator.getbattery", "Estado de la Batería"),
    ("navigator.bluetooth", "Bluetooth"),
    ("navigator.usb", "Puertos USB"),
]

FINGERPRINTING_PATTERNS: list[tuple[str, str]] = [
    ("todataurl", "Huella Digital (Canvas Fingerprinting)"),
    ("audiocontext", "Huella Digital (Audio Fingerprinting)"),
    ("oscillator", "Huella Digital (Audio Fingerprinting)"),
    ("webgl", "Huella Digital Gráfica (WebGL)"),
    ("rtcpeerconnection", "Fugas de Red (WebRTC)"),
    ("mozrtcpeerconnection", "Fugas de Red (WebRTC)"),
]

async def _is_safe_url_async(url: str) -> bool:
    """Wrapper async que ejecuta la validación en thread."""
    return await asyncio.to_thread(is_safe_url, url)

def _is_safe_redirect(url: str) -> bool:
    """Valida que una URL de redirección sea segura."""
    return is_safe_url(url)

def _analyze_privacy(html_lower: str, external_scripts: list[str]) -> PrivacyData:
    """Analiza el HTML en busca de indicadores de privacidad."""
    privacy = PrivacyData()
    tracking_used: set[str] = set()
    data_linked: set[str] = set()
    device_access: set[str] = set()
    trackers_count = 0

    for script_url in external_scripts:
        script_lower = script_url.lower()
        for pattern, labels in TRACKER_PATTERNS:
            if pattern in script_lower:
                trackers_count += 1
                tracking_used.update(labels)
                break

    if trackers_count > 0:
        tracking_used.add("Análisis de Comportamiento")

    for pattern, label in STORAGE_PATTERNS:
        if pattern in html_lower:
            tracking_used.add(label)

    for compiled_re, label in DATA_LINKED_REGEX:
        if compiled_re.search(html_lower):
            data_linked.add(label)

    for pattern, label in DATA_LINKED_SIMPLE:
        if pattern in html_lower:
            if "facebook" in label.lower() and "xfbml" not in html_lower:
                continue
            data_linked.add(label)

    for pattern, label in DEVICE_ACCESS_PATTERNS:
        if pattern in html_lower:
            if label == "Notificaciones Push" and "notification" not in html_lower:
                continue
            device_access.add(label)

    for pattern, label in FINGERPRINTING_PATTERNS:
        if pattern in html_lower:
            if "Canvas" in label and "canvas" not in html_lower:
                continue
            if "WebGL" in label and not any(kw in html_lower for kw in ("getextension", "debug_renderer_info")):
                continue
            tracking_used.add(label)

    if "geolocation" in html_lower or "navigator.geolocation" in html_lower:
        data_linked.add("Ubicación Geográfica")

    privacy.tracking_used = sorted(list(tracking_used))
    privacy.trackers_count = trackers_count
    privacy.data_linked = sorted(list(data_linked))
    privacy.device_access = sorted(list(device_access))

    return privacy

def _extract_external_scripts(html_content: str, hostname: str) -> list[str]:
    """Extrae scripts externos del HTML."""
    soup = BeautifulSoup(html_content, "html.parser")
    scripts = soup.find_all("script", src=True)

    external_scripts: set[str] = set()
    hostname_lower = hostname.lower()

    for script in scripts:
        src = script["src"]
        parsed_src = urlparse(src)

        if parsed_src.netloc and parsed_src.netloc.lower() != hostname_lower:
            external_scripts.add(src)
        elif src.startswith("//"):
            parsed_relative = urlparse("http:" + src)
            if parsed_relative.netloc and parsed_relative.netloc.lower() != hostname_lower:
                external_scripts.add("https:" + src)

    return sorted(list(external_scripts))

class TechScanner:
    """Escáner técnico de páginas web."""

    @staticmethod
    def _cpu_bound_analysis(
        html_content: str,
        response_headers: dict[str, str],
        cookies_dict: dict[str, str],
        hostname: str
    ) -> tuple[list[str], list[str], PrivacyData]:
        """Análisis CPU-intensivo ejecutado en thread."""
        html_lower = html_content.lower()
        external_scripts = _extract_external_scripts(html_content, hostname)
        technologies: list[str] = []
        privacy = _analyze_privacy(html_lower, external_scripts)

        return external_scripts, technologies, privacy

    @staticmethod
    async def get_tech_and_scripts(url: str, hostname: str) -> TechData:
        """Obtiene datos técnicos de una URL."""
        result = TechData()

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        if not await _is_safe_url_async(url):
            logger.warning(f"Intento de SSRF bloqueado: {url}")
            return result

        req_headers = {"User-Agent": USER_AGENT}
        try:
            async with httpx.AsyncClient(verify=True, follow_redirects=False, timeout=HTTP_TIMEOUT, headers=req_headers) as client:
                current_url = url
                redirect_chain: list[str] = [current_url]
                max_redirects = 10
                redirect_count = 0

                while redirect_count < max_redirects:
                    async with client.stream("GET", current_url, timeout=HTTP_TIMEOUT) as response:
                        content_length = response.headers.get("content-length")
                        if content_length and int(content_length) > MAX_DOWNLOAD_BYTES:
                            return result

                        chunks = []
                        bytes_read = 0
                        async for chunk in response.aiter_bytes():
                            bytes_read += len(chunk)
                            if bytes_read > MAX_DOWNLOAD_BYTES:
                                break
                            chunks.append(chunk)

                        html_bytes = b"".join(chunks)
                        html_content = html_bytes.decode("utf-8", errors="ignore")
                        response_headers = dict(response.headers)
                        cookies_dict = {c.name: c.value for c in response.cookies.jar}

                        if response.status_code in (301, 302, 303, 307, 308):
                            location = response.headers.get("location")
                            if not location:
                                break
                            from urllib.parse import urljoin
                            next_url = urljoin(current_url, location)
                            if not await _is_safe_url_async(next_url):
                                break
                            redirect_chain.append(next_url)
                            current_url = next_url
                            redirect_count += 1
                            continue
                        break

                result.redirect_chain = redirect_chain

        except Exception as exc:
            logger.warning(f"Error al conectar con {url}: {exc}")
            return result

        if len(html_content) > MAX_HTML_FOR_MODEL:
            result.html_content = html_content[:MAX_HTML_FOR_MODEL]
        else:
            result.html_content = html_content

        try:
            external_scripts, technologies, privacy = await asyncio.to_thread(
                TechScanner._cpu_bound_analysis,
                html_content,
                response_headers,
                cookies_dict,
                hostname,
            )
            result.external_scripts = external_scripts
            result.technologies = technologies
            result.privacy_analysis = privacy
        except Exception as exc:
            logger.error(f"Error en análisis CPU-bound: {exc}")

        return result
