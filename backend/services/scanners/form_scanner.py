import asyncio
import logging
import os
import re
from typing import Optional, Set
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from models.osint_models import FormData, UrlAnatomyData

logger = logging.getLogger(__name__)

MAX_HTML_SIZE_FOR_FORMS = 500_000

DEFAULT_WEBHOOK_PATTERNS = [
    r"discord\.com/api/webhooks/",
    r"discordapp\.com/api/webhooks/",
    r"api\.telegram\.org/bot",
    r"hooks\.slack\.com/services/",
    r"formspree\.io/f/",
    r"hook\.integromat\.com",
    r"maker\.ifttt\.com/trigger",
    r"webhook\.site",
    r"requestbin\.com",
    r"pipedream\.net",
]

def _get_webhook_patterns() -> list:
    """Carga patrones de webhook desde env o usa defaults."""
    env_patterns = os.getenv("WEBHOOK_PATTERNS", "").strip()
    if env_patterns:
        try:
            import json
            patterns = json.loads(env_patterns)
            if isinstance(patterns, list) and all(isinstance(p, str) for p in patterns):
                return patterns
        except json.JSONDecodeError:
            logger.warning("WEBHOOK_PATTERNS no es JSON válido, usando defaults.")
    return DEFAULT_WEBHOOK_PATTERNS

WEBHOOK_PATTERNS = _get_webhook_patterns()
DANGEROUS_SCHEMES = {"javascript:", "data:", "vbscript:", "file:", "about:"}

def _normalize_netloc(netloc: str) -> str:
    """Normaliza netloc removiendo puerto default."""
    if netloc.endswith(":80"):
        return netloc[:-3]
    if netloc.endswith(":443"):
        return netloc[:-4]
    return netloc.lower()

def _is_external_action(action: str, page_hostname: str) -> bool:
    """Determina si el action de un formulario apunta a un dominio externo."""
    if not action or not action.strip():
        return False

    action = action.strip()

    if action.startswith("//"):
        parsed = urlparse("https:" + action)
        return _normalize_netloc(parsed.netloc) != _normalize_netloc(page_hostname)

    if action.startswith("http://") or action.startswith("https://"):
        parsed = urlparse(action)
        return _normalize_netloc(parsed.netloc) != _normalize_netloc(page_hostname)

    return False

def _has_dangerous_scheme(action: str) -> Optional[str]:
    """Detecta si el action usa un esquema peligroso."""
    if not action:
        return None
    action_lower = action.strip().lower()
    for scheme in DANGEROUS_SCHEMES:
        if action_lower.startswith(scheme):
            return scheme
    return None

def _validate_hostname(hostname: str) -> str:
    """Valida que el hostname sea un string no vacío."""
    if not isinstance(hostname, str) or not hostname.strip():
        raise ValueError("hostname debe ser un string no vacío")
    hostname = hostname.strip().lower()
    if "/" in hostname or "\\" in hostname or "?" in hostname or "#" in hostname:
        raise ValueError(f"hostname contiene caracteres inválidos: {hostname}")
    return hostname

class FormScanner:
    @staticmethod
    async def analyze_forms(
        html_content: str,
        hostname: str,
        url_anatomy: Optional[UrlAnatomyData] = None
    ) -> FormData:
        """Analiza formularios HTML en busca de indicadores de phishing."""
        result = FormData()

        try:
            hostname = _validate_hostname(hostname)
        except ValueError as exc:
            logger.error(f"Hostname inválido: {exc}")
            result.has_dangerous_form = True
            result.reason = "Error interno de validación."
            return result

        if not html_content or not isinstance(html_content, str):
            return result

        if len(html_content) > MAX_HTML_SIZE_FOR_FORMS:
            html_content = html_content[:MAX_HTML_SIZE_FOR_FORMS]

        try:
            result = await asyncio.to_thread(
                FormScanner._analyze_forms_sync,
                html_content,
                hostname,
                url_anatomy
            )
        except Exception as exc:
            logger.error(f"Error en análisis de formularios: {exc}", exc_info=True)
            result.has_dangerous_form = False
            result.reason = "Error interno durante el análisis."

        return result

    @staticmethod
    def _analyze_forms_sync(
        html_content: str,
        hostname: str,
        url_anatomy: Optional[UrlAnatomyData] = None
    ) -> FormData:
        """Versión síncrona del análisis."""
        result = FormData()
        soup = BeautifulSoup(html_content, "html.parser")

        is_high_risk_domain = False
        if url_anatomy is not None:
            is_high_risk_domain = bool(
                url_anatomy.suspicious_tld
                or url_anatomy.is_dga_suspect
                or url_anatomy.excessive_hyphens
                or url_anatomy.excessive_subdomains
            )

        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action", "") or ""
            method = (form.get("method", "get") or "get").lower()

            dangerous = _has_dangerous_scheme(action)
            if dangerous:
                result.has_dangerous_form = True
                result.reason = f"Esquema peligroso detectado: {dangerous}."
                return result

            action_lower = action.lower()
            for pattern in WEBHOOK_PATTERNS:
                if re.search(pattern, action_lower):
                    result.has_dangerous_form = True
                    result.reason = "Exfiltración de datos detectada (webhook)."
                    return result

            has_password = bool(
                form.find("input", type="password")
                or form.find("input", {"name": re.compile(r"password|passwd|pass|pwd|cc_number|cvv|ssn", re.I)})
                or form.find("input", {"id": re.compile(r"password|passwd|pass|pwd", re.I)})
            )

            has_sensitive = bool(
                form.find("input", type="email")
                or form.find("input", {"name": re.compile(r"email|user|login|username|account|phone|card", re.I)})
            )

            if has_password or has_sensitive:
                if action.startswith("http://"):
                    result.has_dangerous_form = True
                    result.reason = "Envío de datos sensibles por HTTP sin cifrar."
                    return result

                if _is_external_action(action, hostname):
                    result.has_dangerous_form = True
                    result.reason = "Envío de datos sensibles a un servidor externo."
                    return result

                if method == "get" and has_password:
                    result.has_dangerous_form = True
                    result.reason = "Envío de contraseñas mediante GET."
                    return result

            hidden_inputs = form.find_all("input", type="hidden")
            for inp in hidden_inputs:
                name = (inp.get("name") or "").lower()
                value = (inp.get("value") or "").lower()
                if any(k in name for k in ("webhook", "bot_token", "chat_id", "exfil", "redirect")):
                    result.has_dangerous_form = True
                    result.reason = f"Input hidden sospechoso: {inp.get('name')}."
                    return result
                for pattern in WEBHOOK_PATTERNS:
                    if re.search(pattern, value):
                        result.has_dangerous_form = True
                        result.reason = "Input hidden contiene URL de webhook."
                        return result

            enctype = (form.get("enctype") or "").lower()
            if enctype == "text/plain" and (has_password or has_sensitive):
                result.has_dangerous_form = True
                result.reason = "Formulario con enctype=text/plain y datos sensibles."
                return result

            if not action.strip() and is_high_risk_domain and has_password:
                result.has_dangerous_form = True
                result.reason = "Login en dominio de alto riesgo sin action definido."
                return result

        html_lower = html_content.lower()
        for pattern in WEBHOOK_PATTERNS:
            if re.search(pattern, html_lower):
                result.has_dangerous_form = True
                result.reason = "Canal de exfiltración detectado en código fuente."
                return result

        iframes = soup.find_all("iframe")
        for iframe in iframes:
            src = (iframe.get("src") or "").lower()
            if src and _is_external_action(src, hostname):
                if has_password or has_sensitive:
                    result.has_dangerous_form = True
                    result.reason = "Página con formularios y contenido externo en iframe."
                    return result

        return result