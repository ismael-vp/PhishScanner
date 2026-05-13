import asyncio
import ipaddress
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional, List, Union

import whois

from models.osint_models import WhoisData

logger = logging.getLogger(__name__)

WHOIS_TIMEOUT = float(os.getenv("WHOIS_SCANNER_TIMEOUT", "8.0"))
MAX_HOSTNAME_LENGTH = 253

DATE_PATTERNS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%d-%b-%Y",
    "%d-%B-%Y",
    "%d %b %Y",
    "%d %B %Y",
    "%b %d %Y",
    "%B %d %Y",
    "%Y.%m.%d",
    "%Y/%m/%d",
    "%m/%d/%Y",
    "%Y%m%d",
    "%a %b %d %H:%M:%S %Y",
    "%a %b %d %H:%M:%S %Z %Y",
]

REDACTED_INDICATORS = [
    "redacted", "privacy", "private", "gdpr", "whoisguard", "protected",
    "not disclosed", "not available", "withheld", "anon", "obfuscated",
    "data protected", "registrant name: redacted", "dns admin: redacted",
]

def _validate_hostname(hostname: str) -> str:
    """Valida que el hostname sea seguro para consulta WHOIS."""
    if not hostname or not isinstance(hostname, str):
        raise ValueError("Hostname inválido")

    hostname = hostname.strip().lower()
    if not hostname:
        raise ValueError("Hostname vacío")
    if len(hostname) > MAX_HOSTNAME_LENGTH:
        raise ValueError(f"Hostname demasiado largo: {len(hostname)}")

    try:
        ipaddress.ip_address(hostname)
        raise ValueError(f"WHOIS no acepta IPs: {hostname}")
    except ValueError:
        pass

    if not re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$", hostname):
        raise ValueError(f"Hostname con formato inválido: {hostname}")

    return hostname

def _parse_whois_date(date_value: Optional[Union[datetime, str, List]]) -> Optional[str]:
    """Parsea una fecha de WHOIS a formato ISO 8601."""
    if date_value is None:
        return None

    if isinstance(date_value, list):
        if not date_value:
            return None
        date_value = date_value[0]

    if isinstance(date_value, datetime):
        if date_value.tzinfo is None:
            date_value = date_value.replace(tzinfo=timezone.utc)
        return date_value.isoformat()

    if isinstance(date_value, str):
        date_str = date_value.strip()
        if not date_str or _is_redacted(date_str):
            return None

        for fmt in DATE_PATTERNS:
            try:
                dt = datetime.strptime(date_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat()
            except ValueError:
                continue

        return None

    return None

def _is_redacted(value: Optional[str]) -> bool:
    """Detecta si un valor WHOIS está redacted/oculto."""
    if not value or not isinstance(value, str):
        return True
    value_lower = value.lower().strip()
    return any(indicator in value_lower for indicator in REDACTED_INDICATORS)

def _extract_registrar(registrar_value: Optional[Union[str, List]]) -> Optional[str]:
    """Extrae el nombre del registrar de un valor."""
    if registrar_value is None:
        return None

    if isinstance(registrar_value, list):
        candidates = [r for r in registrar_value if r and not _is_redacted(str(r))]
        if not candidates:
            return None
        if len(candidates) == 1:
            return str(candidates[0]).strip()
        return "; ".join(str(r).strip() for r in candidates[:3])

    if isinstance(registrar_value, str):
        val = registrar_value.strip()
        if _is_redacted(val):
            return None
        return val if val else None

    return str(registrar_value).strip() if registrar_value else None

def _is_data_incomplete(domain_info) -> bool:
    """Detecta si el objeto WHOIS retornado está vacío o redacted."""
    if domain_info is None:
        return True

    attrs = ["registrar", "creation_date", "expiration_date", "name_servers"]
    has_any_data = False
    for attr in attrs:
        val = getattr(domain_info, attr, None)
        if val is not None:
            if isinstance(val, list) and val:
                has_any_data = True
                break
            if isinstance(val, str) and val.strip() and not _is_redacted(val):
                has_any_data = True
                break
            if isinstance(val, datetime):
                has_any_data = True
                break

    return not has_any_data

class WhoisScanner:
    """Escáner de registros WHOIS."""

    @staticmethod
    async def get_whois(hostname: str) -> Optional[WhoisData]:
        """Obtiene información WHOIS de un dominio."""
        try:
            safe_hostname = _validate_hostname(hostname)
        except ValueError as exc:
            logger.warning(f"Validación rechazada: {exc}")
            return None

        try:
            domain_info = await asyncio.wait_for(
                asyncio.to_thread(whois.whois, safe_hostname),
                timeout=WHOIS_TIMEOUT
            )
        except Exception as exc:
            logger.warning(f"Error en consulta WHOIS para {safe_hostname}: {exc}")
            return None

        if _is_data_incomplete(domain_info):
            return None

        try:
            registrar = _extract_registrar(getattr(domain_info, "registrar", None))
            creation_date = _parse_whois_date(getattr(domain_info, "creation_date", None))
            expiration_date = _parse_whois_date(getattr(domain_info, "expiration_date", None))

            if not registrar and not creation_date and not expiration_date:
                return None

            return WhoisData(
                registrar=registrar,
                creation_date=creation_date,
                expiration_date=expiration_date
            )

        except Exception as exc:
            logger.error(f"Error procesando WHOIS para {safe_hostname}: {exc}")
            return None