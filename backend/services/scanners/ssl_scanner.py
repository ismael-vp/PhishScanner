import asyncio
import logging
import os
import socket
import ssl
from datetime import datetime, timezone

from models.osint_models import SSLData
from services.utils import is_safe_url

logger = logging.getLogger(__name__)

SSL_TIMEOUT = float(os.getenv("SSL_SCANNER_TIMEOUT", "5.0"))
MAX_HOSTNAME_LENGTH = 253
EXPIRY_WARNING_DAYS = 7

SUSPICIOUS_ISSUERS = {
    "self-signed", "localhost", "example.com", "test", "dummy",
    "unknown", "none", "", "ca", "root"
}

def _validate_hostname_for_ssl(hostname: str) -> str:
    """Valida que el hostname sea seguro para conexión SSL directa."""
    if not is_safe_url(f"https://{hostname}"):
        raise ValueError(f"Hostname bloqueado: {hostname}")
    return hostname

def _parse_ssl_date(date_str: str | None) -> str | None:
    """Convierte una fecha SSL a ISO 8601."""
    if not date_str:
        return None

    formats = [
        "%b %d %H:%M:%S %Y GMT",
        "%b %d %H:%M:%S %Y %Z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue

    logger.warning(f"No se pudo parsear fecha SSL: {date_str}")
    return None

def _analyze_issuer(issuer_name: str | None) -> tuple[str | None, bool, bool]:
    """Analiza el nombre del issuer del certificado."""
    if not issuer_name:
        return None, True, True

    issuer_lower = issuer_name.lower().strip()
    is_self_signed = any(
        indicator in issuer_lower
        for indicator in ("self signed", "self-signed", "localhost", "unknown")
    )
    is_suspicious = any(
        suspicious in issuer_lower
        for suspicious in SUSPICIOUS_ISSUERS
    ) or is_self_signed

    return issuer_name, is_self_signed, is_suspicious

def _check_expiry(not_after_iso: str | None) -> tuple[bool, bool, int | None]:
    """Verifica el estado de expiración del certificado."""
    if not not_after_iso:
        return True, True, None

    try:
        expiry_dt = datetime.fromisoformat(not_after_iso)
        now = datetime.now(timezone.utc)

        if expiry_dt.tzinfo is None:
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)

        days_remaining = (expiry_dt - now).days
        is_expired = days_remaining < 0
        is_expiring_soon = 0 <= days_remaining <= EXPIRY_WARNING_DAYS

        return is_expired, is_expiring_soon, days_remaining
    except Exception as exc:
        logger.warning(f"Error calculando expiración: {exc}")
        return True, True, None

class SSLScanner:
    """Escáner de certificados SSL/TLS."""

    @staticmethod
    async def get_ssl_info(hostname: str) -> SSLData | None:
        """Obtiene información del certificado SSL de un hostname."""
        try:
            safe_hostname = _validate_hostname_for_ssl(hostname)
        except ValueError as exc:
            logger.warning(f"Validación rechazada: {exc}")
            return None

        def _fetch_cert():
            context = ssl.create_default_context()
            with socket.create_connection((safe_hostname, 443), timeout=SSL_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=safe_hostname) as ssock:
                    return ssock.getpeercert()

        try:
            cert = await asyncio.to_thread(_fetch_cert)
        except ssl.SSLError as exc:
            logger.info(f"Error SSL en {safe_hostname}: {exc}")
            return SSLData(
                issuer=None,
                expiration_date=None,
                is_self_signed=True,
                is_suspicious=True,
                is_expired=True,
                is_expiring_soon=True,
                days_until_expiry=None,
                ssl_error=str(exc)
            )
        except Exception as exc:
            logger.info(f"Fallo conexión SSL para {safe_hostname}: {exc}")
            return None

        if not cert:
            return None

        try:
            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            issuer_raw = issuer_dict.get("organizationName") or issuer_dict.get("commonName")
            issuer_name, is_self_signed, is_suspicious = _analyze_issuer(issuer_raw)

            not_after_raw = cert.get("notAfter")
            not_after_iso = _parse_ssl_date(not_after_raw)
            is_expired, is_expiring_soon, days_remaining = _check_expiry(not_after_iso)

            if is_expired or is_expiring_soon:
                is_suspicious = True

            return SSLData(
                issuer=issuer_name,
                expiration_date=not_after_iso,
                is_self_signed=is_self_signed,
                is_suspicious=is_suspicious,
                is_expired=is_expired,
                is_expiring_soon=is_expiring_soon,
                days_until_expiry=days_remaining
            )
        except Exception as exc:
            logger.error(f"Error procesando cert de {safe_hostname}: {exc}")
            return None