import asyncio
import ipaddress
import logging
import os
from typing import Optional

import httpx

from models.osint_models import GeoScannerResult, GeolocationData
from services.utils import is_safe_url

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = float(os.getenv("GEO_SCANNER_TIMEOUT", "5.0"))
MAX_RETRIES = int(os.getenv("GEO_SCANNER_MAX_RETRIES", "2"))
USER_AGENT = os.getenv(
    "GEO_SCANNER_USER_AGENT",
    "PhishingScanner/1.0 (Security Research Platform)"
)

class GeoScanner:
    """Escáner de geolocalización y reputación IP."""

    _client: Optional[httpx.AsyncClient] = None

    @classmethod
    def _get_client(cls) -> httpx.AsyncClient:
        """Retorna un cliente HTTPX compartido."""
        if cls._client is None or cls._client.is_closed:
            cls._client = httpx.AsyncClient(
                timeout=httpx.Timeout(HTTP_TIMEOUT, connect=3.0),
                headers={"User-Agent": USER_AGENT},
                limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
                follow_redirects=False,
            )
        return cls._client

    @classmethod
    async def close_client(cls):
        """Cierra el cliente HTTPX."""
        if cls._client and not cls._client.is_closed:
            await cls._client.aclose()
            cls._client = None

    @staticmethod
    def validate_public_ip(ip_address: str) -> str:
        """Valida que la dirección sea una IPv4 o IPv6 pública válida."""
        if not ip_address or not isinstance(ip_address, str):
            raise ValueError("La dirección IP no puede estar vacía")

        ip_address = ip_address.strip()
        if not ip_address:
            raise ValueError("La dirección IP no puede estar vacía")

        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError as exc:
            raise ValueError(f"Dirección IP inválida: {ip_address}") from exc

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or \
           ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            raise ValueError(f"IP no permitida (privada/reservada): {ip_address}")

        return str(ip_obj)

    @staticmethod
    async def _fetch_with_retry(
        client: httpx.AsyncClient,
        method: str,
        url: str,
        **kwargs
    ) -> Optional[httpx.Response]:
        """Realiza una petición HTTP con reintentos."""
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = await client.request(method, url, **kwargs)

                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")
                    wait = float(retry_after) if retry_after else 2 ** attempt
                    logger.warning(f"Rate limit en {url}. Reintentando en {wait}s.")
                    await asyncio.sleep(wait)
                    continue

                return response

            except httpx.TimeoutException:
                logger.warning(f"Timeout en {url} (intento {attempt + 1})")
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(1.0)
                    continue
                return None
            except httpx.NetworkError as exc:
                logger.warning(f"Error de red en {url} (intento {attempt + 1})")
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(1.0)
                    continue
                return None
            except Exception as exc:
                logger.error(f"Error inesperado en petición a {url}: {exc}", exc_info=True)
                return None

        return None

    @staticmethod
    async def get_geolocation_and_reputation(ip_address: str) -> GeoScannerResult:
        """Obtiene geolocalización y reputación de una IP pública."""
        result = GeoScannerResult()

        try:
            validated_ip = GeoScanner.validate_public_ip(ip_address)
        except ValueError as exc:
            logger.warning(f"Validación de IP rechazada: {exc}")
            return result

        client = GeoScanner._get_client()

        try:
            from urllib.parse import quote
            safe_ip = quote(validated_ip, safe="")
            url = f"https://ip-api.com/json/{safe_ip}"

            response = await GeoScanner._fetch_with_retry(client, "GET", url)

            if response and response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    result.geolocation = GeolocationData(
                        ip=validated_ip,
                        lat=float(data.get("lat", 0.0)),
                        lon=float(data.get("lon", 0.0)),
                        country=data.get("country", ""),
                        country_code=data.get("countryCode", ""),
                        city=data.get("city", ""),
                        isp=data.get("isp", "")
                    )
        except Exception as exc:
            logger.error(f"Error en geolocalización para {validated_ip}: {exc}")

        abuse_api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        if abuse_api_key:
            try:
                headers = {"Key": abuse_api_key, "Accept": "application/json"}
                response = await GeoScanner._fetch_with_retry(
                    client,
                    "GET",
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": validated_ip, "maxAgeInDays": "90"},
                    headers=headers
                )

                if response and response.status_code == 200:
                    data = response.json().get("data", {})
                    result.abuse_confidence_score = data.get("abuseConfidenceScore")
                    result.total_reports = data.get("totalReports")
            except Exception as exc:
                logger.error(f"Error en AbuseIPDB para {validated_ip}: {exc}")

        return result