import asyncio
import base64
import logging
import os
import re
import time

import httpx
from fastapi import HTTPException

from services.utils import is_safe_url

logger = logging.getLogger(__name__)

# --- Constantes configurables ---
VT_API_URL = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = float(os.getenv("VT_TIMEOUT", "30.0"))
VT_POLL_MAX_ATTEMPTS = int(os.getenv("VT_POLL_MAX_ATTEMPTS", "10"))
VT_POLL_INTERVAL = float(os.getenv("VT_POLL_INTERVAL", "3.0"))
VT_POLL_MAX_TOTAL_TIME = float(os.getenv("VT_POLL_MAX_TOTAL_TIME", "45.0"))
VT_MAX_FILE_SIZE = 32 * 1024 * 1024  # 32MB
VT_RATE_LIMIT_REQUESTS = int(os.getenv("VT_RATE_LIMIT_REQUESTS", "4"))
VT_RATE_LIMIT_WINDOW = int(os.getenv("VT_RATE_LIMIT_WINDOW", "60"))


# =============================================================================
# RATE LIMITING POR TOKEN/IP (memoria local; usar Redis en multi-worker)
# =============================================================================

_vt_rate_limit_store: dict[str, list[float]] = {}


def _check_vt_rate_limit(identifier: str) -> bool:
    """Verifica si una petición a VT está dentro del límite permitido."""
    now = time.time()
    window = _vt_rate_limit_store.get(identifier, [])
    window = [t for t in window if now - t < VT_RATE_LIMIT_WINDOW]
    if len(window) >= VT_RATE_LIMIT_REQUESTS:
        _vt_rate_limit_store[identifier] = window
        return False
    window.append(now)
    _vt_rate_limit_store[identifier] = window
    return True


# =============================================================================
# VALIDACIÓN DE INPUTS
# =============================================================================

def _validate_file_hash(file_hash: str) -> str:
    """Valida que un string sea un hash SHA-256 válido."""
    if not file_hash or not isinstance(file_hash, str):
        raise ValueError("Hash de archivo inválido")
    file_hash = file_hash.strip().lower()
    if not re.match(r"^[a-f0-9]{64}$", file_hash):
        raise ValueError(f"Hash SHA-256 inválido: {file_hash}")
    return file_hash


def _validate_url_for_vt(url: str) -> str:
    """Valida una URL antes de enviarla a VirusTotal."""
    if not url or not isinstance(url, str):
        raise ValueError("URL inválida")
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError("La URL debe usar http:// o https://")
    # Validación SSRF centralizada
    if not is_safe_url(url):
        raise ValueError("La URL no es segura para analizar (posible SSRF)")
    return url


def _encode_url_for_vt(url: str) -> str:
    """Codifica una URL para el endpoint de VT (base64url)."""
    try:
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")
    except UnicodeEncodeError as exc:
        raise ValueError(f"URL contiene caracteres no válidos: {exc}") from exc


# =============================================================================
# CLASE PRINCIPAL
# =============================================================================

class VirusTotalService:
    """
    Servicio de integración con VirusTotal API v3.

    Usa un cliente HTTPX compartido y protege contra SSRF, rate limits
    y fugas de información.
    """

    _client: httpx.AsyncClient | None = None

    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY", "").strip()
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}

    @classmethod
    def _get_client(cls) -> httpx.AsyncClient:
        """Retorna un cliente HTTPX compartido."""
        if cls._client is None or cls._client.is_closed:
            cls._client = httpx.AsyncClient(
                timeout=httpx.Timeout(VT_TIMEOUT, connect=5.0),
                limits=httpx.Limits(max_keepalive_connections=3, max_connections=5),
                follow_redirects=False,
            )
        return cls._client

    @classmethod
    async def close_client(cls):
        """Cierra el cliente HTTPX. Llamar al shutdown de la app."""
        if cls._client and not cls._client.is_closed:
            await cls._client.aclose()
            cls._client = None

    def _check_api_key(self):
        """Verifica que la API key esté configurada."""
        if not self.api_key:
            logger.error("VT_API_KEY no está configurada")
            raise HTTPException(
                status_code=503,
                detail="Servicio de análisis de VirusTotal no disponible."
            )

    def _check_rate_limit(self):
        """Verifica el rate limit propio antes de gastar cuota de VT."""
        if not _check_vt_rate_limit("global"):
            logger.warning("Rate limit propio de VT excedido")
            raise HTTPException(
                status_code=429,
                detail="Demasiadas solicitudes de análisis. Por favor, espera un momento."
            )

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> dict:
        """
        Realiza una petición a la API de VirusTotal.

        Args:
            method: Método HTTP.
            endpoint: Endpoint relativo (ej. "/urls/{id}").
            **kwargs: Argumentos adicionales para httpx.

        Returns:
            Dict con la respuesta JSON.
        """
        self._check_api_key()
        self._check_rate_limit()

        client = self._get_client()
        url = f"{VT_API_URL}{endpoint}"

        # Merge headers (sin sobrescribir Content-Type en uploads)
        request_headers = self.headers.copy()
        if "headers" in kwargs:
            request_headers.update(kwargs.pop("headers"))

        try:
            response = await client.request(method, url, headers=request_headers, **kwargs)
        except httpx.TimeoutException:
            logger.warning(f"Timeout en petición a VT: {method} {endpoint}")
            raise HTTPException(
                status_code=504,
                detail="VirusTotal no respondió a tiempo. Intenta de nuevo más tarde."
            )
        except httpx.NetworkError as exc:
            logger.warning(f"Error de red con VT: {exc}")
            raise HTTPException(
                status_code=502,
                detail="Error de conexión con VirusTotal."
            )

        # Manejo de errores HTTP específicos
        if response.status_code == 404:
            raise HTTPException(
                status_code=404,
                detail="El análisis para este recurso no fue encontrado en VirusTotal."
            )
        if response.status_code == 429:
            logger.warning("Rate limit de VirusTotal alcanzado")
            raise HTTPException(
                status_code=429,
                detail="Se ha excedido el límite de cuota de VirusTotal. Por favor, intenta de nuevo más tarde."
            )
        if response.status_code == 401:
            logger.error("API key de VirusTotal inválida o expirada")
            raise HTTPException(
                status_code=401,
                detail="Error de autenticación con VirusTotal."
            )

        # Otros errores HTTP
        if response.status_code >= 400:
            logger.warning(f"Error HTTP {response.status_code} de VT: {endpoint}")
            raise HTTPException(
                status_code=502,
                detail="Error al comunicarse con VirusTotal."
            )

        try:
            return response.json()
        except Exception as exc:
            logger.error(f"Respuesta no JSON de VT: {exc}")
            raise HTTPException(
                status_code=502,
                detail="Respuesta inesperada de VirusTotal."
            )

    def _extract_useful_stats(self, data: dict, is_analysis: bool = False) -> dict:
        """Extrae estadísticas de detección del reporte de VT."""
        try:
            attributes = data["data"]["attributes"]
            stats_key = "stats" if is_analysis else "last_analysis_stats"
            results_key = "results" if is_analysis else "last_analysis_results"

            stats = attributes[stats_key]
            results = attributes.get(results_key, {})

            detailed_results = []
            for engine_name, result in results.items():
                detailed_results.append({
                    "name": engine_name,
                    "status": result.get("category", "unknown"),
                    "result": result.get("result", None),
                    "method": result.get("method", "blacklist")
                })

            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "timeout": stats.get("timeout", 0),
                "full_results": detailed_results
            }
        except (KeyError, TypeError) as exc:
            logger.error(f"Error extrayendo stats de VT: {exc}")
            raise HTTPException(
                status_code=502,
                detail="No se pudieron extraer las estadísticas del reporte de VirusTotal."
            )

    async def _poll_analysis(self, analysis_id: str) -> dict:
        """
        Realiza polling al endpoint de análisis hasta completar o timeout.

        Usa backoff adaptativo y un timeout total estricto.
        """
        endpoint = f"/analyses/{analysis_id}"
        start_time = time.time()
        attempt = 0

        while True:
            elapsed = time.time() - start_time
            if elapsed > VT_POLL_MAX_TOTAL_TIME:
                logger.warning(f"Polling de VT excedió timeout total ({VT_POLL_MAX_TOTAL_TIME}s)")
                raise HTTPException(
                    status_code=408,
                    detail="El análisis de VirusTotal tomó demasiado tiempo. Intenta consultar más tarde."
                )

            if attempt >= VT_POLL_MAX_ATTEMPTS:
                logger.warning(f"Polling de VT agotó {VT_POLL_MAX_ATTEMPTS} intentos")
                raise HTTPException(
                    status_code=408,
                    detail="El análisis de VirusTotal no se completó a tiempo."
                )

            # Fix Caos #6: Evitar _make_request en polling para no consumir rate limit global (memoria)
            client = self._get_client()
            url = f"{VT_API_URL}{endpoint}"
            try:
                response = await client.request("GET", url, headers=self.headers)
            except httpx.TimeoutException:
                raise HTTPException(status_code=504, detail="VT polling timeout.")
            except httpx.NetworkError:
                raise HTTPException(status_code=502, detail="Error de red en VT polling.")
            
            if response.status_code >= 400:
                raise HTTPException(status_code=502, detail=f"VT error en polling: {response.status_code}")
                
            try:
                data = response.json()
            except Exception:
                raise HTTPException(status_code=502, detail="Respuesta no JSON en polling VT.")

            status = data.get("data", {}).get("attributes", {}).get("status", "queued")

            if status == "completed":
                return self._extract_useful_stats(data, is_analysis=True)

            # Backoff adaptativo: intervalo base * (1 + attempt * 0.5)
            wait_time = VT_POLL_INTERVAL * (1 + attempt * 0.5)
            wait_time = min(wait_time, 10.0)  # Cap a 10s máximo
            logger.debug(f"VT polling esperando... status={status}, esperando {wait_time:.1f}s")
            await asyncio.sleep(wait_time)
            attempt += 1

    async def get_file_report(self, file_hash: str, file_bytes: bytes) -> dict:
        """
        Consulta el reporte de un archivo por su hash SHA-256.
        Si no existe, lo sube (si < 32MB) y hace polling.

        Args:
            file_hash: Hash SHA-256 del archivo (64 hex chars).
            file_bytes: Contenido del archivo en bytes.
        """
        # Validar hash
        try:
            safe_hash = _validate_file_hash(file_hash)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        # Validar tamaño
        if len(file_bytes) > VT_MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"El archivo excede el límite de {VT_MAX_FILE_SIZE // (1024*1024)}MB para VirusTotal."
            )

        endpoint = f"/files/{safe_hash}"

        try:
            data = await self._make_request("GET", endpoint)
            return self._extract_useful_stats(data)
        except HTTPException as exc:
            if exc.status_code == 404:
                # Subir archivo
                logger.info(f"Archivo no encontrado en VT, subiendo: {safe_hash}")

                files = {"file": ("upload.bin", file_bytes)}
                try:
                    response_data = await self._make_request(
                        "POST", "/files", files=files
                    )
                except HTTPException:
                    raise
                except Exception as exc:
                    logger.error(f"Error subiendo archivo a VT: {exc}", exc_info=True)
                    raise HTTPException(
                        status_code=500,
                        detail="Error al subir el archivo a VirusTotal."
                    )

                analysis_id = response_data.get("data", {}).get("id")
                if not analysis_id:
                    logger.error("VT no retornó analysis_id tras upload")
                    raise HTTPException(
                        status_code=502,
                        detail="Respuesta inesperada de VirusTotal tras subir archivo."
                    )

                return await self._poll_analysis(analysis_id)
            raise exc

    async def get_url_report(self, url: str) -> dict:
        """
        Consulta el reporte de una URL en VirusTotal.
        Si no existe, la envía y hace polling.

        Args:
            url: URL completa (http:// o https://).
        """
        # Validar URL (incluye SSRF)
        try:
            safe_url = _validate_url_for_vt(url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        url_id = _encode_url_for_vt(safe_url)
        endpoint = f"/urls/{url_id}"

        try:
            data = await self._make_request("GET", endpoint)
            return self._extract_useful_stats(data)
        except HTTPException as exc:
            if exc.status_code == 404:
                # Enviar URL para escaneo
                logger.info(f"URL no encontrada en VT, enviando: {safe_url}")

                form_data = {"url": safe_url}
                try:
                    response_data = await self._make_request(
                        "POST",
                        "/urls",
                        data=form_data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"}
                    )
                except HTTPException:
                    raise
                except Exception as exc:
                    logger.error(f"Error enviando URL a VT: {exc}", exc_info=True)
                    raise HTTPException(
                        status_code=500,
                        detail="Error al enviar la URL a VirusTotal."
                    )

                analysis_id = response_data.get("data", {}).get("id")
                if not analysis_id:
                    logger.error("VT no retornó analysis_id tras enviar URL")
                    raise HTTPException(
                        status_code=502,
                        detail="Respuesta inesperada de VirusTotal."
                    )

                return await self._poll_analysis(analysis_id)
            raise exc
