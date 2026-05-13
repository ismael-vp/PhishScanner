import os
import logging
import hashlib
import hmac
import time
import json
from typing import List, Dict, Any
from urllib.parse import urlparse

from fastapi import (
    APIRouter, File, UploadFile, HTTPException, Body, Header,
    Request, status, Depends
)
from pydantic import BaseModel, Field, field_validator

from services.virustotal_service import VirusTotalService
from services.ai_service import AIService
from services.osint_service import OSINTService
from services.image_phishing_service import ImagePhishingService
from utils.cache_service import CacheService
from services.utils import is_safe_url

logger = logging.getLogger(__name__)
router = APIRouter()

vt_service = VirusTotalService()
ai_service = AIService()
image_service = ImagePhishingService()
cache_service = CacheService()

MAX_IMAGE_SIZE = 10 * 1024 * 1024
RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW = 60
MAX_CHAT_MESSAGES = 20
MAX_CHAT_CONTENT_LENGTH = 4000
MAX_SCAN_CONTEXT_SIZE = 50000
IMAGE_ALLOWED_TYPES = {
    "image/jpeg", "image/png", "image/webp",
    "image/gif", "image/bmp", "image/tiff"
}

_rate_limit_store: Dict[str, List[float]] = {}

def get_client_ip(request: Request) -> str:
    """Extrae la IP real del cliente respetando headers de proxy."""
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"

def check_rate_limit(client_ip: str) -> bool:
    """Retorna True si la solicitud está dentro del límite permitido."""
    now = time.time()
    window = _rate_limit_store.get(client_ip, [])
    window = [t for t in window if now - t < RATE_LIMIT_WINDOW]
    if len(window) >= RATE_LIMIT_REQUESTS:
        _rate_limit_store[client_ip] = window
        return False
    window.append(now)
    _rate_limit_store[client_ip] = window
    return True

async def rate_limit_dependency(request: Request):
    client_ip = get_client_ip(request)
    if not check_rate_limit(client_ip):
        logger.warning(f"Rate limit excedido para IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiadas solicitudes. Por favor, espera un momento."
        )

def serialize_to_dict(obj: Any) -> Any:
    """Serializa objetos Pydantic o dicts a dicts estándar."""
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    raise TypeError(f"Objeto no serializable a dict: {type(obj)}")

def validate_image_magic_bytes(image_bytes: bytes) -> str:
    """Valida el tipo REAL de una imagen inspeccionando sus magic bytes."""
    if len(image_bytes) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Archivo demasiado pequeño o corrupto."
        )

    if image_bytes[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if image_bytes[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if image_bytes[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if image_bytes[:2] == b"BM":
        return "image/bmp"
    if image_bytes[:4] in (b"II*\x00", b"MM\x00*"):
        return "image/tiff"
    if image_bytes[:4] == b"RIFF" and image_bytes[8:12] == b"WEBP":
        return "image/webp"

    raise HTTPException(
        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        detail="Formato de imagen no soportado, corrupto o posible archivo malicioso."
    )

def validate_url_safety(url: str) -> str:
    """Valida formato y seguridad de una URL."""
    url = url.strip()
    if not url:
        raise ValueError("La URL no puede estar vacía")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("La URL debe usar protocolo http:// o https://")
    if not parsed.netloc:
        raise ValueError("La URL no contiene un dominio válido")

    if not is_safe_url(url):
        raise ValueError(
            "La URL no es segura para analizar. Se detectó un posible intento de SSRF."
        )

    return url

class URLRequest(BaseModel):
    url: str = Field(..., min_length=1, description="URL a analizar")

    @field_validator("url")
    @classmethod
    def check_url(cls, v: str) -> str:
        return validate_url_safety(v)

class ChatMessage(BaseModel):
    role: str = Field(..., pattern="^(system|user|assistant)$")
    content: str = Field(..., min_length=1, max_length=MAX_CHAT_CONTENT_LENGTH)

class ChatRequest(BaseModel):
    messages: List[ChatMessage] = Field(..., max_length=MAX_CHAT_MESSAGES)
    scan_context: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("scan_context")
    @classmethod
    def limit_context_size(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        try:
            size = len(json.dumps(v))
        except (TypeError, ValueError):
            raise ValueError("El contexto contiene datos no serializables")
        if size > MAX_SCAN_CONTEXT_SIZE:
            raise ValueError(
                f"El contexto del escaneo excede el tamaño máximo permitido ({MAX_SCAN_CONTEXT_SIZE} bytes)"
            )
        return v

class ScriptExplainRequest(BaseModel):
    script_url: str = Field(..., min_length=1, description="URL del script a explicar")

    @field_validator("script_url")
    @classmethod
    def check_script_url(cls, v: str) -> str:
        return validate_url_safety(v)

@router.post(
    "/analyze/url",
    dependencies=[Depends(rate_limit_dependency)]
)
async def analyze_url(request: URLRequest = Body(...)):
    """Analiza una URL en busca de phishing, malware y anomalías."""
    try:
        cached_result = cache_service.get(request.url, "url")
        if cached_result:
            return cached_result

        vt_stats = await vt_service.get_url_report(request.url)
        osint_data = await OSINTService.get_osint_data(request.url)

        # Heurística de Respaldo
        if vt_stats.get("malicious", 0) == 0 and vt_stats.get("suspicious", 0) == 0:
            is_suspicious_osint = False
            heuristic_reasons = []

            if getattr(osint_data, "is_typosquatting", False):
                is_suspicious_osint = True
                heuristic_reasons.append("Posible Typosquatting detectado")

            if getattr(osint_data, "has_dangerous_form", False):
                is_suspicious_osint = True
                heuristic_reasons.append("Formulario de login sospechoso o redirección ofuscada")

            if getattr(osint_data, "cloaking_detected", False):
                is_suspicious_osint = True
                heuristic_reasons.append("Detección de Cloaking (contenido engañoso para bots)")

            url_struct = getattr(osint_data, "url_structure", None)
            if url_struct and getattr(url_struct, "risk_score", 0) >= 60:
                is_suspicious_osint = True
                heuristic_reasons.append(
                    f"Estructura de URL maliciosa (Score: {url_struct.risk_score}/100)"
                )

            if is_suspicious_osint:
                vt_stats["suspicious"] = vt_stats.get("suspicious", 0) + 1
                vt_stats["heuristic_flag"] = " | ".join(heuristic_reasons)

        ai_summary = await ai_service.generate_analysis_explanation(vt_stats, "url")

        result = {
            "type": "url",
            "stats": vt_stats,
            "ai_summary": ai_summary,
            "osint_data": serialize_to_dict(osint_data),
            "status": "success"
        }

        cache_service.set(request.url, result, "url")
        return result

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Error no controlado en analyze_url: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Se produjo un error interno al procesar la URL."
        )

@router.post(
    "/analyze/image",
    dependencies=[Depends(rate_limit_dependency)]
)
async def analyze_image(file: UploadFile = File(...)):
    """Analiza una imagen en busca de phishing mediante OCR e IA."""
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El archivo no es válido o no tiene nombre."
        )

    try:
        image_bytes = await file.read()

        if len(image_bytes) > MAX_IMAGE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"La imagen no puede superar los {MAX_IMAGE_SIZE // (1024 * 1024)}MB."
            )

        detected_type = validate_image_magic_bytes(image_bytes)
        if detected_type not in IMAGE_ALLOWED_TYPES:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail=f"Formato de imagen no soportado: {detected_type}"
            )

        file_hash = hashlib.sha256(image_bytes).hexdigest()
        cached_result = cache_service.get(file_hash, "image")
        if cached_result:
            return cached_result

        analysis = await image_service.analyze_for_phishing(image_bytes)

        result = {
            "type": "image",
            "status": "success",
            "image_analysis": analysis,
            "stats": {
                "malicious": 1 if analysis.get("is_phishing") else 0,
                "suspicious": 0,
                "harmless": 0 if analysis.get("is_phishing") else 1,
                "undetected": 0,
                "timeout": 0,
            }
        }

        cache_service.set(file_hash, result, "image")
        return result

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Error no controlado en analyze_image: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Se produjo un error interno al procesar la imagen."
        )

@router.post(
    "/chat",
    dependencies=[Depends(rate_limit_dependency)]
)
async def chat_endpoint(request: ChatRequest = Body(...)):
    """Endpoint de chat con contexto del escaneo."""
    try:
        clean_context = request.scan_context.copy()

        if "osint_data" in clean_context and isinstance(clean_context["osint_data"], dict):
            clean_context["osint_data"] = {
                k: v for k, v in clean_context["osint_data"].items()
                if k != "html_content"
            }

        if "stats" in clean_context and isinstance(clean_context["stats"], dict):
            if "full_results" in clean_context["stats"]:
                clean_context["stats"]["full_results"] = clean_context["stats"]["full_results"][:5]

        messages_dicts = [
            msg.model_dump() if hasattr(msg, "model_dump") else msg.dict()
            for msg in request.messages
        ]

        reply = await ai_service.chat_with_context(messages_dicts, clean_context)
        return {"reply": reply}

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Error no controlado en chat_endpoint: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No se pudo procesar la consulta con la IA."
        )

@router.post(
    "/explain-script",
    dependencies=[Depends(rate_limit_dependency)]
)
async def explain_script_endpoint(request: ScriptExplainRequest = Body(...)):
    """Explica un script remoto."""
    try:
        explanation = await ai_service.explain_script(request.script_url)
        return {"explanation": explanation}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Error no controlado en explain_script: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno al analizar el script."
        )

@router.post(
    "/admin/clear-cache",
    tags=["Admin"],
    dependencies=[Depends(rate_limit_dependency)]
)
async def clear_cache(
    x_admin_key: str = Header(
        ...,
        min_length=1,
        description="Clave de acceso de administrador"
    )
):
    """Limpia manualmente toda la base de datos de caché."""
    admin_secret = os.getenv("ADMIN_SECRET_KEY", "").strip()

    if len(admin_secret) < 16:
        logger.error(
            "ADMIN_SECRET_KEY no está configurada o no cumple longitud mínima de seguridad (16 chars)."
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de administración no configurado correctamente."
        )

    if not hmac.compare_digest(x_admin_key, admin_secret):
        logger.warning("Intento de acceso denegado a /api/admin/clear-cache.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado: Credenciales no válidas."
        )

    success = cache_service.clear_all()
    if success:
        return {"status": "success", "message": "Caché eliminada correctamente."}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No se pudo eliminar la caché."
        )

