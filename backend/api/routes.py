import os
import logging
import hashlib
from fastapi import APIRouter, File, UploadFile, HTTPException, Body, Header
from pydantic import BaseModel
from services.virustotal_service import VirusTotalService
from services.ai_service import AIService
from services.osint_service import OSINTService
from services.image_phishing_service import ImagePhishingService
from utils.cache_service import CacheService

# Configurar logger para evitar exponer errores al cliente
logger = logging.getLogger(__name__)

router = APIRouter()

# Instanciar servicios
vt_service = VirusTotalService()
ai_service = AIService()
image_service = ImagePhishingService()
cache_service = CacheService()


class URLRequest(BaseModel):
    url: str

@router.post("/api/analyze/url")
async def analyze_url(request: URLRequest = Body(...)):
    if not request.url:
        raise HTTPException(status_code=400, detail="La URL no puede estar vacía.")
        
    try:
        # 0. Verificar Caché
        cached_result = cache_service.get(request.url, "url")
        if cached_result:
            return cached_result

        # 1. Consultar reporte a VirusTotal
        vt_stats = await vt_service.get_url_report(request.url)
        
        # 2. Obtener datos OSINT masivos en paralelo
        osint_data = await OSINTService.get_osint_data(request.url)
        
        # Heurística de Respaldo: Si VT da 0 pero OSINT detecta anomalías
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
            if url_struct and url_struct.risk_score >= 60:
                is_suspicious_osint = True
                heuristic_reasons.append(f"Estructura de URL maliciosa (Score: {url_struct.risk_score}/100)")

            if is_suspicious_osint:
                vt_stats["suspicious"] = vt_stats.get("suspicious", 0) + 1
                vt_stats["heuristic_flag"] = " | ".join(heuristic_reasons)
        
        # 3. Generar explicación con Inteligencia Artificial
        ai_summary = await ai_service.generate_analysis_explanation(vt_stats, "url")
        
        # 4. Formatear respuesta
        result = {
            "type": "url",
            "stats": vt_stats,
            "ai_summary": ai_summary,
            "osint_data": osint_data.dict(), # Convertimos a dict para serializar a JSON en cache
            "status": "success"
        }

        # 5. Guardar en Caché
        cache_service.set(request.url, result, "url")

        return result

    except HTTPException as e:
        # Dejar pasar excepciones controladas HTTP (e.g. 404 de VT o 429 de límite de API)
        raise e
    except Exception as e:
        # NUEVO: Prevenir Information Disclosure. Se loguea el error real, pero no se envía al frontend.
        logger.error(f"Error no controlado en analyze_url: {e}", exc_info=True)
        return {
            "type": "url",
            "status": "error",
            "message": "Se produjo un error interno al procesar la URL."
        }


IMAGE_ALLOWED_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif", "image/bmp", "image/tiff"}

@router.post("/api/analyze/image")
async def analyze_image(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="El archivo no es válido.")
    if file.content_type not in IMAGE_ALLOWED_TYPES:
        raise HTTPException(
            status_code=415,
            detail=f"Formato no soportado: {file.content_type}. Sube una imagen (JPG, PNG, WEBP, GIF)."
        )
    try:
        image_bytes = await file.read()
        if len(image_bytes) > 10 * 1024 * 1024:  # 10MB max
            raise HTTPException(status_code=413, detail="La imagen no puede superar los 10MB.")

        # 0. Verificar Caché (por hash SHA256)
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

        # 5. Guardar en Caché
        cache_service.set(file_hash, result, "image")

        return result

    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error no controlado en analyze_image: {e}", exc_info=True)
        return {"type": "image", "status": "error", "message": "Se produjo un error interno al procesar la imagen."}


class ChatRequest(BaseModel):
    messages: list
    scan_context: dict

@router.post("/api/chat")
async def chat_endpoint(request: ChatRequest = Body(...)):
    try:
        # Limpiar el contexto para evitar saturar los tokens de la IA (Remover HTML y datos pesados)
        clean_context = request.scan_context.copy()
        
        # Eliminar recursivamente o en profundidad los datos que no aportan al chat
        if "osint_data" in clean_context and isinstance(clean_context["osint_data"], dict):
            clean_context["osint_data"] = {k: v for k, v in clean_context["osint_data"].items() if k != "html_content"}
        
        if "stats" in clean_context and isinstance(clean_context["stats"], dict) and "full_results" in clean_context["stats"]:
            clean_context["stats"]["full_results"] = clean_context["stats"]["full_results"][:5]

        reply = await ai_service.chat_with_context(request.messages, clean_context)
        return {"reply": reply}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error no controlado en chat_endpoint: {e}", exc_info=True)
        return {"status": "error", "message": "No se pudo procesar la consulta con la IA."}


class ScriptExplainRequest(BaseModel):
    script_url: str

@router.post("/api/explain-script")
async def explain_script_endpoint(request: ScriptExplainRequest = Body(...)):
    if not request.script_url:
        raise HTTPException(status_code=400, detail="La URL del script no puede estar vacía.")
    try:
        explanation = await ai_service.explain_script(request.script_url)
        return {"explanation": explanation}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error no controlado en explain_script: {e}", exc_info=True)
        return {"status": "error", "message": "Error interno al analizar el script."}


# NUEVO: Protección del Endpoint de Administración mediante Header Authentication
@router.post("/api/admin/clear-cache", tags=["Admin"])
async def clear_cache(x_admin_key: str = Header(..., description="Clave de acceso de administrador")):
    """Limpia manualmente toda la base de datos de caché. Requiere autenticación."""
    admin_secret = os.getenv("ADMIN_SECRET_KEY")
    
    # Validamos que exista una clave configurada en el servidor y que coincida con la enviada
    if not admin_secret or x_admin_key != admin_secret:
        logger.warning("Intento de acceso denegado a /api/admin/clear-cache.")
        raise HTTPException(status_code=403, detail="Acceso denegado: Credenciales no válidas.")

    success = cache_service.clear_all()
    if success:
        return {"status": "success", "message": "Caché eliminada correctamente."}
    else:
        raise HTTPException(status_code=500, detail="No se pudo eliminar la caché.")