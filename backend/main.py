from fastapi import FastAPI, Request, status, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import logging
import os
import traceback

# Configuración de logging para producción
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Cargar variables de entorno
load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gestor del ciclo de vida de la aplicación.
    """
    logger.info("🚀 Iniciando motor de PhishingScanner API...")
    
    # Verificación de seguridad al arrancar (Fail-Fast pattern)
    if not os.getenv("VT_API_KEY"):
        logger.warning("⚠️ ALERTA: VT_API_KEY no encontrada. El motor de VirusTotal fallará.")
    if not os.getenv("OPENAI_API_KEY"):
        logger.warning("⚠️ ALERTA: OPENAI_API_KEY no encontrada. La heurística IA fallará.")
        
    yield  # El servidor está corriendo
    
    logger.info("🛑 Apagando PhishingScanner API de forma segura. Liberando recursos...")

# Inicializar aplicación FastAPI
app = FastAPI(
    title="PhishingScanner API",
    description="Motor de análisis avanzado para Phishing, Typosquatting y Malware",
    version="1.0.0",
    lifespan=lifespan
)

# --- HARDENING DE CORS ---
# Definimos orígenes permitidos (Whitelist)
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# Permitir orígenes adicionales por variable de entorno (para producción)
env_origins = os.getenv("ALLOWED_ORIGINS")
if env_origins:
    origins.extend(env_origins.split(","))

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- ESCUDO CONTRA FUGAS DE DATOS (Exception Handlers) ---

# NUEVO: Interceptor de errores HTTP
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """
    Intercepta errores HTTP controlados. 
    Permite mostrar detalles al usuario para errores de cliente (4xx), 
    pero enmascara los errores de servidor (5xx) para evitar Information Disclosure.
    """
    if exc.status_code >= 500:
        # Logueamos el error real internamente para depuración
        logger.error(f"⚠️ HTTP ERROR {exc.status_code} en {request.url.path}: {exc.detail}")
        
        # Devolvemos un mensaje genérico al frontend
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "detail": "Error interno en los servicios de escaneo. El incidente ha sido registrado.",
                "status": "error"
            }
        )
    
    # Para errores 4xx (ej. URL inválida, archivo muy grande), devolvemos el detalle
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "status": "error"
        }
    )

# MANTENIDO: Interceptor de crasheos generales
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Captura cualquier crasheo imprevisto (no HTTP) para evitar que el servidor 
    filtre información técnica sensible (rutas locales, versiones, etc.) al cliente.
    """
    logger.error(f"⚠️ ERROR CRÍTICO NO CONTROLADO en {request.url.path}: {str(exc)}")
    logger.error(traceback.format_exc())
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Error crítico interno del servidor. El incidente ha sido registrado para revisión técnica.",
            "status": "error"
        }
    )

@app.get("/health", tags=["Sistema"])
async def health_check():
    return {
        "status": "API operativa", 
        "engine": "PhishingScanner Core v1.0",
        "environment": os.getenv("ENVIRONMENT", "development")
    }

# Registrar router de análisis
from api.routes import router as analyze_router
app.include_router(analyze_router)