import logging
import os
import sys
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

load_dotenv()
from config import settings  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Iniciando PhishingScanner API v1.0...")
    try:
        from utils.cache_service import CacheService
        CacheService()
        logger.info("✅ SQLite caché inicializado")
    except Exception as exc:
        logger.error(f"❌ Error inicializando caché: {exc}")
        sys.exit(1)
    yield
    logger.info("🛑 Apagando PhishingScanner API...")
    try:
        from services.geo_scanner import GeoScanner

        from services.virustotal_service import VirusTotalService
        await VirusTotalService.close_client()
        await GeoScanner.close_client()
    except Exception as exc:
        logger.warning(f"Error cerrando clientes: {exc}")

app = FastAPI(
    title="PhishingScanner API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS restrictivo — protege cuotas de API permitiendo solo nuestros frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_id = f"ERR-{os.urandom(4).hex().upper()}"
    logger.error(f"[{error_id}] ERROR CRÍTICO en {request.url.path}: {type(exc).__name__}: {exc!s}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Error interno del servidor.", "error_id": error_id},
    )

@app.get("/api/app-info", tags=["Sistema"])
async def system_info():
    """Información básica del sistema — usada por el frontend para mostrar el estado."""
    all_ok = True
    try:
        from utils.cache_service import CacheService
        CacheService()
    except Exception:
        all_ok = False

    return JSONResponse(
        status_code=status.HTTP_200_OK if all_ok else status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "status": "API operativa",
            "engine": "PhishingScanner Core v1.0",
            "environment": settings.ENVIRONMENT,
        },
    )

from api.routes import router as analyze_router  # noqa: E402 — import after app init is intentional

app.include_router(analyze_router, prefix="/api")
