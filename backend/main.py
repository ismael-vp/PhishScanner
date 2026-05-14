import logging
import os
import sys
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

def _validate_critical_env_vars():
    """Valida variables de entorno críticas al arranque."""
    critical_vars: dict[str, str] = {}  # añadir aquí vars críticas si se necesitan en el futuro
    is_prod = os.getenv("ENVIRONMENT") == "production"

    for var, purpose in critical_vars.items():
        if not os.getenv(var, "").strip():
            msg = f"❌ FALTAN VARIABLES CRÍTICAS: {var} ({purpose})"
            if is_prod:
                logger.error(msg)
                sys.exit(1)
            else:
                logger.warning(f"{msg}. Continuando en modo desarrollo.")

_validate_critical_env_vars()

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
    docs_url="/docs" if os.getenv("ENVIRONMENT") == "development" else None,
    redoc_url="/redoc" if os.getenv("ENVIRONMENT") == "development" else None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- Middleware & Security ---
allowed_hosts = ["localhost", "127.0.0.1", "*.onrender.com", "*.vercel.app"]
env_hosts = os.getenv("ALLOWED_HOSTS", "").strip()
if env_hosts:
    allowed_hosts.extend(env_hosts.split(","))
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

origins = ["http://localhost:3000", "http://127.0.0.1:3000"]
env_origins = os.getenv("ALLOWED_ORIGINS", "").strip()
if env_origins:
    origins.extend([o.strip() for o in env_origins.split(",") if o.strip()])

if "*" in origins:
    origins.remove("*")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-Admin-Key", "X-Requested-With"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining"],
    max_age=600,
)

# Middleware que abre /health a cualquier origen (endpoint público de solo lectura).
# Se añade DESPUÉS de CORSMiddleware para ejecutarse ANTES en la cadena de
# middleware de Starlette (último en añadirse = primero en ejecutarse).
@app.middleware("http")
async def public_health_cors(request: Request, call_next):
    """Permite CORS irrestricto para el endpoint /health."""
    if request.url.path == "/health":
        # Responder directamente al preflight OPTIONS sin llegar al router
        if request.method == "OPTIONS":
            from starlette.responses import Response as StarletteResponse
            return StarletteResponse(
                status_code=204,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Max-Age": "600",
                },
            )
        response = await call_next(request)
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response
    return await call_next(request)

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if os.getenv("ENVIRONMENT") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'none'; object-src 'none'; frame-ancestors 'none';"
    response.headers["X-Powered-By"] = "PhishingScanner"
    return response

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_id = f"ERR-{os.urandom(4).hex().upper()}"
    logger.error(f"[{error_id}] ERROR CRÍTICO en {request.url.path}: {type(exc).__name__}: {exc!s}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Error interno del servidor.", "error_id": error_id},
    )

@app.get("/health", tags=["Sistema"])
@limiter.limit("10/minute")
async def health_check(request: Request):
    checks = {}
    try:
        from utils.cache_service import CacheService
        CacheService()
        checks["sqlite"] = "ok"
    except Exception as exc:
        checks["sqlite"] = f"error: {type(exc).__name__}"

    try:
        from utils.openai_client import get_openai_client
        checks["ai_client"] = "ok" if get_openai_client() else "not_configured"
    except Exception as exc:
        checks["ai_client"] = f"error: {type(exc).__name__}"

    all_healthy = all(v == "ok" or v == "not_configured" for v in checks.values())
    return JSONResponse(
        status_code=status.HTTP_200_OK if all_healthy else status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "healthy" if all_healthy else "unhealthy", "checks": checks},
    )

from api.routes import router as analyze_router  # noqa: E402 — import after app init is intentional

app.include_router(analyze_router, prefix="/api")
