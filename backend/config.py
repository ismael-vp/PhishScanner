from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """
    Configuración centralizada y validada.
    FastAPI fallará en el arranque (Crash Early) si falta alguna clave secreta obligatoria.
    """
    # Entorno
    ENVIRONMENT: str = "development"
    
    # CORS (El frontend real)
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000", 
        "https://phishscanner-iu6g.onrender.com"
    ]

    # Secretos Obligatorios
    ADMIN_SECRET_KEY: str
    OPENAI_API_KEY: str
    VT_API_KEY: str
    
    # Secretos Opcionales
    ABUSEIPDB_API_KEY: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"  # Permite tener variables extra en el .env sin fallar
    )

settings = Settings()
