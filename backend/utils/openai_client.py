import logging
import os

from openai import AsyncOpenAI

logger = logging.getLogger(__name__)

def get_openai_client() -> AsyncOpenAI | None:
    """Inicializa y retorna un cliente AsyncOpenAI configurado."""
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        logger.error("OPENAI_API_KEY no configurada.")
        return None

    # Si no se configura OPENAI_BASE_URL, se usa el proxy ChatAnywhere por defecto
    # ya que la clave sk-DK54V... es una clave de ChatAnywhere, no de OpenAI oficial.
    _default_base = "https://api.chatanywhere.tech/v1"
    base_url = os.getenv("OPENAI_BASE_URL", "").strip() or _default_base
    provider_name = "ChatAnywhere" if "chatanywhere" in base_url.lower() else "OpenAI"

    try:
        client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=30.0,
            max_retries=0,
        )
        logger.info(f"Cliente de IA inicializado: {provider_name}")
        return client
    except Exception as exc:
        logger.error(f"Error inicializando cliente de IA: {exc}")
        return None