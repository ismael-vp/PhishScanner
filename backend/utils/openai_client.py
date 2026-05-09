import os
from openai import AsyncOpenAI

_client = None

def get_openai_client() -> AsyncOpenAI | None:
    """
    Retorna una instancia compartida de AsyncOpenAI para usar en toda la aplicación.
    Si la API Key no está configurada, retorna None.
    """
    global _client
    if _client is not None:
        return _client

    api_key = os.getenv("OPENAI_API_KEY")
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.chatanywhere.tech/v1")
    
    if api_key:
        _client = AsyncOpenAI(api_key=api_key, base_url=base_url)
    return _client
