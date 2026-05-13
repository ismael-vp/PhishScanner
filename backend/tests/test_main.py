"""
Tests de integración de la app FastAPI.

NOTA: El TestClient necesita enviar Host: localhost para superar el
TrustedHostMiddleware (que en test rechaza 'testserver').
"""
import pytest
from fastapi.testclient import TestClient

from main import app

# Enviamos Host: localhost en cada petición para pasar TrustedHostMiddleware
client = TestClient(app, headers={"host": "localhost"}, raise_server_exceptions=False)


def test_health_check():
    """El endpoint /health debe responder 200 con los checks del sistema."""
    response = client.get("/health", headers={"host": "localhost"})
    assert response.status_code == 200
    body = response.json()
    # La respuesta tiene "status" y "checks"
    assert "status" in body
    assert "checks" in body


def test_analyze_url_empty_request():
    """El endpoint debe rechazar un body vacío con 422 (Pydantic validation)."""
    response = client.post(
        "/api/analyze/url",
        json={},
        headers={"host": "localhost"},
    )
    assert response.status_code == 422


def test_analyze_url_invalid_body():
    """El endpoint debe rechazar un body sin el campo 'url' con 422."""
    response = client.post(
        "/api/analyze/url",
        json={"not_a_url": "test"},
        headers={"host": "localhost"},
    )
    assert response.status_code == 422


def test_global_exception_handler():
    """El manejador global debe devolver 500 sin exponer detalles internos."""
    @app.get("/error-test-unique-12345")
    async def _error_route():
        raise RuntimeError("Error secreto de base de datos")

    response = client.get(
        "/error-test-unique-12345",
        headers={"host": "localhost"},
    )
    assert response.status_code == 500
    body = response.json()
    # No debe filtrar el mensaje interno
    assert "Error secreto" not in str(body)
