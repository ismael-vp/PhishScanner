import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

def test_health_check():
    """Prueba que el endpoint de salud responda correctamente."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "API operativa"
    assert "engine" in response.json()

def test_analyze_url_empty_request():
    """Prueba que el análisis de URL falle si no se envía nada."""
    response = client.post("/api/analyze/url", json={})
    assert response.status_code == 422  # Error de validación de Pydantic

def test_analyze_url_invalid_body():
    """Prueba que el análisis de URL falle si el body es incorrecto."""
    response = client.post("/api/analyze/url", json={"not_a_url": "test"})
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_global_exception_handler():
    """Verifica que el manejador global de excepciones oculte detalles técnicos."""
    # Forzamos un error accediendo a una ruta inexistente que lance error no controlado
    # O simplemente simulamos un error en una ruta
    @app.get("/error-test")
    async def error_route():
        raise Exception("Error secreto de base de datos")

    response = client.get("/error-test")
    assert response.status_code == 500
    assert "Error interno del servidor" in response.json()["detail"]
    assert "Error secreto" not in response.json()["detail"]
