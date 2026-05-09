import hashlib
import os
import httpx
import base64
import asyncio
from fastapi import HTTPException

# Aseguramos que la key pueda ser cargada
VT_API_URL = "https://www.virustotal.com/api/v3"

def calculate_sha256(file_bytes: bytes) -> str:
    """Calcula el hash SHA-256 de un archivo (cargado en memoria)."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_bytes)
    return sha256_hash.hexdigest()

class VirusTotalService:
    def __init__(self):
        # Obtenemos la llave dinámicamente al instanciar el servicio
        self.api_key = os.getenv("VT_API_KEY")
        self.headers = {
            "x-apikey": self.api_key
        }

    async def _make_request(self, client: httpx.AsyncClient, method: str, endpoint: str, **kwargs) -> dict:
        """Método interno que recibe el cliente HTTP inyectado para hacer la petición."""
        if not self.api_key:
            raise HTTPException(status_code=500, detail="La API Key de VirusTotal no está configurada en las variables de entorno.")
            
        response = await client.request(method, f"{VT_API_URL}{endpoint}", headers=self.headers, **kwargs)
        
        # Manejo específico de errores solicitados
        if response.status_code == 404:
            raise HTTPException(status_code=404, detail="El análisis para este recurso no fue encontrado en VirusTotal.")
        elif response.status_code == 429:
            raise HTTPException(status_code=429, detail="Se ha excedido el límite de cuota de la API de VirusTotal. Por favor, intenta de nuevo más tarde.")
        
        # Si hay otro tipo de error HTTP (500, 401, etc.), lo levantamos
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=exc.response.status_code, detail=f"Error al comunicarse con VirusTotal: {exc.response.text}")
        
        return response.json()

    def _extract_useful_stats(self, data: dict, is_analysis: bool = False) -> dict:
        """
        Extrae estadísticas de detección y resultados detallados por motor.
        """
        try:
            attributes = data["data"]["attributes"]
            stats_key = "stats" if is_analysis else "last_analysis_stats"
            results_key = "results" if is_analysis else "last_analysis_results"
            
            stats = attributes[stats_key]
            results = attributes.get(results_key, {})
            
            # Formatear resultados detallados para el frontend
            detailed_results = []
            for engine_name, result in results.items():
                detailed_results.append({
                    "name": engine_name,
                    "status": result.get("category", "unknown"),
                    "result": result.get("result", None),
                    "method": result.get("method", "blacklist")
                })

            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "timeout": stats.get("timeout", 0),
                "full_results": detailed_results
            }
        except KeyError:
            raise HTTPException(status_code=500, detail="No se pudieron extraer las estadísticas detalladas del reporte de VirusTotal.")

    async def _poll_analysis(self, client: httpx.AsyncClient, analysis_id: str) -> dict:
        """
        Realiza un polling al endpoint de análisis hasta que se complete el escaneo.
        """
        endpoint = f"/analyses/{analysis_id}"
        max_attempts = 15 # 15 * 5s = 75s máximo
        
        for _ in range(max_attempts):
            data = await self._make_request(client, "GET", endpoint)
            status = data.get("data", {}).get("attributes", {}).get("status", "queued")
            
            if status == "completed":
                return self._extract_useful_stats(data, is_analysis=True)
                
            await asyncio.sleep(5)
            
        raise HTTPException(status_code=408, detail="El análisis de VirusTotal tomó demasiado tiempo y excedió el límite de espera.")

    async def get_file_report(self, file_hash: str, file_bytes: bytes) -> dict:
        """
        Consulta el reporte de un archivo por su hash (idealmente SHA-256).
        Si no existe (404), sube el archivo (si < 32MB) y hace polling.
        """
        # BLOQUE ASÍNCRONO DE CONTEXTO: Garantiza que el cliente se cierre al terminar
        async with httpx.AsyncClient(timeout=30.0) as client:
            endpoint = f"/files/{file_hash}"
            try:
                data = await self._make_request(client, "GET", endpoint)
                return self._extract_useful_stats(data)
            except HTTPException as e:
                if e.status_code == 404:
                    # El archivo no existe, lo subimos si es menor de 32MB
                    if len(file_bytes) > 32 * 1024 * 1024:
                        raise HTTPException(status_code=413, detail="El archivo excede el límite de 32MB para ser subido a VirusTotal.")
                    
                    # Para POST de archivos usamos form-data
                    files = {"file": ("upload", file_bytes)}
                    response = await client.post(f"{VT_API_URL}/files", headers=self.headers, files=files)
                    
                    if response.status_code == 429:
                        raise HTTPException(status_code=429, detail="Se ha excedido el límite de cuota de la API de VirusTotal.")
                    response.raise_for_status()
                    
                    analysis_data = response.json()
                    analysis_id = analysis_data["data"]["id"]
                        
                    return await self._poll_analysis(client, analysis_id)
                raise e

    async def get_url_report(self, url: str) -> dict:
        """
        Consulta el reporte de una URL. 
        Si no existe (404), la envía y hace polling.
        """
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"/urls/{url_id}"
        
        # BLOQUE ASÍNCRONO DE CONTEXTO: Garantiza el cierre del socket
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                data = await self._make_request(client, "GET", endpoint)
                return self._extract_useful_stats(data)
            except HTTPException as e:
                if e.status_code == 404:
                    # La URL no existe, la enviamos para escaneo
                    form_data = {"url": url}
                    headers = self.headers.copy()
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                    
                    response = await client.post(f"{VT_API_URL}/urls", headers=headers, data=form_data)
                    
                    if response.status_code == 429:
                        raise HTTPException(status_code=429, detail="Se ha excedido el límite de cuota de la API de VirusTotal.")
                    response.raise_for_status()
                    
                    analysis_data = response.json()
                    analysis_id = analysis_data["data"]["id"]
                        
                    return await self._poll_analysis(client, analysis_id)
                raise e