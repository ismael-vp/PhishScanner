import httpx
import logging
import os
from models.osint_models import GeoScannerResult, GeolocationData

logger = logging.getLogger(__name__)

class GeoScanner:
    @staticmethod
    async def get_geolocation_and_reputation(ip_address: str) -> GeoScannerResult:
        result = GeoScannerResult()
        
        if not ip_address:
            return result

        # 1. Geolocation via ip-api.com
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"http://ip-api.com/json/{ip_address}", timeout=5.0)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        result.geolocation = GeolocationData(
                            ip=ip_address,
                            lat=data.get("lat", 0.0),
                            lon=data.get("lon", 0.0),
                            country=data.get("country", ""),
                            countryCode=data.get("countryCode", ""),
                            city=data.get("city", ""),
                            isp=data.get("isp", "")
                        )
        except Exception as e:
            logger.warning(f"Error en OSINT Geolocation para {ip_address}: {e}")

        # 1.5. AbuseIPDB
        abuse_api_key = os.getenv("ABUSEIPDB_API_KEY")
        if abuse_api_key:
            try:
                async with httpx.AsyncClient() as client:
                    headers = {
                        "Key": abuse_api_key,
                        "Accept": "application/json"
                    }
                    response = await client.get(
                        "https://api.abuseipdb.com/api/v2/check", 
                        params={"ipAddress": ip_address}, 
                        headers=headers, 
                        timeout=5.0
                    )
                    if response.status_code == 200:
                        data = response.json().get("data", {})
                        result.abuseConfidenceScore = data.get("abuseConfidenceScore")
                        result.totalReports = data.get("totalReports")
            except Exception as e:
                logger.warning(f"Error en AbuseIPDB para {ip_address}: {e}")

        return result
