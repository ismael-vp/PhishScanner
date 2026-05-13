import socket
import logging
import asyncio
import httpx
import re
from urllib.parse import urlparse, quote

from models.osint_models import OSINTResponse, URLStructureResult
from services.scanners.geo_scanner import GeoScanner
from services.scanners.whois_scanner import WhoisScanner
from services.scanners.ssl_scanner import SSLScanner
from services.scanners.tech_scanner import TechScanner
from services.scanners.heuristic_scanner import HeuristicScanner
from services.scanners.form_scanner import FormScanner

logger = logging.getLogger(__name__)

class OSINTService:
    
    @staticmethod
    def _extract_title_fast(html_content: str) -> str:
        """Extrae el título usando Regex."""
        if not html_content:
            return ""
        match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip().lower()
        return ""

    @staticmethod
    async def get_osint_data(url: str) -> OSINTResponse:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc if parsed_url.netloc else parsed_url.path.split('/')[0]
        
        if not hostname:
            return OSINTResponse()
            
        osint_data = OSINTResponse()

        try:
            ip_address = await asyncio.to_thread(socket.gethostbyname, hostname)
        except Exception as e:
            logger.warning(f"Fallo de resolución DNS para {hostname}: {e}")
            ip_address = None

        try:
            results = await asyncio.wait_for(
                asyncio.gather(
                    GeoScanner.get_geolocation_and_reputation(ip_address),
                    WhoisScanner.get_whois(hostname),
                    SSLScanner.get_ssl_info(hostname),
                    TechScanner.get_tech_and_scripts(url, hostname),
                    return_exceptions=True
                ),
                timeout=12.0
            )
            geo_data, whois_data, ssl_data, tech_data = results
        except asyncio.TimeoutError:
            logger.error(f"Timeout global de motores OSINT para {hostname}.")
            geo_data = whois_data = ssl_data = tech_data = None
        except Exception as e:
            logger.error(f"Error en orquestación concurrente: {e}")
            geo_data = whois_data = ssl_data = tech_data = None

        if geo_data and not isinstance(geo_data, Exception):
            osint_data.geolocation = geo_data.geolocation
            osint_data.abuse_confidence_score = geo_data.abuse_confidence_score
            osint_data.total_reports = geo_data.total_reports
            
        if whois_data and not isinstance(whois_data, Exception):
            osint_data.whois = whois_data
            
        if ssl_data and not isinstance(ssl_data, Exception):
            osint_data.ssl = ssl_data
            
        if tech_data and not isinstance(tech_data, Exception):
            osint_data.tech_data = tech_data

        try:
            heuristic_orchestrator = HeuristicScanner()
            heuristic_result = await heuristic_orchestrator.run_full_heuristics(url, hostname)
            osint_data.heuristic_result = heuristic_result
            
            if heuristic_result.url_anatomy:
                osint_data.url_anatomy = heuristic_result.url_anatomy
            
            if heuristic_result.typosquatting:
                osint_data.typosquatting = heuristic_result.typosquatting
                
            if osint_data.tech_data and osint_data.tech_data.html_content:
                form_data = await FormScanner.analyze_forms(
                    osint_data.tech_data.html_content, 
                    hostname, 
                    heuristic_result.url_anatomy
                )
                if form_data:
                    osint_data.form_analysis = form_data
        except Exception as e:
            logger.error(f"Error en Heuristic Facade: {e}")

        safe_url = url if url.startswith(('http://', 'https://')) else f"https://{url}"
        encoded_url = quote(safe_url)
        ua_desktop = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
        ua_mobile = "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1"
        
        osint_data.screenshot_desktop = f"https://api.microlink.io/?url={encoded_url}&screenshot=true&embed=screenshot.url&viewport.width=1920&viewport.height=1080&userAgent={quote(ua_desktop)}"
        
        try:
            microlink_url = f"https://api.microlink.io/?url={encoded_url}&screenshot=true&device=iPhone+13&userAgent={quote(ua_mobile)}"
            
            async with httpx.AsyncClient(timeout=25.0) as client:
                response = await client.get(microlink_url)
                if response.status_code == 200:
                    api_data = response.json().get("data", {})
                    shot_url = api_data.get("screenshot", {}).get("url")
                    if shot_url:
                        osint_data.screenshot_mobile = shot_url
                    
                    real_title = api_data.get("title", "").strip().lower()
                    if real_title and osint_data.tech_data and osint_data.tech_data.html_content:
                        bot_title = OSINTService._extract_title_fast(osint_data.tech_data.html_content)
                        if bot_title and bot_title != real_title:
                            osint_data.cloaking_detected = True
                else:
                    logger.warning(f"Microlink falló con status {response.status_code} para {url}")
        except Exception as e:
            logger.warning(f"Error en Microlink (Mobile render) para {url}: {e}")

        if not osint_data.screenshot_mobile:
            osint_data.screenshot_mobile = f"https://api.microlink.io/?url={encoded_url}&screenshot=true&embed=screenshot.url&device=iPhone+13"

        if osint_data.tech_data:
            osint_data.tech_data.html_content = "" 
        
        return osint_data