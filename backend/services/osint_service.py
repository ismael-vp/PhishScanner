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
        """
        Extrae el título usando Regex para evitar el bloqueo de CPU de BeautifulSoup.
        """
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

        # --- 1. RESOLUCIÓN DNS (Timeout implicito de SO) ---
        try:
            ip_address = await asyncio.to_thread(socket.gethostbyname, hostname)
        except Exception as e:
            logger.warning(f"Fallo de resolución DNS para {hostname}: {e}")
            ip_address = None

        # --- 2. EJECUCIÓN CONCURRENTE CON TIMEOUT GLOBAL (SLA) ---
        try:
            # Límite de 12 segundos para los motores base
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
            logger.error(f"⌛ Timeout global de motores OSINT para {hostname}. Devolviendo resultados parciales.")
            geo_data = whois_data = ssl_data = tech_data = None
        except Exception as e:
            logger.error(f"Error en orquestación concurrente: {e}")
            geo_data = whois_data = ssl_data = tech_data = None

        # Procesamiento de resultados parciales
        if geo_data and not isinstance(geo_data, Exception):
            osint_data.geolocation = geo_data.geolocation
            osint_data.abuseConfidenceScore = geo_data.abuseConfidenceScore
            osint_data.totalReports = geo_data.totalReports
            
        if whois_data and not isinstance(whois_data, Exception):
            osint_data.whois = whois_data
            
        if ssl_data and not isinstance(ssl_data, Exception):
            osint_data.ssl = ssl_data
            
        if tech_data and not isinstance(tech_data, Exception):
            osint_data.external_scripts = tech_data.external_scripts
            osint_data.technologies = tech_data.technologies
            osint_data.redirect_chain = tech_data.redirect_chain
            osint_data.html_content = tech_data.html_content
            osint_data.privacy_analysis = tech_data.privacy_analysis
            osint_data.is_mobile_optimized = tech_data.is_mobile_optimized

        # --- 3. ORQUESTACIÓN HEURÍSTICA ---
        try:
            heuristic_orchestrator = HeuristicScanner()
            heuristic_result = await heuristic_orchestrator.run_full_heuristics(url, hostname)
            osint_data.heuristic_result = heuristic_result
            osint_data.url_structure = heuristic_result.url_anatomy
            
            if heuristic_result.typosquatting:
                osint_data.is_typosquatting = heuristic_result.typosquatting.is_typosquatting
                osint_data.target_brand = heuristic_result.typosquatting.target_brand
                
            if osint_data.html_content:
                form_data = await FormScanner.analyze_forms(
                    osint_data.html_content, 
                    hostname, 
                    heuristic_result.url_anatomy
                )
                if form_data:
                    osint_data.has_dangerous_form = form_data.has_dangerous_form
                    osint_data.reason = form_data.reason
        except Exception as e:
            logger.error(f"Error en Heuristic Facade: {e}")

        # --- 4. RENDERIZADO Y CLOAKING (Microlink) ---
        safe_url = url if url.startswith(('http://', 'https://')) else f"https://{url}"
        encoded_url = quote(safe_url)
        ua_desktop = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
        ua_mobile = "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1"
        
        osint_data.screenshot_desktop = f"https://api.microlink.io/?url={encoded_url}&screenshot=true&embed=screenshot.url&viewport.width=1920&viewport.height=1080&userAgent={quote(ua_desktop)}"
        
        try:
            js_script = "() => { return { isBursting: document.body.scrollWidth > window.innerWidth + 20 }; }"
            microlink_url = f"https://api.microlink.io/?url={encoded_url}&screenshot=true&device=iPhone+13&userAgent={quote(ua_mobile)}&function={quote(js_script)}"
            
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(microlink_url)
                if response.status_code == 200:
                    api_data = response.json().get("data", {})
                    osint_data.screenshot_mobile = api_data.get("screenshot", {}).get("url")
                    osint_data.is_mobile_optimized = not api_data.get("function", {}).get("value", {}).get("isBursting", False)
                    
                    # Detección de Cloaking
                    real_title = api_data.get("title", "").strip().lower()
                    bot_title = OSINTService._extract_title_fast(osint_data.html_content or "")
                    if bot_title and real_title and bot_title != real_title:
                        osint_data.cloaking_detected = True
        except Exception as e:
            logger.warning(f"Fallo no crítico en Microlink: {e}")
            osint_data.screenshot_mobile = f"https://api.microlink.io/?url={encoded_url}&screenshot=true&embed=screenshot.url&device=iPhone+13"

        # --- 5. OPTIMIZACIÓN DE PAYLOAD FINAL ---
        # El contenido HTML es masivo y solo se usa para análisis interno. No se envía al cliente.
        osint_data.html_content = None 
        
        return osint_data