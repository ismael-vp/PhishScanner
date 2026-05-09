import httpx
import re
import logging
import yaml
import os
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from models.osint_models import TechData, PrivacyData

logger = logging.getLogger(__name__)




class TechScanner:

    @staticmethod
    def _cpu_bound_analysis(html_content: str, response_headers: dict, cookies_dict: dict, hostname: str):
        """
        Esta función contiene todo el código que estresa la CPU.
        Al separarlo aquí, podemos enviarlo a un hilo secundario y evitar que FastAPI se congele.
        """
        # --- 1. Parsing del DOM ---
        soup = BeautifulSoup(html_content, "html.parser")
        scripts = soup.find_all("script", src=True)

        external_scripts = []
        for script in scripts:
            src = script["src"]
            parsed_src = urlparse(src)

            if parsed_src.netloc and parsed_src.netloc != hostname:
                external_scripts.append(src)
            elif src.startswith("//"):
                parsed_protocol_relative = urlparse("http:" + src)
                if parsed_protocol_relative.netloc and parsed_protocol_relative.netloc != hostname:
                    external_scripts.append("https:" + src)

        external_scripts = list(set(external_scripts))

        # --- 2. Detección de Tecnologías (ELIMINADO: Demasiado pesado e innecesario) ---
        technologies = []


        # --- 3. Privacy Nutrition Label (Detección de Rastreadores) ---
        privacy = PrivacyData()
        tracking_used = set()
        data_linked = set()
        device_access = set()
        trackers_count = 0

        tracker_domains = [
            "doubleclick.net", "google-analytics.com", "googletagmanager.com",
            "facebook.net", "facebook.com/tr/", "adnxs.com", "adsnative.com",
            "hotjar.com", "scorecardresearch.com", "bing.com/pixel", "taboola.com",
            "outbrain.com", "rubiconproject.com", "pubmatic.com", "criteo.com",
            "tiktok.com", "ads-twitter.com", "snap.com", "pinterest.com",
            "amazon-adsystem.com", "redditstatic.com/ads", "yandex.ru/metrika",
            "clarity.ms", "mouseflow.com", "segment.com", "mixpanel.com"
        ]

        for script_url in external_scripts:
            if any(domain in script_url.lower() for domain in tracker_domains):
                trackers_count += 1
                tracking_used.add("Cookies de Terceros")
                tracking_used.add("Rastreo Publicitario")

        if trackers_count > 0:
            tracking_used.add("Análisis de Comportamiento")

        if "localstorage" in html_lower or "window.localstorage" in html_lower:
            tracking_used.add("Almacenamiento Local (LocalStorage)")
        if "sessionstorage" in html_lower or "window.sessionstorage" in html_lower:
            tracking_used.add("Almacenamiento de Sesión (SessionStorage)")
        if "indexeddb" in html_lower or "window.indexeddb" in html_lower:
            tracking_used.add("Base de Datos Local (IndexedDB)")

        if re.search(r'type=["\']email["\']', html_lower) or re.search(r'name=["\']email["\']', html_lower):
            data_linked.add("Correo Electrónico")
        if re.search(r'type=["\']tel["\']', html_lower) or re.search(r'name=["\'](phone|tel)["\']', html_lower):
            data_linked.add("Número de Teléfono")
        if "geolocation" in html_lower or "navigator.geolocation" in html_lower:
            data_linked.add("Ubicación Geográfica")

        if "accounts.google.com/gsi/client" in html_lower or "gapi.auth2" in html_lower:
            data_linked.add("Perfil de Google")
        if "connect.facebook.net" in html_lower and "xfbml" in html_lower:
            data_linked.add("Perfil de Facebook")
        if "appleid.apple.com/appleauth" in html_lower:
            data_linked.add("Perfil de Apple")

        if "js.stripe.com" in html_lower or "elements" in html_lower:
            data_linked.add("Datos Financieros (Stripe)")
        if "paypalobjects.com" in html_lower or "paypal.com/sdk" in html_lower:
            data_linked.add("Datos Financieros (PayPal)")

        if "getusermedia" in html_lower or "enumeratedevices" in html_lower:
            device_access.add("Cámara y Micrófono")
        if "requestpermission" in html_lower and "notification" in html_lower:
            device_access.add("Notificaciones Push")
        if "navigator.clipboard.readtext" in html_lower or "navigator.clipboard.read" in html_lower:
            device_access.add("Portapapeles (Copiar/Pegar)")
        if "navigator.getbattery" in html_lower:
            device_access.add("Estado de la Batería")
        if "navigator.bluetooth" in html_lower:
            device_access.add("Bluetooth")
        if "navigator.usb" in html_lower:
            device_access.add("Puertos USB")

        if "todataurl" in html_lower and "canvas" in html_lower:
            tracking_used.add("Huella Digital (Canvas Fingerprinting)")
        if "audiocontext" in html_lower or "oscillator" in html_lower:
            tracking_used.add("Huella Digital (Audio Fingerprinting)")
        if "webgl" in html_lower and ("getextension" in html_lower or "debug_renderer_info" in html_lower):
            tracking_used.add("Huella Digital Gráfica (WebGL)")
        if "rtcpeerconnection" in html_lower or "mozrtcpeerconnection" in html_lower:
            tracking_used.add("Fugas de Red (WebRTC)")

        privacy.tracking_used = sorted(list(tracking_used))
        privacy.trackers_count = trackers_count
        privacy.data_linked = sorted(list(data_linked))
        privacy.device_access = sorted(list(device_access))

        return external_scripts, technologies, privacy


    @staticmethod
    async def get_tech_and_scripts(url: str, hostname: str) -> TechData:
        result = TechData()

        html_content = ""
        response_headers: dict = {}
        cookies_dict: dict = {}

        try:
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            
            # Petición de red (I/O). Aquí `await` es correcto y cede el control limpiamente.
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(url, follow_redirects=True, timeout=10.0, headers=req_headers)

            html_content = response.text
            result.html_content = html_content 
            response_headers = dict(response.headers)
            cookies_dict = dict(response.cookies)

            redirect_chain = [str(req.url) for req in response.history]
            redirect_chain.append(str(response.url))
            result.redirect_chain = redirect_chain

        except Exception as e:
            logger.warning(f"Error al conectar por HTTP con {url}: {e}")
            return result
            
        try:
            # 🚀 LA MAGIA OCURRE AQUÍ 🚀
            # En lugar de bloquear el servidor ejecutando las expresiones regulares de forma síncrona,
            # delegamos TODO ese bloque de código de arriba a un hilo en segundo plano.
            # 🚀 LA MAGIA OCURRE AQUÍ 🚀
            # Delegamos el análisis de privacidad (que aún tiene regex) a un hilo secundario
            external_scripts, technologies, privacy = await asyncio.to_thread(
                TechScanner._cpu_bound_analysis,
                html_content,
                response_headers,
                cookies_dict,
                hostname
            )


            result.external_scripts = external_scripts
            result.technologies = technologies
            result.privacy_analysis = privacy

        except Exception as e:
            logger.error(f"Error en el análisis asíncrono (CPU-bound) para {url}: {e}")

        return result