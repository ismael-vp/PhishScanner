import re
from bs4 import BeautifulSoup
from models.osint_models import FormData, UrlAnatomyData

class FormScanner:
    @staticmethod
    async def analyze_forms(html_content: str, hostname: str, url_anatomy: UrlAnatomyData = None) -> FormData:
        result = FormData()

        if not html_content:
            return result

        try:
            soup = BeautifulSoup(html_content, "html.parser")
            
            # Nuevos patrones para Webhooks
            webhook_patterns = [
                r'discord\.com/api/webhooks/',
                r'api\.telegram\.org/bot',
                r'hooks\.slack\.com/services/',
                r'formspree\.io/f/'
            ]

            # 1. Búsqueda de Formularios sospechosos
            forms = soup.find_all("form")
            for form in forms:
                action = form.get("action", "").lower()
                
                # Check webhook in action (Patrones claros de Phishing Kit)
                if any(re.search(pattern, action) for pattern in webhook_patterns):
                    result.has_dangerous_form = True
                    result.reason = f"Se detectó exfiltración de datos a un destino sospechoso (Webhook): {action[:40]}..."
                    return result

                # Solo sospechamos de campos de contraseña si el destino es dudoso
                has_password = form.find("input", type="password") or form.find("input", {"name": re.compile(r"password|passwd|cc_number", re.I)})
                
                if has_password:
                    # CASO A: Envía datos por HTTP (No seguro)
                    if action.startswith("http://"):
                        result.has_dangerous_form = True
                        result.reason = "Se detectó un formulario de credenciales que envía datos por una conexión no cifrada (HTTP)."
                        return result
                    
                    # CASO B: Envía datos a un dominio externo que no es el actual
                    # (Permitimos si el action es una ruta relativa o el mismo dominio)
                    if action.startswith("http") and hostname not in action:
                        result.has_dangerous_form = True
                        result.reason = "Se detectó un formulario que envía tus claves a un servidor externo desconocido."
                        return result

            # 2. Búsqueda de endpoints de Webhook inyectados directamente en el JS/HTML
            html_lower = html_content.lower()
            for pattern in webhook_patterns:
                if re.search(pattern, html_lower):
                    result.has_dangerous_form = True
                    result.reason = "Se ha detectado un canal de filtración de datos (Webhook) oculto en el código."
                    return result

        except Exception as e:
            pass
            
        return result
