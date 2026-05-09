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

            # 1. Búsqueda clásica de Formularios sospechosos
            forms = soup.find_all("form")
            for form in forms:
                action = form.get("action", "").lower()
                
                # Check webhook in action
                if any(re.search(pattern, action) for pattern in webhook_patterns):
                    result.has_dangerous_form = True
                    result.reason = f"Se detectó exfiltración de datos a un Webhook conocido (Phishing Kit): {action[:40]}..."
                    return result

                # Si pide contraseña y el action va a un HTTP inseguro o a un dominio raro
                if form.find("input", type="password") or form.find("input", {"name": re.compile(r"password|passwd|cc_number", re.I)}):
                    if action.startswith("http://") or (action.startswith("http") and hostname not in action):
                        result.has_dangerous_form = True
                        result.reason = "Se detectó un formulario de credenciales que envía datos a un destino externo o no seguro."
                        return result

            # 2. Búsqueda agresiva: Inputs de contraseña huérfanos (típico de ataques modernos con JS)
            orphan_passwords = soup.find_all("input", type="password")
            if orphan_passwords:
                result.has_dangerous_form = True
                result.reason = "Se ha detectado un campo de contraseña directamente en el código fuente, comúnmente usado para robar credenciales."
                return result

            # 3. Búsqueda en código JS crudo (ofuscación y webhooks)
            html_lower = html_content.lower()
            
            for pattern in webhook_patterns:
                if re.search(pattern, html_lower):
                    result.has_dangerous_form = True
                    result.reason = "Se ha detectado un endpoint de Webhook (típico de Phishing Kits) inyectado en el código fuente."
                    return result

            if 'type="password"' in html_lower or "type='password'" in html_lower:
                result.has_dangerous_form = True
                result.reason = "Se ha detectado código oculto inyectando campos de contraseña."
                return result

        except Exception as e:
            pass
            
        return result
