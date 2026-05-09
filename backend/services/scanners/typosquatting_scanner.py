import difflib
import logging
from typing import Optional
from models.osint_models import TyposquattingData
from services.utils import TARGET_BRANDS

logger = logging.getLogger(__name__)

# Lista ahora importada desde utils.py para centralización
TOP_BRANDS = TARGET_BRANDS

class TyposquattingScanner:

    
    @staticmethod
    def _extract_root_domain(hostname: str) -> str:
        """
        Extrae el nombre de dominio raíz ignorando subdominios y TLDs largos.
        Ej: 'login.secure.paypa1.co.uk' -> 'paypa1'
        """
        parts = hostname.split('.')
        if len(parts) <= 1:
            return hostname
            
        # TLDs compuestos comunes
        compound_tlds = ['co.uk', 'com.mx', 'com.ar', 'com.br', 'org.uk']
        
        # Juntar las dos últimas partes para ver si es un TLD compuesto
        if len(parts) >= 3:
            last_two = f"{parts[-2]}.{parts[-1]}"
            if last_two in compound_tlds:
                return parts[-3] # Devuelve el nombre antes del TLD compuesto
                
        # Si no es compuesto, el nombre está justo antes del último punto
        return parts[-2]

    @staticmethod
    async def check_typosquatting(hostname: str) -> Optional[TyposquattingData]:
        if not hostname:
            return None
            
        try:
            # 1. Extraer el dominio raíz real en lugar de hacer solo split()[0]
            main_domain = TyposquattingScanner._extract_root_domain(hostname.lower())

            for brand in TOP_BRANDS:
                # Si es exactamente la marca, NO es typosquatting (es el dominio real o un subdominio legítimo)
                if main_domain == brand:
                    continue
                    
                # Comparar similitud de la raíz
                similarity = difflib.SequenceMatcher(None, main_domain, brand).ratio()
                
                # Si la similitud es mayor al 80% (bajamos un poco para cazar más) y no es idéntico
                if similarity > 0.80:
                    return TyposquattingData(
                        is_typosquatting=True,
                        target_brand=brand.capitalize()
                    )
            
            return None

        except Exception as e:
            logger.warning(f"Error en el escáner de Typosquatting: {e}")
            return None