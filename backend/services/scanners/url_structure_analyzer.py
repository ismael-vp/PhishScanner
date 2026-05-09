import re
import math
from urllib.parse import urlparse
from collections import Counter
import difflib
from typing import List, Dict, Any, Optional
from services.utils import TARGET_BRANDS, ABUSED_FREE_HOSTING

class URLStructureAnalyzer:
    """
    Analizador avanzado de estructura de URLs diseñado para detectar patrones
    de phishing, typosquatting, abuso de hosting y suplantación de identidad.
    """
    
    # Listas ahora importadas desde utils.py para centralización
    ABUSED_FREE_HOSTING = ABUSED_FREE_HOSTING
    TARGET_BRANDS = TARGET_BRANDS

    
    SUSPICIOUS_KEYWORDS = [
        'login', 'verify', 'secure', 'account', 'update', 'auth', 
        'signin', 'billing', 'confirm', 'support', 'wallet', 'recovery',
        'clone' # Añadido a la lista principal para mejor detección de distancia
    ]

    @staticmethod
    def calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _is_levenshtein_similar(word: str, target_list: List[str], threshold: float = 0.8) -> Optional[str]:
        """Detecta patrones de typosquatting (ej: xlone vs clone, amozon vs amazon)."""
        if len(word) < 4: return None # Ignorar palabras muy cortas para evitar falsos positivos
        
        for target in target_list:
            ratio = difflib.SequenceMatcher(None, word.lower(), target.lower()).ratio()
            if ratio >= threshold:
                return target
        return None

    def analyze(self, url: str) -> Dict[str, Any]:
        # SANITIZACIÓN CRÍTICA: Prevenir fallos de urlparse por falta de esquema
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed = urlparse(url)
        hostname = parsed.netloc.lower()
        path = parsed.path.lower()
        
        flags = []
        risk_score = 0
        
        # 1. Detección de Hosting Gratuito Abusado
        is_free_hosting = False
        for domain in self.ABUSED_FREE_HOSTING:
            if hostname.endswith(domain):
                flags.append("ABUSED_FREE_HOSTING")
                risk_score += 25
                is_free_hosting = True
                break
        
        # 2. Detección de Suplantación de Marca (Brand Impersonation)
        for brand in self.TARGET_BRANDS:
            in_hostname = brand in hostname
            in_path = brand in path
            
            # Ajuste de falsos positivos (ej: googleapis pertenece a google)
            is_official = (
                hostname == f"{brand}.com" or 
                hostname.endswith(f".{brand}.com") or
                (brand == 'google' and 'googleapis.com' in hostname)
            )
            
            if (in_hostname or in_path) and not is_official:
                location = "HOSTNAME" if in_hostname else "PATH"
                flags.append(f"BRAND_IMPERSONATION_IN_{location} ({brand.capitalize()})")
                risk_score += 45
                break

        # 3. Análisis de Entropía y DGA (Domain Generation Algorithm)
        parts = hostname.split('.')
        # Asegurar que hay al menos un subdominio válido
        if len(parts) > 2 and not is_free_hosting:
             subdomain = ".".join(parts[:-2])
        elif is_free_hosting and len(parts) > 2:
             # Si es github.io (2 partes), el subdominio es la cuenta (ej: ayush68886888)
             subdomain = parts[0]
        else:
             subdomain = ""

        if subdomain:
            entropy = self.calculate_entropy(subdomain)
            has_consecutive_numbers = re.search(r'\d{4,}', subdomain) is not None
            
            if entropy > 3.8 or has_consecutive_numbers:
                flags.append("HIGH_ENTROPY_SUBDOMAIN")
                risk_score += 15
        
        # 4. Typosquatting y Palabras Clave de Riesgo (en Path y Subdominio)
        combined_text = f"{subdomain} {path}"
        words = re.split(r'[^a-zA-Z0-9]', combined_text)
        
        found_keywords = set()
        for word in words:
            if not word: continue
            
            if word in self.SUSPICIOUS_KEYWORDS:
                found_keywords.add(word)
            else:
                similar = self._is_levenshtein_similar(word, self.SUSPICIOUS_KEYWORDS, 0.75)
                if similar and word != similar:
                    found_keywords.add(f"{word} (similar a {similar})")
        
        if found_keywords:
            for kw in found_keywords:
                flags.append(f"SUSPICIOUS_KEYWORD ({kw})")
            risk_score += 15 * len(found_keywords)

        # 5. Evaluación Final y Normalización
        risk_score = min(risk_score, 100)
        
        level = "LOW"
        if risk_score >= 70:
            level = "CRITICAL"
        elif risk_score >= 40:
            level = "MEDIUM"
            
        return {
            "risk_score": risk_score,
            "level": level,
            "flags": flags
        }