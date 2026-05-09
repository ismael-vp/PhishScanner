import logging
from typing import Optional
from models.osint_models import HeuristicResult, URLStructureResult, TyposquattingData
from services.scanners.url_structure_analyzer import URLStructureAnalyzer
from services.scanners.typosquatting_scanner import TyposquattingScanner

logger = logging.getLogger(__name__)

class HeuristicScanner:
    """
    Facade que orquestra el análisis heurístico avanzado, combinando la estructura
    de la URL y la detección de typosquatting para generar un veredicto unificado.
    """
    
    def __init__(self):
        self.url_analyzer = URLStructureAnalyzer()
        self.typos_scanner = TyposquattingScanner()

    async def run_full_heuristics(self, url: str, hostname: str) -> HeuristicResult:
        """
        Orquestador principal que ejecuta todos los escáneres heurísticos y 
        consolida el riesgo en un único modelo.
        """
        final_result = HeuristicResult()
        
        # 1. Ejecutar análisis de estructura de URL
        try:
            struct_data = self.url_analyzer.analyze(url)
            final_result.risk_score = struct_data.get("risk_score", 0)
            final_result.level = struct_data.get("level", "LOW")
            final_result.flags = struct_data.get("flags", [])
            final_result.url_anatomy = URLStructureResult(**struct_data)
        except Exception as e:
            logger.error(f"Error en URLStructureAnalyzer: {e}", exc_info=True)
            
        # 2. Ejecutar escáner de Typosquatting
        try:
            typos_data = await self.typos_scanner.check_typosquatting(hostname)
            if typos_data and typos_data.is_typosquatting:
                final_result.typosquatting = typos_data
                
                # Consolidación del Riesgo: Penalización severa por Typosquatting
                if "TYPOSQUATTING_DETECTED" not in final_result.flags:
                    final_result.flags.append(f"TYPOSQUATTING_DETECTED ({typos_data.target_brand})")
                
                final_result.risk_score += 50
                
                # Recalcular nivel basado en el nuevo score (Max 100)
                final_result.risk_score = min(final_result.risk_score, 100)
                if final_result.risk_score >= 70:
                    final_result.level = "CRITICAL"
                elif final_result.risk_score >= 40:
                    final_result.level = "MEDIUM"
                    
        except Exception as e:
            logger.error(f"Error en TyposquattingScanner: {e}", exc_info=True)
            
        return final_result
