import whois
import asyncio
import logging
from datetime import datetime
from models.osint_models import WhoisData

logger = logging.getLogger(__name__)

class WhoisScanner:
    @staticmethod
    async def get_whois(hostname: str) -> WhoisData | None:
        if not hostname:
            return None
            
        try:
            domain_info = await asyncio.to_thread(whois.whois, hostname)
            
            def parse_date(d):
                if isinstance(d, list):
                    d = d[0]
                if isinstance(d, datetime):
                    return d.isoformat()
                return str(d) if d else None
                
            return WhoisData(
                registrar=domain_info.registrar,
                creation_date=parse_date(domain_info.creation_date),
                expiration_date=parse_date(domain_info.expiration_date)
            )
        except Exception as e:
            logger.warning(f"Error en OSINT WHOIS para {hostname}: {e}")
            return None
