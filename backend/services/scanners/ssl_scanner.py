import ssl
import socket
import asyncio
import logging
from models.osint_models import SSLData

logger = logging.getLogger(__name__)

class SSLScanner:
    @staticmethod
    async def get_ssl_info(hostname: str) -> SSLData | None:
        if not hostname:
            return None
            
        def _get_cert():
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert()

        try:
            cert = await asyncio.to_thread(_get_cert)
            
            if cert:
                # Extract issuer
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer_dict.get('organizationName') or issuer_dict.get('commonName')
                
                # Date formatting: cert returns strings like "May 25 12:00:00 2024 GMT"
                not_after = cert.get('notAfter')
                
                return SSLData(
                    issuer=issuer_name,
                    expiration_date=not_after
                )
        except (ssl.SSLError, socket.gaierror, socket.timeout, ConnectionRefusedError):
            # Errores comunes de red o de certificados mal configurados (esperable en sitios sospechosos)
            pass
        except Exception as e:
            logger.debug(f"Error inesperado en OSINT SSL para {hostname}: {e}")
            
        return None
