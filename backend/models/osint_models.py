import ipaddress
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_HTML_LENGTH = 200_000
MAX_SCREENSHOT_LENGTH = 5_000_000
MAX_LIST_ITEMS = 500
MAX_STRING_LENGTH = 10_000
MAX_KEYWORD_LENGTH = 100

ISO_DATE_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$"
)

def _validate_ip(v: str) -> str:
    """Valida que el string sea una IPv4 o IPv6 válida."""
    try:
        ipaddress.ip_address(v)
    except ValueError:
        raise ValueError(f"Dirección IP inválida: {v}")
    return v

def _validate_iso_date(v: str | None) -> str | None:
    """Valida formato ISO 8601 básico."""
    if v is None:
        return v
    if not ISO_DATE_PATTERN.match(v):
        raise ValueError(f"Formato de fecha inválido (esperado ISO 8601): {v}")
    return v

def _validate_url_list(v: list[str]) -> list[str]:
    """Valida que cada elemento sea una URL http/https válida y segura."""
    for item in v:
        if not isinstance(item, str):
            raise ValueError(f"Elemento no es string: {item}")
        if len(item) > MAX_STRING_LENGTH:
            raise ValueError(f"URL demasiado larga: {item[:50]}...")
        if not item.startswith(("http://", "https://")):
            raise ValueError(f"URL debe usar http:// o https://: {item}")
    return v

class GeolocationData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str = Field(..., description="Dirección IPv4 o IPv6")
    lat: float = Field(..., ge=-90.0, le=90.0, description="Latitud")
    lon: float = Field(..., ge=-180.0, le=180.0, description="Longitud")
    country: str = Field(..., max_length=100)
    country_code: str = Field(..., max_length=5, description="Código ISO del país")
    city: str = Field(..., max_length=100)
    isp: str = Field(..., max_length=200, description="Proveedor de servicios de Internet")

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        return _validate_ip(v)

class GeoScannerResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    geolocation: GeolocationData | None = None
    abuse_confidence_score: int | None = Field(None, ge=0, le=100)
    total_reports: int | None = Field(None, ge=0)

class WhoisData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    registrar: str | None = Field(None, max_length=200)
    creation_date: str | None = Field(None, description="Fecha ISO 8601")
    expiration_date: str | None = Field(None, description="Fecha ISO 8601")

    @field_validator("creation_date", "expiration_date")
    @classmethod
    def validate_dates(cls, v: str | None) -> str | None:
        return _validate_iso_date(v)

class SSLData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer: str | None = Field(None, max_length=200)
    expiration_date: str | None = Field(None, description="Fecha ISO 8601")
    is_self_signed: bool = Field(False, description="True si el certificado parece auto-firmado")
    is_suspicious: bool = Field(False, description="True si el issuer o estado del cert es sospechoso")
    is_expired: bool = Field(False, description="True si el certificado ya caducó")
    is_expiring_soon: bool = Field(False, description="True si vence en los próximos 7 días")
    days_until_expiry: int | None = Field(None, ge=-9999, description="Días restantes hasta expiración")
    ssl_error: str | None = Field(None, max_length=500, description="Error de SSL si el handshake falló")

    @field_validator("expiration_date")
    @classmethod
    def validate_dates(cls, v: str | None) -> str | None:
        return _validate_iso_date(v)

class HostingBrandAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    brand: str = Field(..., max_length=100)
    provider: str = Field(..., max_length=100)

class UrlAnatomyData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_ip: bool = False
    suspicious_tld: bool = False
    excessive_subdomains: bool = False
    excessive_hyphens: bool = False
    phishing_keywords: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Palabras clave sospechosas detectadas en la URL"
    )
    length_warning: bool = False
    hosting_brand_alert: HostingBrandAlert | None = None
    domain_entropy: float = Field(0.0, ge=0.0, description="Entropía del dominio")
    is_dga_suspect: bool = False

    @field_validator("phishing_keywords")
    @classmethod
    def validate_keywords(cls, v: list[str]) -> list[str]:
        if len(v) > 50:
            raise ValueError("Máximo 50 palabras clave permitidas")
        for kw in v:
            if len(kw) > MAX_KEYWORD_LENGTH:
                raise ValueError(f"Keyword demasiado larga: {kw[:30]}...")
        return v

class PrivacyData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tracking_used: list[str] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    trackers_count: int = Field(0, ge=0)
    data_linked: list[str] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    device_access: list[str] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)

class TechData(BaseModel):
    """Datos técnicos y de contenido de la página web analizada."""
    model_config = ConfigDict(extra="forbid")

    technologies: list[str] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    external_scripts: list[str] = Field(
        default_factory=list,
        max_length=MAX_LIST_ITEMS,
        description="URLs de scripts externos detectados"
    )
    redirect_chain: list[str] = Field(
        default_factory=list,
        max_length=100,
        description="Cadena de redirecciones HTTP"
    )
    html_content: str = Field(
        default="",
        max_length=MAX_HTML_LENGTH,
        description="HTML crudo de la página"
    )
    privacy_analysis: PrivacyData | None = None
    is_mobile_optimized: bool = True

    @field_validator("external_scripts", "redirect_chain")
    @classmethod
    def validate_urls(cls, v: list[str]) -> list[str]:
        return _validate_url_list(v)

class TyposquattingData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_typosquatting: bool = False
    target_brand: str | None = Field(None, max_length=100)
    # Campos usados por TyposquattingScanner (necesarios para evitar ValidationError con extra=forbid)
    confidence: float | None = Field(None, ge=0.0, le=1.0, description="Confianza de la detección 0.0-1.0")
    technique: str | None = Field(None, max_length=50, description="Técnica de detección usada")

class FormData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    has_dangerous_form: bool = False
    reason: str | None = Field(None, max_length=500)

class URLStructureResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_score: int = Field(0, ge=0, le=100, description="Puntuación de riesgo 0-100")
    level: str = Field("LOW", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    flags: list[str] = Field(default_factory=list, max_length=50)

class HeuristicResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_score: int = Field(0, ge=0, le=100, description="Puntuación de riesgo 0-100")
    level: str = Field("LOW", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    flags: list[str] = Field(default_factory=list, max_length=50)
    typosquatting: TyposquattingData | None = None
    url_anatomy: URLStructureResult | None = None

class OSINTResponse(BaseModel):
    """Respuesta consolidada del análisis OSINT."""
    model_config = ConfigDict(extra="forbid")

    geolocation: GeolocationData | None = None
    abuse_confidence_score: int | None = Field(None, ge=0, le=100)
    total_reports: int | None = Field(None, ge=0)
    whois: WhoisData | None = None
    ssl: SSLData | None = None
    tech_data: TechData | None = None
    url_anatomy: UrlAnatomyData | None = None
    heuristic_result: HeuristicResult | None = None
    typosquatting: TyposquattingData | None = None
    form_analysis: FormData | None = None
    cloaking_detected: bool = False
    screenshot_desktop: str | None = Field(None, max_length=MAX_SCREENSHOT_LENGTH)
    screenshot_mobile: str | None = Field(None, max_length=MAX_SCREENSHOT_LENGTH)
    is_mobile_optimized: bool = True

    @property
    def redirect_chain(self) -> list[str]:
        return self.tech_data.redirect_chain if self.tech_data else []

    @property
    def external_scripts(self) -> list[str]:
        return self.tech_data.external_scripts if self.tech_data else []

    @property
    def technologies(self) -> list[str]:
        return self.tech_data.technologies if self.tech_data else []

    @property
    def html_content(self) -> str:
        return self.tech_data.html_content if self.tech_data else ""

    @property
    def privacy_analysis(self) -> PrivacyData | None:
        return self.tech_data.privacy_analysis if self.tech_data else None

    @property
    def is_typosquatting(self) -> bool:
        if self.typosquatting:
            return self.typosquatting.is_typosquatting
        if self.heuristic_result and self.heuristic_result.typosquatting:
            return self.heuristic_result.typosquatting.is_typosquatting
        return False

    @property
    def target_brand(self) -> str | None:
        if self.typosquatting and self.typosquatting.target_brand:
            return self.typosquatting.target_brand
        if self.heuristic_result and self.heuristic_result.typosquatting:
            return self.heuristic_result.typosquatting.target_brand
        return None

    @property
    def has_dangerous_form(self) -> bool:
        return self.form_analysis.has_dangerous_form if self.form_analysis else False

    @property
    def reason(self) -> str | None:
        return self.form_analysis.reason if self.form_analysis else None

    @property
    def url_structure(self) -> URLStructureResult | None:
        return self.heuristic_result.url_anatomy if self.heuristic_result else None