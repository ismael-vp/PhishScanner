from pydantic import BaseModel, Field
from typing import Optional, List

class GeolocationData(BaseModel):
    ip: str
    lat: float
    lon: float
    country: str
    countryCode: str
    city: str
    isp: str

class GeoScannerResult(BaseModel):
    geolocation: Optional[GeolocationData] = None
    abuseConfidenceScore: Optional[int] = None
    totalReports: Optional[int] = None

class WhoisData(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None

class SSLData(BaseModel):
    issuer: Optional[str] = None
    expiration_date: Optional[str] = None

class HostingBrandAlert(BaseModel):
    brand: str
    provider: str

class UrlAnatomyData(BaseModel):
    is_ip: bool = False
    suspicious_tld: bool = False
    excessive_subdomains: bool = False
    excessive_hyphens: bool = False
    phishing_keywords: List[str] = Field(default_factory=list)
    length_warning: bool = False
    hosting_brand_alert: Optional[HostingBrandAlert] = None
    domain_entropy: float = 0.0
    is_dga_suspect: bool = False

class PrivacyData(BaseModel):
    tracking_used: List[str] = Field(default_factory=list)
    trackers_count: int = 0
    data_linked: List[str] = Field(default_factory=list)
    device_access: List[str] = Field(default_factory=list)

class TechData(BaseModel):
    technologies: List[str] = Field(default_factory=list)
    external_scripts: List[str] = Field(default_factory=list)
    redirect_chain: List[str] = Field(default_factory=list)
    html_content: str = ""
    privacy_analysis: Optional[PrivacyData] = None
    is_mobile_optimized: bool = True

class TyposquattingData(BaseModel):
    is_typosquatting: bool = False
    target_brand: Optional[str] = None

class FormData(BaseModel):
    has_dangerous_form: bool = False
    reason: Optional[str] = None

class URLStructureResult(BaseModel):
    risk_score: int = 0
    level: str = "LOW"
    flags: List[str] = Field(default_factory=list)

class HeuristicResult(BaseModel):
    risk_score: int = 0
    level: str = "LOW"
    flags: List[str] = Field(default_factory=list)
    typosquatting: Optional[TyposquattingData] = None
    url_anatomy: Optional[URLStructureResult] = None

class OSINTResponse(BaseModel):


    geolocation: Optional[GeolocationData] = None
    whois: Optional[WhoisData] = None
    ssl: Optional[SSLData] = None
    redirect_chain: List[str] = Field(default_factory=list)
    external_scripts: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    url_anatomy: Optional[UrlAnatomyData] = None
    is_typosquatting: bool = False
    target_brand: Optional[str] = None
    has_dangerous_form: bool = False
    reason: Optional[str] = None
    html_content: str = ""
    abuseConfidenceScore: Optional[int] = None
    totalReports: Optional[int] = None
    privacy_analysis: Optional[PrivacyData] = None
    screenshot_desktop: Optional[str] = None
    screenshot_mobile: Optional[str] = None
    is_mobile_optimized: bool = True
    cloaking_detected: bool = False
    url_structure: Optional[URLStructureResult] = None
    heuristic_result: Optional[HeuristicResult] = None


