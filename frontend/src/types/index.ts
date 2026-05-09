export type ScanMode = 'url' | 'image';

export interface EngineResult {
  name: string;
  status: string;
  result: string | null;
  method: string;
}

export interface ThreatStats {
  malicious: number;
  suspicious: number;
  undetected: number;
  harmless: number;
  timeout: number;
  full_results?: EngineResult[];
  heuristic_flag?: string;
}

export interface AISummaryData {
  summary: string;
  action_steps: string[];
}

export interface GeolocationData {
  ip?: string;
  lat?: number;
  lon?: number;
  country?: string;
  countryCode?: string;
  city?: string;
  isp?: string;
}

export interface WhoisData {
  registrar?: string;
  creation_date?: string;
  expiration_date?: string;
}

export interface SSLData {
  issuer?: string;
  expiration_date?: string;
}

export interface UrlAnatomyData {
  is_ip?: boolean;
  suspicious_tld?: boolean;
  excessive_subdomains?: boolean;
  excessive_hyphens?: boolean;
  phishing_keywords?: string[];
  length_warning?: boolean;
  hosting_brand_alert?: { brand: string; provider: string };
}

export interface PrivacyData {
  tracking_used: string[];
  trackers_count: number;
  data_linked: string[];
  device_access: string[];
}

export interface OSINTData {
  geolocation?: GeolocationData | null;
  whois?: WhoisData | null;
  ssl?: SSLData | null;
  redirect_chain?: string[];
  external_scripts?: string[];
  technologies?: string[];
  url_anatomy?: UrlAnatomyData | null;
  is_typosquatting?: boolean;
  target_brand?: string;
  has_dangerous_form?: boolean;
  reason?: string;
  html_content?: string;
  abuseConfidenceScore?: number;
  totalReports?: number;
  privacy_analysis?: PrivacyData | null;
  screenshot_desktop?: string;
  screenshot_mobile?: string;
  is_mobile_optimized?: boolean;
  cloaking_detected?: boolean;
  url_structure?: URLStructureResult | null;
  heuristic_result?: HeuristicResult | null;
}

export interface URLStructureResult {
  risk_score: number;
  level: 'LOW' | 'MEDIUM' | 'CRITICAL';
  flags: string[];
}

export interface HeuristicResult {
  risk_score: number;
  level: 'LOW' | 'MEDIUM' | 'CRITICAL';
  flags: string[];
  typosquatting?: TyposquattingData;
  url_anatomy?: URLStructureResult;
}

export interface TyposquattingData {
  is_typosquatting: boolean;
  target_brand?: string;
}

export interface ImagePhishingResult {
  is_phishing: boolean;
  confidence: 'Alta' | 'Media' | 'Baja';
  verdict: string;
  red_flags: string[];
  extracted_text: string;
  extracted_urls: string[];
}

export interface ScanResult {
  type: ScanMode;
  stats?: ThreatStats | null;
  ai_summary?: string | AISummaryData | null;
  status: 'success' | 'error';
  message?: string; 
  resourceName?: string;
  timestamp?: string;
  osint_data?: OSINTData | null;
  image_analysis?: ImagePhishingResult | null;
}
