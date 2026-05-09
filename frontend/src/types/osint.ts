export interface GeolocationData {
  ip: string;
  lat: number;
  lon: number;
  country: string;
  countryCode: string;
  city: string;
  isp: string;
}

export interface WhoisData {
  registrar: string | null;
  creation_date: string | null;
  expiration_date: string | null;
}

export interface SSLData {
  issuer: string | null;
  expiration_date: string | null;
}

export interface UrlAnatomyData {
  is_ip: boolean;
  suspicious_tld: boolean;
  excessive_subdomains: boolean;
  excessive_hyphens: boolean;
  phishing_keywords: string[];
  length_warning: boolean;
  hosting_brand_alert: { brand: string; provider: string } | null;
}

export interface PrivacyData {
  tracking_used: string[];
  trackers_count: number;
  data_linked: string[];
  device_access: string[];
}

export interface OSINTData {
  geolocation: GeolocationData | null;
  whois: WhoisData | null;
  ssl: SSLData | null;
  redirect_chain: string[];
  external_scripts: string[];
  technologies: string[];
  url_anatomy: UrlAnatomyData | null;
  is_typosquatting: boolean;
  target_brand: string | null;
  has_dangerous_form: boolean;
  reason: string | null;
  html_content: string;
  abuseConfidenceScore: number | null;
  totalReports: number | null;
  privacy_analysis: PrivacyData | null;
}
