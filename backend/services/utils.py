import httpx
import logging
import socket
from urllib.parse import urlparse
import hashlib
import math
from collections import Counter
import filetype

logger = logging.getLogger(__name__)

def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = Counter(data)
    for count in occurrences.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def format_size(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"

def calculate_file_forensics(file_bytes: bytes, filename: str) -> dict:
    md5 = hashlib.md5(file_bytes).hexdigest()
    sha1 = hashlib.sha1(file_bytes).hexdigest()
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    
    size_str = format_size(len(file_bytes))
    entropy = calculate_shannon_entropy(file_bytes)
    
    kind = filetype.guess(file_bytes)
    mime_type = kind.mime if kind else "application/octet-stream"
    
    return {
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "file_size": size_str,
        "file_type": mime_type,
        "entropy": round(entropy, 2)
    }

# --- CONSTANTES DE SEGURIDAD CENTRALIZADAS ---

TARGET_BRANDS = [
    "google", "microsoft", "amazon", "netflix", "paypal", 
    "apple", "facebook", "instagram", "linkedin", "binance", "yahoo",
    "santander", "bbva", "caixabank", "outlook", "gmail", "twitter", "x"
]

ABUSED_FREE_HOSTING = [
    'github.io', 'vercel.app', 'netlify.app', 'firebaseapp.com', 
    'pages.dev', 'herokuapp.com', '000webhostapp.com', 'web.app',
    'azurewebsites.net', 's3.amazonaws.com', 'storage.googleapis.com',
    'duckdns.org', 'ngrok.io'
]

