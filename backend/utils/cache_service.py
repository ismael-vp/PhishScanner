import gzip
import json
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_DB_NAME = os.getenv("CACHE_DB_NAME", "threat_cache.db")
DEFAULT_DB_DIR = os.getenv("CACHE_DB_DIR", "")
DEFAULT_TTL_HOURS = int(os.getenv("CACHE_DEFAULT_TTL_HOURS", "24"))
MAX_KEY_LENGTH = int(os.getenv("CACHE_MAX_KEY_LENGTH", "512"))
MAX_DATA_SIZE_BYTES = int(os.getenv("CACHE_MAX_DATA_SIZE_BYTES", "500_000"))
COMPRESSION_ENABLED = os.getenv("CACHE_COMPRESSION_ENABLED", "true").lower() == "true"
COMPRESSION_THRESHOLD = int(os.getenv("CACHE_COMPRESSION_THRESHOLD", "1024"))
WAL_MODE = os.getenv("CACHE_WAL_MODE", "true").lower() == "true"
MAX_DB_SIZE_MB = int(os.getenv("CACHE_MAX_DB_SIZE_MB", "500"))
CLEANUP_INTERVAL_HOURS = int(os.getenv("CACHE_CLEANUP_INTERVAL_HOURS", "6"))
DB_LOCK_RETRY_ATTEMPTS = int(os.getenv("CACHE_DB_LOCK_RETRY_ATTEMPTS", "3"))
DB_LOCK_RETRY_DELAY = float(os.getenv("CACHE_DB_LOCK_RETRY_DELAY", "0.1"))

def _safe_json_dumps(obj: Any) -> str:
    """Serializa a JSON de forma segura, manejando Pydantic y datetime."""
    def _default_serializer(o):
        if hasattr(o, "model_dump"):
            return o.model_dump()
        if hasattr(o, "dict"):
            return o.dict()
        if hasattr(o, "isoformat"):
            return o.isoformat()
        return str(o)
    return json.dumps(obj, default=_default_serializer, ensure_ascii=False)

def _validate_key(key: str) -> str:
    """Valida que una key de caché sea segura."""
    if not key or not isinstance(key, str):
        raise ValueError("La key de caché no puede estar vacía")
    key = key.strip()
    if not key:
        raise ValueError("La key de caché no puede estar vacía")
    if len(key) > MAX_KEY_LENGTH:
        raise ValueError(f"Key demasiado larga: {len(key)}")
    if not re.match(r"^[a-zA-Z0-9_\.\-/]+$", key):
        raise ValueError(f"Key contiene caracteres inválidos: {key[:50]}")
    return key

def _validate_cache_type(cache_type: str) -> str:
    """Valida el tipo de caché."""
    if not cache_type or not isinstance(cache_type, str):
        raise ValueError("El tipo de caché no puede estar vacío")
    cache_type = cache_type.strip().lower()
    if not cache_type or len(cache_type) > 50:
        raise ValueError("Tipo de caché inválido o demasiado largo")
    if not re.match(r"^[a-z0-9_]+$", cache_type):
        raise ValueError("Tipo de caché contiene caracteres inválidos")
    return cache_type

def _get_db_path(db_path: str | None = None) -> str:
    """Retorna la ruta segura de la base de datos."""
    if db_path:
        basename = os.path.basename(db_path)
        if not basename or basename != db_path:
            raise ValueError("db_path debe ser un nombre de archivo simple")
        filename = basename
    else:
        filename = DEFAULT_DB_NAME

    if DEFAULT_DB_DIR:
        base_dir = os.path.abspath(DEFAULT_DB_DIR)
    else:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    os.makedirs(base_dir, exist_ok=True)
    return os.path.join(base_dir, filename)

class CacheService:
    """Servicio de caché persistente basado en SQLite."""

    def __init__(self, db_path: str | None = None):
        self.db_path = _get_db_path(db_path)
        self._last_cleanup = 0.0
        self._cleanup_interval_seconds = CLEANUP_INTERVAL_HOURS * 3600
        self._init_db()

    def _init_db(self):
        """Inicializa la base de datos con WAL mode e índices."""
        def _do_init():
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                if WAL_MODE:
                    conn.execute("PRAGMA journal_mode=WAL")
                    conn.execute("PRAGMA synchronous=NORMAL")
                else:
                    conn.execute("PRAGMA journal_mode=DELETE")

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS scan_cache (
                        key TEXT NOT NULL,
                        data BLOB NOT NULL,
                        type TEXT NOT NULL,
                        timestamp DATETIME NOT NULL,
                        compressed INTEGER NOT NULL DEFAULT 0,
                        size_bytes INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (key, type)
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_type_timestamp ON scan_cache(type, timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_cache(timestamp)")
                conn.commit()

        self._with_retry(_do_init)

    def _with_retry(self, operation, *args, **kwargs):
        """Ejecuta una operación SQLite con retry ante locks."""
        last_exc = None
        for attempt in range(DB_LOCK_RETRY_ATTEMPTS):
            try:
                return operation(*args, **kwargs)
            except sqlite3.OperationalError as exc:
                if "database is locked" in str(exc).lower():
                    last_exc = exc
                    delay = DB_LOCK_RETRY_DELAY * (2 ** attempt)
                    logger.warning(f"SQLite locked (intento {attempt + 1}), esperando {delay:.2f}s")
                    time.sleep(delay)
                else:
                    raise
        raise last_exc

    def _maybe_cleanup(self):
        """Ejecuta limpieza de expirados si ha pasado el intervalo."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval_seconds:
            return
        self._last_cleanup = now
        try:
            deleted = self._cleanup_expired()
            if deleted > 0:
                logger.info(f"Limpieza automática de caché: {deleted} registros eliminados")
        except Exception as exc:
            logger.warning(f"Error en limpieza de caché: {exc}")

    def _cleanup_expired(self) -> int:
        """Elimina registros expirados."""
        def _do_cleanup():
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                cutoff = (datetime.now() - timedelta(hours=DEFAULT_TTL_HOURS)).isoformat()
                cursor = conn.execute("DELETE FROM scan_cache WHERE timestamp < ?", (cutoff,))
                conn.commit()
                try:
                    conn.execute("VACUUM")
                except sqlite3.OperationalError:
                    pass
                return cursor.rowcount
        return self._with_retry(_do_cleanup)

    def _check_db_size(self) -> bool:
        """Verifica el tamaño de la DB."""
        try:
            size_mb = os.path.getsize(self.db_path) / (1024 * 1024)
            if size_mb > MAX_DB_SIZE_MB:
                logger.warning(f"Caché excede límite: {size_mb:.1f}MB > {MAX_DB_SIZE_MB}MB")
                self._cleanup_expired()
                return False
            return True
        except OSError:
            return True

    def get(self, key: str, cache_type: str, ttl_hours: int | None = None) -> dict | None:
        """Recupera un valor del caché si no ha expirado."""
        try:
            key = _validate_key(key)
            cache_type = _validate_cache_type(cache_type)
        except ValueError as exc:
            logger.warning(f"Validación de caché rechazada: {exc}")
            return None

        ttl = ttl_hours if ttl_hours is not None else DEFAULT_TTL_HOURS

        def _do_get():
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                cursor = conn.execute(
                    "SELECT data, timestamp, compressed FROM scan_cache WHERE key = ? AND type = ?",
                    (key, cache_type)
                )
                row = cursor.fetchone()
                if not row:
                    return None

                data_blob, timestamp_str, compressed = row
                if datetime.now() - datetime.fromisoformat(timestamp_str) >= timedelta(hours=ttl):
                    conn.execute("DELETE FROM scan_cache WHERE key = ? AND type = ?", (key, cache_type))
                    conn.commit()
                    return None

                if compressed:
                    data_blob = gzip.decompress(data_blob)

                return json.loads(data_blob.decode("utf-8"))

        try:
            result = self._with_retry(_do_get)
            self._maybe_cleanup()
            return result
        except Exception as exc:
            logger.error(f"Error leyendo caché para {key}: {exc}")
            return None

    def set(self, key: str, data: Any, cache_type: str):
        """Almacena un valor en el caché."""
        try:
            key = _validate_key(key)
            cache_type = _validate_cache_type(cache_type)
        except ValueError as exc:
            logger.warning(f"Validación de caché rechazada: {exc}")
            return

        if not self._check_db_size():
            return

        try:
            data_str = _safe_json_dumps(data)
        except Exception as exc:
            logger.error(f"Error serializando datos para caché: {exc}")
            return

        data_bytes = data_str.encode("utf-8")
        original_size = len(data_bytes)

        if original_size > MAX_DATA_SIZE_BYTES:
            if isinstance(data, dict):
                data = self._truncate_large_fields(data)
                try:
                    data_str = _safe_json_dumps(data)
                    data_bytes = data_str.encode("utf-8")
                    original_size = len(data_bytes)
                    if original_size > MAX_DATA_SIZE_BYTES:
                        return
                except Exception:
                    return
            else:
                return

        compressed = 0
        if COMPRESSION_ENABLED and original_size > COMPRESSION_THRESHOLD:
            compressed_data = gzip.compress(data_bytes, compresslevel=6)
            if len(compressed_data) < original_size:
                data_bytes = compressed_data
                compressed = 1

        timestamp = datetime.now().isoformat()

        def _do_set():
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO scan_cache
                       (key, data, type, timestamp, compressed, size_bytes)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (key, data_bytes, cache_type, timestamp, compressed, original_size)
                )
                conn.commit()

        try:
            self._with_retry(_do_set)
            self._maybe_cleanup()
        except Exception as exc:
            logger.error(f"Error escribiendo caché para {key}: {exc}")

    def delete(self, key: str, cache_type: str):
        """Elimina una entrada específica."""
        try:
            key = _validate_key(key)
            cache_type = _validate_cache_type(cache_type)
        except ValueError:
            return

        def _do_delete():
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                conn.execute("DELETE FROM scan_cache WHERE key = ? AND type = ?", (key, cache_type))
                conn.commit()
        self._with_retry(_do_delete)

    def clear_all(self, admin_key: str | None = None) -> bool:
        """Borra absolutamente toda la caché."""
        def _do_clear():
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                cursor = conn.execute("DELETE FROM scan_cache")
                deleted = cursor.rowcount
                conn.commit()
                try:
                    conn.execute("VACUUM")
                except sqlite3.OperationalError:
                    pass
                return deleted
        try:
            deleted = self._with_retry(_do_clear)
            logger.info(f"Caché completamente eliminada ({deleted} registros)")
            return True
        except Exception:
            return False

    @staticmethod
    def _truncate_large_fields(data: dict, max_field_size: int = 5000) -> dict:
        """Trunca campos string grandes en un dict."""
        result = {}
        for k, v in data.items():
            if isinstance(v, str) and len(v) > max_field_size:
                result[k] = v[:max_field_size] + "... [TRUNCADO]"
            elif isinstance(v, dict):
                result[k] = CacheService._truncate_large_fields(v, max_field_size)
            elif isinstance(v, list):
                result[k] = [(i[:max_field_size] + "... [TRUNCADO]" if isinstance(i, str) and len(i) > max_field_size else i) for i in v]
            else:
                result[k] = v
        return result
