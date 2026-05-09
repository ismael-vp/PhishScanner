import sqlite3
import json
import os
import logging
from datetime import datetime, timedelta
from typing import Optional, Any

logger = logging.getLogger(__name__)

class CacheService:
    def __init__(self, db_path: str = "threat_cache.db"):
        self.db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), db_path)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_cache (
                    key TEXT PRIMARY KEY,
                    data TEXT,
                    type TEXT,
                    timestamp DATETIME
                )
            """)
            conn.commit()

    def get(self, key: str, cache_type: str, ttl_hours: int = 24) -> Optional[dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT data, timestamp FROM scan_cache WHERE key = ? AND type = ?", 
                    (key, cache_type)
                )
                row = cursor.fetchone()
                if row:
                    data_str, timestamp_str = row
                    timestamp = datetime.fromisoformat(timestamp_str)
                    if datetime.now() - timestamp < timedelta(hours=ttl_hours):
                        return json.loads(data_str)
                    else:
                        # Expired
                        self.delete(key, cache_type)
        except Exception as e:
            logger.error(f"Error reading from cache: {e}")
        return None

    def set(self, key: str, data: Any, cache_type: str):
        try:
            data_str = json.dumps(data)
            timestamp = datetime.now().isoformat()
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO scan_cache (key, data, type, timestamp) VALUES (?, ?, ?, ?)",
                    (key, data_str, cache_type, timestamp)
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Error writing to cache: {e}")

    def delete(self, key: str, cache_type: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM scan_cache WHERE key = ? AND type = ?", (key, cache_type))
            conn.commit()

    def clear_all(self):
        """Borra absolutamente toda la caché almacenada."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM scan_cache")
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error clearing all cache: {e}")
            return False
