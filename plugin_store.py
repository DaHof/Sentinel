import os
import json
import sqlite3
from typing import Any, Dict


PLUGINS_DB_PATH = os.getenv("PLUGINS_DB_PATH", "plugins.db")


def _get_conn() -> sqlite3.Connection:
    return sqlite3.connect(PLUGINS_DB_PATH)


def ensure_db():
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS plugin_settings (
                plugin TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.commit()


def load_plugin(plugin: str, default: Dict[str, Any]) -> Dict[str, Any]:
    ensure_db()
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM plugin_settings WHERE plugin=?", (plugin,))
        row = cur.fetchone()
        if not row:
            save_plugin(plugin, default)
            return json.loads(json.dumps(default))
        try:
            current = json.loads(row[0])
        except Exception:
            current = {}

        merged = _deep_merge(default, current)
        # If defaults added new keys, persist upgraded config
        if merged != current:
            save_plugin(plugin, merged)
        return merged


def _deep_merge(default: Any, current: Any) -> Any:
    """Recursively merge defaults into current, without removing extra keys.

    - For dicts: ensure all default keys exist; recursively merge.
    - For lists/scalars: prefer current when set, else fallback to default.
    """
    if isinstance(default, dict) and isinstance(current, dict):
        out: Dict[str, Any] = {}
        for k, v in default.items():
            if k in current:
                out[k] = _deep_merge(v, current[k])
            else:
                out[k] = v
        # Preserve additional keys present in current but not in default
        for k, v in current.items():
            if k not in out:
                out[k] = v
        return out
    # For non-dicts: if current is None or empty string, use default
    if current is None or current == "":
        return default
    return current


def save_plugin(plugin: str, config: Dict[str, Any]) -> None:
    ensure_db()
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO plugin_settings (plugin, value) VALUES (?, ?)",
            (plugin, json.dumps(config)),
        )
        conn.commit()
