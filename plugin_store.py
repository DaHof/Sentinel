import os
import json
import sqlite3
from typing import Any, Dict, List
from contextlib import contextmanager
from datetime import datetime

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine


PLUGINS_DB_PATH = os.getenv("PLUGINS_DB_PATH", "plugins.db")
PLUGINS_DB_URL = os.getenv("PLUGINS_DB_URL") or os.getenv("DATABASE_URL")
_ENGINE: Engine | None = create_engine(PLUGINS_DB_URL) if PLUGINS_DB_URL else None


def _get_conn() -> sqlite3.Connection:
    return sqlite3.connect(PLUGINS_DB_PATH)


@contextmanager
def _engine_conn():
    if not _ENGINE:
        raise RuntimeError("No SQLAlchemy engine configured")
    conn = _ENGINE.connect()
    try:
        yield conn
    finally:
        conn.close()


def ensure_db():
    if _ENGINE:
        with _engine_conn() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS plugin_settings (
                        plugin TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                    """
                )
            )
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS plugin_alerts (
                        id SERIAL PRIMARY KEY,
                        plugin TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        message TEXT NOT NULL,
                        deliveries TEXT,
                        meta TEXT
                    )
                    """
                )
            )
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS plugin_events (
                        id SERIAL PRIMARY KEY,
                        plugin TEXT NOT NULL,
                        event TEXT NOT NULL,
                        status TEXT,
                        message TEXT,
                        created_at TEXT NOT NULL,
                        meta TEXT
                    )
                    """
                )
            )
            conn.commit()
    else:
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
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS plugin_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plugin TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    message TEXT NOT NULL,
                    deliveries TEXT,
                    meta TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS plugin_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plugin TEXT NOT NULL,
                    event TEXT NOT NULL,
                    status TEXT,
                    message TEXT,
                    created_at TEXT NOT NULL,
                    meta TEXT
                )
                """
            )
            conn.commit()


def load_plugin(plugin: str, default: Dict[str, Any]) -> Dict[str, Any]:
    ensure_db()
    if _ENGINE:
        with _engine_conn() as conn:
            row = conn.execute(
                text("SELECT value FROM plugin_settings WHERE plugin=:p"), {"p": plugin}
            ).fetchone()
            if not row:
                save_plugin(plugin, default)
                return json.loads(json.dumps(default))
            try:
                current = json.loads(row[0])
            except Exception:
                current = {}
    else:
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
    if _ENGINE:
        with _engine_conn() as conn:
            conn.execute(
                text(
                    "INSERT INTO plugin_settings (plugin, value) VALUES (:p, :v) "
                    "ON CONFLICT (plugin) DO UPDATE SET value=excluded.value"
                ),
                {"p": plugin, "v": json.dumps(config)},
            )
            conn.commit()
    else:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO plugin_settings (plugin, value) VALUES (?, ?)",
                (plugin, json.dumps(config)),
            )
            conn.commit()


def add_alert(plugin: str, message: str, deliveries: str = "", meta: Dict[str, Any] | None = None) -> None:
    """Persist a single alert event for dashboard visibility."""
    ensure_db()
    created = datetime.utcnow().isoformat()
    meta_json = json.dumps(meta or {})
    if _ENGINE:
        with _engine_conn() as conn:
            conn.execute(
                text(
                    "INSERT INTO plugin_alerts (plugin, created_at, message, deliveries, meta) "
                    "VALUES (:p, :c, :m, :d, :meta)"
                ),
                {"p": plugin, "c": created, "m": message, "d": deliveries, "meta": meta_json},
            )
            conn.commit()
    else:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO plugin_alerts (plugin, created_at, message, deliveries, meta) VALUES (?, ?, ?, ?, ?)",
                (plugin, created, message, deliveries, meta_json),
            )
            conn.commit()


def list_alerts(limit: int = 20) -> List[Dict[str, Any]]:
    """Return recent alerts across all plugins, newest first."""
    ensure_db()
    rows: List[tuple]
    if _ENGINE:
        with _engine_conn() as conn:
            result = conn.execute(
                text(
                    "SELECT id, plugin, created_at, message, deliveries, meta "
                    "FROM plugin_alerts ORDER BY created_at DESC LIMIT :lim"
                ),
                {"lim": limit},
            )
            rows = result.fetchall()
    else:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, plugin, created_at, message, deliveries, meta FROM plugin_alerts ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()

    alerts: List[Dict[str, Any]] = []
    for r in rows:
        rid, plugin, created, message, deliveries, meta = r
        try:
            meta_obj = json.loads(meta) if meta else {}
        except Exception:
            meta_obj = {}
        alerts.append(
            {
                "id": rid,
                "plugin": plugin,
                "created_at": created,
                "message": message,
                "deliveries": deliveries or "",
                "meta": meta_obj,
            }
        )
    return alerts


def add_event(
    plugin: str,
    event: str,
    status: str = "info",
    message: str = "",
    meta: Dict[str, Any] | None = None,
) -> None:
    """Record lifecycle events for plugins (enable/disable/run/results)."""
    ensure_db()
    created = datetime.utcnow().isoformat()
    payload = json.dumps(meta or {})
    if _ENGINE:
        with _engine_conn() as conn:
            conn.execute(
                text(
                    "INSERT INTO plugin_events (plugin, event, status, message, created_at, meta) "
                    "VALUES (:plugin, :event, :status, :message, :created_at, :meta)"
                ),
                {
                    "plugin": plugin,
                    "event": event,
                    "status": status,
                    "message": message,
                    "created_at": created,
                    "meta": payload,
                },
            )
            conn.commit()
    else:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO plugin_events (plugin, event, status, message, created_at, meta) VALUES (?, ?, ?, ?, ?, ?)",
                (plugin, event, status, message, created, payload),
            )
            conn.commit()


def list_events(limit: int = 200) -> List[Dict[str, Any]]:
    """Return recent plugin lifecycle events, newest first."""
    ensure_db()
    rows: List[tuple]
    if _ENGINE:
        with _engine_conn() as conn:
            result = conn.execute(
                text(
                    "SELECT id, plugin, event, status, message, created_at, meta "
                    "FROM plugin_events ORDER BY created_at DESC LIMIT :lim"
                ),
                {"lim": limit},
            )
            rows = result.fetchall()
    else:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, plugin, event, status, message, created_at, meta FROM plugin_events ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()

    events: List[Dict[str, Any]] = []
    for r in rows:
        rid, plugin, event, status, message, created, meta = r
        try:
            meta_obj = json.loads(meta) if meta else {}
        except Exception:
            meta_obj = {}
        events.append(
            {
                "id": rid,
                "plugin": plugin,
                "event": event,
                "status": status or "",
                "message": message or "",
                "created_at": created,
                "meta": meta_obj,
            }
        )
    return events


def list_events_by_plugin(plugin: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Return recent events for a single plugin."""
    ensure_db()
    rows: List[tuple]
    if _ENGINE:
        with _engine_conn() as conn:
            result = conn.execute(
                text(
                    "SELECT id, plugin, event, status, message, created_at, meta "
                    "FROM plugin_events WHERE plugin=:p ORDER BY created_at DESC LIMIT :lim"
                ),
                {"p": plugin, "lim": limit},
            )
            rows = result.fetchall()
    else:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, plugin, event, status, message, created_at, meta FROM plugin_events WHERE plugin=? ORDER BY created_at DESC LIMIT ?",
                (plugin, limit),
            )
            rows = cur.fetchall()

    events: List[Dict[str, Any]] = []
    for r in rows:
        rid, plug, event, status, message, created, meta = r
        try:
            meta_obj = json.loads(meta) if meta else {}
        except Exception:
            meta_obj = {}
        events.append(
            {
                "id": rid,
                "plugin": plug,
                "event": event,
                "status": status or "",
                "message": message or "",
                "created_at": created,
                "meta": meta_obj,
            }
        )
    return events


def list_alerts_by_plugin(plugin: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Return recent alerts for a specific plugin, newest first."""
    ensure_db()
    rows: List[tuple]
    if _ENGINE:
        with _engine_conn() as conn:
            result = conn.execute(
                text(
                    "SELECT id, plugin, created_at, message, deliveries, meta "
                    "FROM plugin_alerts WHERE plugin=:p ORDER BY created_at DESC LIMIT :lim"
                ),
                {"p": plugin, "lim": limit},
            )
            rows = result.fetchall()
    else:
        with _get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, plugin, created_at, message, deliveries, meta FROM plugin_alerts WHERE plugin=? ORDER BY created_at DESC LIMIT ?",
                (plugin, limit),
            )
            rows = cur.fetchall()
    alerts: List[Dict[str, Any]] = []
    for r in rows:
        rid, plug, created, message, deliveries, meta = r
        try:
            meta_obj = json.loads(meta) if meta else {}
        except Exception:
            meta_obj = {}
        alerts.append(
            {
                "id": rid,
                "plugin": plug,
                "created_at": created,
                "message": message,
                "deliveries": deliveries or "",
                "meta": meta_obj,
            }
        )
    return alerts
