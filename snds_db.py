import csv
import os
import sqlite3
from io import StringIO
from typing import Dict, Iterable

import requests
from email import message_from_string


def load_env(path: str | None = None) -> None:
    """Load environment variables from a .env file if present."""
    if path is None:
        path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(path):
        return
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key, value)


load_env()

DB_PATH = os.getenv("SNDS_DB_PATH", "snds.db")
SNDS_KEY = os.getenv("SNDS_KEY")
SNDS_URL_DATA = (
    "https://sendersupport.olc.protection.outlook.com/snds/data.aspx?key={key}"
)
SNDS_URL_IPSTATUS = (
    "https://sendersupport.olc.protection.outlook.com/snds/ipStatus.aspx?key={key}"
)
SNDS_URL_SAMPLE = (
    "https://sendersupport.olc.protection.outlook.com/snds/data.aspx?key={key}&ip={ip}&sampletype={stype}"
)


def init_db(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Create tables for SNDS data if they do not exist."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_metrics (
            date TEXT,
            ip TEXT,
            complaint_rate REAL,
            trap_hits INTEGER,
            filtered INTEGER
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ip_status (
            ip TEXT,
            status TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS samples (
            date TEXT,
            ip TEXT,
            sample_type TEXT,
            rcpt TEXT,
            message TEXT
        )
        """
    )
    conn.commit()
    return conn


def fetch_csv(url: str) -> Iterable[Dict[str, str]]:
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return csv.DictReader(StringIO(resp.text))


def store_daily_metrics(conn: sqlite3.Connection, rows: Iterable[Dict[str, str]]):
    cur = conn.cursor()
    for row in rows:
        cur.execute(
            "INSERT INTO daily_metrics (date, ip, complaint_rate, trap_hits, filtered) VALUES (?, ?, ?, ?, ?)",
            (
                row.get('Date'),
                row.get('IPAddress'),
                float(row.get('ComplaintRate', 0) or 0),
                int(row.get('TrapHits', 0) or 0),
                int(row.get('Filtered%', 0) or 0),
            ),
        )
    conn.commit()


def store_ip_status(conn: sqlite3.Connection, rows: Iterable[Dict[str, str]]):
    cur = conn.cursor()
    for row in rows:
        cur.execute(
            "INSERT INTO ip_status (ip, status) VALUES (?, ?)",
            (row.get('IPAddress'), row.get('Status')),
        )
    conn.commit()


def fetch_sample(ip: str, sample_type: str) -> str:
    """Fetch a trap or complaint sample message for an IP."""
    if not SNDS_KEY:
        raise RuntimeError('SNDS_KEY is not set')
    url = SNDS_URL_SAMPLE.format(key=SNDS_KEY, ip=ip, stype=sample_type)
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.text


def store_sample(conn: sqlite3.Connection, ip: str, sample_type: str, raw_message: str):
    msg = message_from_string(raw_message)
    rcpt = msg.get('To', '')
    date = msg.get('Date', '')
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO samples (date, ip, sample_type, rcpt, message) VALUES (?, ?, ?, ?, ?)",
        (date, ip, sample_type, rcpt, raw_message),
    )
    conn.commit()


def main():
    if not SNDS_KEY:
        raise RuntimeError('SNDS_KEY is not set')
    conn = init_db()
    data_rows = fetch_csv(SNDS_URL_DATA.format(key=SNDS_KEY))
    store_daily_metrics(conn, data_rows)
    status_rows = fetch_csv(SNDS_URL_IPSTATUS.format(key=SNDS_KEY))
    store_ip_status(conn, status_rows)
    # Example: fetch and store trap samples for each IP in status data
    for row in status_rows:
        ip = row.get('IPAddress')
        try:
            sample = fetch_sample(ip, 'trap')
            store_sample(conn, ip, 'trap', sample)
        except Exception:
            # Ignore failures for sample retrieval
            pass


if __name__ == '__main__':
    main()
