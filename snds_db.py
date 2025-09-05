import csv
import os
import sqlite3
from io import StringIO
from typing import Dict, Iterable, List, Optional

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
            filtered TEXT
        )
        """
    )
    # Full capture of SNDS data endpoint columns
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS data_feed (
            ip_address TEXT,
            activity_start TEXT,
            activity_end TEXT,
            rcpt_commands INTEGER,
            data_commands INTEGER,
            message_recipients INTEGER,
            filter_result TEXT,
            complaint_rate TEXT,
            trap_start TEXT,
            trap_end TEXT,
            trap_hits INTEGER,
            sample_helo TEXT,
            jmr_p1_sender TEXT,
            comments TEXT
        )
        """
    )
    # NOTE: IP status table creation disabled; leaving here for reference only.
    # cur.execute(
    #     """
    #     CREATE TABLE IF NOT EXISTS ip_status (
    #         ip TEXT,
    #         status TEXT
    #     )
    #     """
    # )
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


def _looks_like_ip(value: str) -> bool:
    try:
        parts = value.strip().split(".")
        return (
            len(parts) == 4
            and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
        )
    except Exception:
        return False


def _parse_percent(value: str | None) -> float:
    """Convert values like '0.3%' or '< 0.1%' to a numeric percent (0.3 -> 0.3)."""
    if not value:
        return 0.0
    v = value.strip()
    # Remove trailing percent sign
    if v.endswith("%"):
        v = v[:-1].strip()
    # Handle leading '<' or '~'
    if v.startswith("<") or v.startswith("~"):
        v = v[1:].strip()
    # Some feeds return like '0.1' or '0.1%'. If not a float, fallback to 0.
    try:
        return float(v)
    except Exception:
        return 0.0


def fetch_csv(url: str, fieldnames: Optional[List[str]] = None) -> Iterable[Dict[str, str]]:
    """
    Fetch CSV from URL. If the CSV lacks headers, use provided fieldnames.

    For SNDS endpoints that sometimes omit headers, pass appropriate default
    fieldnames to ensure stable parsing.
    """
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    text = resp.text

    # Peek first row to detect header presence
    sio = StringIO(text)
    rdr = csv.reader(sio)
    try:
        first_row = next(rdr)
    except StopIteration:
        return []

    # If first field looks like an IP address, assume no headers
    has_header = not (first_row and _looks_like_ip(first_row[0]))

    sio.seek(0)
    if has_header:
        return csv.DictReader(sio)
    # No header present — build a DictReader with fallback fieldnames
    # Provide a conservative default layout for SNDS daily data if none supplied.
    if not fieldnames:
        # Default to the SNDS data endpoint column set (headerless variant)
        fieldnames = [
            "IP Address",
            "Activity Start",
            "Activity End",
            "RCPT commands",
            "DATA commands",
            "Message recipients",
            "Filter result",
            "Complaint rate",
            "Trap message period start",
            "Trap message period end",
            "Trap hits",
            "Sample HELO",
            "JMR P1 Sender",
            "Comments",
        ]
    return csv.DictReader(sio, fieldnames=fieldnames)


def store_daily_metrics(conn: sqlite3.Connection, rows: Iterable[Dict[str, str]]):
    cur = conn.cursor()
    for row in rows:
        ip = (
            row.get('IP Address')
            or row.get('IPAddress')
            or row.get('ip')
            or row.get('IP')
        )
        # Choose a representative date/time; prefer EndTime if present
        date_val = (
            row.get('Activity End')
            or row.get('EndTime')
            or row.get('Date')
            or row.get('date')
            or ''
        )
        # Complaint rate can be like "< 0.1%" — normalize to a float number
        complaint_rate = _parse_percent(
            row.get('Complaint rate')
            or row.get('ComplaintRate')
            or row.get('Complaint Rate')
            or row.get('Complaints')
        )
        # Trap hits — try multiple possible keys
        trap_hits_raw = (
            row.get('Trap hits')
            or row.get('TrapHits')
            or row.get('TrapSampleCount')
            or row.get('Trap Samples')
            or row.get('Trap Count')
            or '0'
        )
        try:
            trap_hits = int(trap_hits_raw or 0)
        except Exception:
            trap_hits = 0
        # Filter result (GREEN/YELLOW/etc.) — store the textual status
        filtered = (
            row.get('Filter result')
            or row.get('Status')
            or row.get('Color')
            or ''
        )
        cur.execute(
            "INSERT INTO daily_metrics (date, ip, complaint_rate, trap_hits, filtered) VALUES (?, ?, ?, ?, ?)",
            (date_val, ip, complaint_rate, trap_hits, filtered),
        )
    conn.commit()


def _to_int(value: str | None) -> int:
    try:
        return int(str(value or '0').replace(',', '').strip())
    except Exception:
        return 0


def store_data_feed(conn: sqlite3.Connection, rows: Iterable[Dict[str, str]]):
    """Store all columns for the SNDS data endpoint into data_feed."""
    cur = conn.cursor()
    for row in rows:
        ip_address = row.get('IP Address') or row.get('IPAddress') or row.get('ip')
        activity_start = row.get('Activity Start') or row.get('StartTime')
        activity_end = row.get('Activity End') or row.get('EndTime')
        rcpt_commands = _to_int(row.get('RCPT commands') or row.get('MsgCount1'))
        data_commands = _to_int(row.get('DATA commands') or row.get('MsgCount2'))
        message_recipients = _to_int(
            row.get('Message recipients') or row.get('MsgCount3')
        )
        filter_result = row.get('Filter result') or row.get('Status')
        complaint_rate_text = (
            row.get('Complaint rate') or row.get('ComplaintRate') or ''
        )
        trap_start = (
            row.get('Trap message period start')
            or row.get('TrapSampleStart')
            or row.get('CompSampleStart')
        )
        trap_end = (
            row.get('Trap message period end')
            or row.get('TrapSampleEnd')
            or row.get('CompSampleEnd')
        )
        trap_hits = _to_int(
            row.get('Trap hits')
            or row.get('TrapSampleCount')
            or row.get('TrapHits')
        )
        sample_helo = row.get('Sample HELO') or ''
        jmr_p1_sender = row.get('JMR P1 Sender') or ''
        comments = row.get('Comments') or row.get('Notes') or ''

        cur.execute(
            """
            INSERT INTO data_feed (
                ip_address, activity_start, activity_end,
                rcpt_commands, data_commands, message_recipients,
                filter_result, complaint_rate,
                trap_start, trap_end, trap_hits,
                sample_helo, jmr_p1_sender, comments
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ip_address,
                activity_start,
                activity_end,
                rcpt_commands,
                data_commands,
                message_recipients,
                filter_result,
                complaint_rate_text,
                trap_start,
                trap_end,
                trap_hits,
                sample_helo,
                jmr_p1_sender,
                comments,
            ),
        )
    conn.commit()


def store_ip_status(conn: sqlite3.Connection, rows: Iterable[Dict[str, str]]):
    cur = conn.cursor()
    for row in rows:
        cur.execute(
            "INSERT INTO ip_status (ip, status) VALUES (?, ?)",
            (
                row.get('IPAddress') or row.get('ip') or row.get('IP'),
                row.get('Status') or row.get('Color') or row.get('StatusText'),
            ),
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
    # SNDS data feed may omit headers — pass fallback fieldnames
    data_rows = list(
        fetch_csv(
            SNDS_URL_DATA.format(key=SNDS_KEY),
            fieldnames=[
                "IP Address",
                "Activity Start",
                "Activity End",
                "RCPT commands",
                "DATA commands",
                "Message recipients",
                "Filter result",
                "Complaint rate",
                "Trap message period start",
                "Trap message period end",
                "Trap hits",
                "Sample HELO",
                "JMR P1 Sender",
                "Comments",
            ],
        )
    )
    # Store both a normalized summary and the full raw columns
    store_daily_metrics(conn, data_rows)
    store_data_feed(conn, data_rows)
    # IP status ingestion disabled; keeping example code commented for future use.
    # status_rows = list(
    #     fetch_csv(
    #         SNDS_URL_IPSTATUS.format(key=SNDS_KEY),
    #         fieldnames=["IPAddress", "Status", "Notes"],
    #     )
    # )
    # store_ip_status(conn, status_rows)
    # # Example: fetch and store trap samples for each IP in status data
    # for row in status_rows:
    #     ip = row.get('IPAddress')
    #     try:
    #         sample = fetch_sample(ip, 'trap')
    #         store_sample(conn, ip, 'trap', sample)
    #     except Exception:
    #         # Ignore failures for sample retrieval
    #         pass


if __name__ == '__main__':
    main()
