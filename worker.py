import os
import json
import time
import sqlite3
from datetime import datetime, timedelta

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore

import requests
import smtplib
from email.message import EmailMessage

import snds_db
import plugin_store
from plugins import register, get_registered
from bs4 import BeautifulSoup
import re
import random


TZ = os.getenv("TZ", "UTC")


def _send_email(to_addresses: str, body: str, subject: str = "SNDS Alerts"):
    emails = [e.strip() for e in (to_addresses or "").split(",") if e.strip()]
    if not emails:
        print("[worker] email enabled but no recipients configured")
        return
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    pwd = os.getenv("SMTP_PASS")
    sender = os.getenv("SMTP_FROM", user or "alerts@example.com")
    if not host or not user or not pwd:
        print("[worker] SMTP not fully configured; skipping email send")
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(emails)
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.starttls()
            s.login(user, pwd)
            s.send_message(msg)
        print(f"[worker] email alerts sent to {emails}")
    except Exception as e:
        print(f"[worker] email send error: {e}")


def _send_slack(webhook_url: str, body: str):
    if not webhook_url:
        print("[worker] slack enabled but webhook missing")
        return
    try:
        resp = requests.post(webhook_url, json={"text": body}, timeout=10)
        if resp.status_code >= 300:
            print(f"[worker] slack webhook failed: {resp.status_code} {resp.text}")
        else:
            print("[worker] slack alert posted")
    except Exception as e:
        print(f"[worker] slack error: {e}")


def _send_teams(webhook_url: str, body: str):
    if not webhook_url:
        print("[worker] teams enabled but webhook missing")
        return
    try:
        resp = requests.post(webhook_url, json={"text": body}, timeout=10)
        if resp.status_code >= 300:
            print(f"[worker] teams webhook failed: {resp.status_code} {resp.text}")
        else:
            print("[worker] teams alert posted")
    except Exception as e:
        print(f"[worker] teams error: {e}")


def _ensure_senderscore_tables():
    try:
        conn = sqlite3.connect(snds_db.DB_PATH)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS senderscore_daily (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                score INTEGER,
                volume INTEGER,
                measures TEXT
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_senderscore_ip_time ON senderscore_daily(ip, observed_at)")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[worker] failed ensuring senderscore tables: {e}")


def _parse_senderscore_html(html: str) -> dict:
    """Parse SenderScore HTML, extracting ssData from inline script and tables.

    Returns a dict with keys:
    - score (int), score_word (str), rating_desc (str)
    - volume (int if derivable), volume_tier (str)
    - certified (str/bool), return_path (str)
    - score_history (list), volume_history (list)
    - reputations (dict), sending_domains (list)
    """
    soup = BeautifulSoup(html, "html.parser")
    details: dict = {
        "score": None,
        "score_word": None,
        "rating_desc": None,
        "volume": None,
        "volume_tier": None,
        "certified": None,
        "return_path": None,
        "score_history": [],
        "volume_history": [],
        "reputations": {},
        "sending_domains": [],
    }

    # Extract ssData from an inline script
    script_content = None
    for sc in soup.find_all("script"):
        try:
            txt = sc.get_text() or ""
        except Exception:
            txt = ""
        if txt and "ssData" in txt:
            script_content = txt
            break
    if not script_content:
        try:
            node = soup.find("script", string=re.compile("ssData"))
            if node:
                script_content = node.get_text()
        except Exception:
            pass
    if script_content:
        try:
            m = re.search(r"ssData\.senderscore\s*=\s*(\d+);", script_content)
            if m:
                details["score"] = int(m.group(1))
        except Exception:
            pass
        try:
            m = re.search(r"ssData\.rating\s*=\s*'([^']*)'", script_content)
            if m:
                details["score_word"] = m.group(1)
        except Exception:
            pass
        try:
            m = re.search(r"ssData\.rating_desc\s*=\s*'([^']*)'", script_content)
            if m:
                details["rating_desc"] = m.group(1)
        except Exception:
            pass
        try:
            m = re.search(r"ssData\.volume_tier\s*=\s*'([^']*)'", script_content)
            if m:
                details["volume_tier"] = m.group(1)
        except Exception:
            pass
        try:
            m = re.search(r"ssData\.certified\s*=\s*'([^']*)'", script_content)
            if m:
                details["certified"] = m.group(1)
        except Exception:
            pass
        try:
            m = re.search(r"ssData\.rp_safe\s*=\s*'([^']*)'", script_content)
            if m:
                details["return_path"] = m.group(1)
        except Exception:
            pass
        try:
            m = re.search(r"ssData\.ss_trend\s*=\s*(\[.*?\])", script_content)
            if m:
                arr = json.loads(m.group(1))
                if isinstance(arr, list):
                    details["score_history"] = arr
        except Exception:
            pass
        try:
            m = re.search(r"ssData\.ss_volume_trend\s*=\s*(\[.*?\])", script_content)
            if m:
                arr = json.loads(m.group(1))
                if isinstance(arr, list):
                    details["volume_history"] = arr
                    # Use last entry's value as current numeric volume if possible
                    try:
                        last = arr[-1]
                        if isinstance(last, dict) and "value" in last:
                            details["volume"] = int(last.get("value") or 0)
                            ts = last.get("timestamp")
                            if ts is not None:
                                try:
                                    # Expecting ms epoch
                                    ms = int(ts)
                                    iso = datetime.utcfromtimestamp(ms / 1000.0).isoformat()
                                    details["volume_timestamp"] = ms
                                    details["volume_timestamp_iso"] = iso
                                except Exception:
                                    pass
                        elif isinstance(last, (int, float)):
                            details["volume"] = int(last)
                    except Exception:
                        pass
        except Exception:
            pass

    # Reputation measures from table#repTable
    try:
        rep_table = soup.find("table", id="repTable")
        if rep_table:
            rows = rep_table.find_all("tr")
            reps: dict[str, str] = {}
            for row in rows[1:]:
                cols = row.find_all("td")
                if len(cols) >= 2:
                    key = cols[0].get_text(strip=True)
                    val = cols[1].get_text(strip=True)
                    reps[key] = val
            details["reputations"] = reps
    except Exception:
        pass

    # Sending domains from table#sendingTable
    try:
        s_table = soup.find("table", id="sendingTable")
        domains: list[str] = []
        if s_table:
            rows = s_table.find_all("tr")
            for row in rows[1:]:
                cols = row.find_all("td")
                if cols:
                    domains.append(cols[0].get_text(strip=True))
        details["sending_domains"] = domains
    except Exception:
        pass

    return details


def _default_chrome_ua() -> str:
    # Reasonably modern Chrome UA (update periodically)
    return (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/127.0.0.0 Safari/537.36"
    )


def _human_session() -> requests.Session:
    s = requests.Session()
    ua = os.getenv("SENDERSCORE_USER_AGENT") or _default_chrome_ua()
    s.headers.update(
        {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": os.getenv("SENDERSCORE_ACCEPT_LANGUAGE", "en-US,en;q=0.9"),
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
    )
    cookie = os.getenv("SENDERSCORE_COOKIE", "")
    if cookie:
        s.headers["Cookie"] = cookie
    return s


def _fetch_senderscore(ip: str, session: requests.Session) -> dict | None:
    base = "https://senderscore.org/assess/get-your-score/report/?lookup={ip}&authenticated=true"
    url = base.format(ip=ip)
    try:
        resp = session.get(url, timeout=30)
        if resp.status_code >= 400:
            print(f"[worker] senderscore HTTP {resp.status_code} for {ip}")
            return None
        return _parse_senderscore_html(resp.text)
    except Exception as e:
        print(f"[worker] senderscore fetch error for {ip}: {e}")
        return None


@register("snds")
def run_snds():
    # Ingest
    try:
        snds_db.main()
    except Exception as e:
        print(f"[worker] SNDS ingest failed: {e}")
        return
    # Evaluate
    cfg = plugin_store.load_plugin("snds", {
        "enabled": True,
        "schedule": {"enabled": False, "interval_minutes": 60},
        "alerts": {"enabled": True, "complaint_rate_threshold": 0.1, "trap_hits_threshold": 1, "filter_levels": ["YELLOW", "RED"]},
        "delivery": {
            "email": {"enabled": False, "recipients": ""},
            "slack": {"enabled": False, "webhook_url": ""},
            "teams": {"enabled": False, "webhook_url": ""},
            "message_template": "SNDS alert for {ip}: complaints={complaint_rate}% traps={trap_hits} filter={filter_result} window {activity_start}→{activity_end}",
        },
    })
    if not cfg.get("enabled") or not cfg["alerts"].get("enabled"):
        print("[worker] SNDS alerts disabled; skipping evaluation")
        return
    alerts = []
    seen = set()
    try:
        cur = sqlite3.connect(snds_db.DB_PATH).cursor()
        cur.execute(
            """
            SELECT ip_address, activity_start, activity_end, complaint_rate, trap_hits, filter_result
            FROM data_feed
            ORDER BY activity_end DESC
            LIMIT 1000
            """
        )
        rows = cur.fetchall()
    except Exception as e:
        print(f"[worker] failed to load data_feed: {e}")
        rows = []
    for r in rows:
        ip, astart, aend, complaint_text, trap_hits, filter_result = r
        if ip in seen:
            continue
        seen.add(ip)
        try:
            comp_val = snds_db._parse_percent(complaint_text)
        except Exception:
            comp_val = 0.0
        hit_val = int(trap_hits or 0)
        filt = (filter_result or "").strip().upper()
        cond_comp = comp_val > float(cfg["alerts"].get("complaint_rate_threshold", 0.1))
        cond_trap = hit_val >= int(cfg["alerts"].get("trap_hits_threshold", 1))
        cond_filter = filt in [x.upper() for x in cfg["alerts"].get("filter_levels", [])]
        if cond_comp or cond_trap or cond_filter:
            alerts.append({
                "ip": ip,
                "activity_start": astart,
                "activity_end": aend,
                "complaint_rate": comp_val,
                "trap_hits": hit_val,
                "filter_result": filt,
            })
    if not alerts:
        print("[worker] SNDS: no alerts triggered")
        return
    template = cfg["delivery"].get("message_template")
    lines = []
    for a in alerts:
        try:
            lines.append(template.format(**a))
        except Exception:
            lines.append(f"SNDS alert for {a['ip']}: complaints={a['complaint_rate']}% traps={a['trap_hits']} filter={a['filter_result']}")
    msg = "\n".join(lines)
    if cfg["delivery"].get("email", {}).get("enabled"):
        _send_email(cfg["delivery"]["email"].get("recipients", ""), msg)
    if cfg["delivery"].get("slack", {}).get("enabled"):
        _send_slack(cfg["delivery"]["slack"].get("webhook_url", ""), msg)
    if cfg["delivery"].get("teams", {}).get("enabled"):
        _send_teams(cfg["delivery"]["teams"].get("webhook_url", ""), msg)

    # Persist each alert line for dashboard visibility
    methods = []
    if cfg["delivery"].get("email", {}).get("enabled"):
        methods.append("email")
    if cfg["delivery"].get("slack", {}).get("enabled"):
        methods.append("slack")
    if cfg["delivery"].get("teams", {}).get("enabled"):
        methods.append("teams")
    methods_str = ",".join(methods)
    for idx, a in enumerate(alerts):
        line = lines[idx] if idx < len(lines) else str(a)
        meta = {
            "ip": a.get("ip"),
            "complaint_rate": a.get("complaint_rate"),
            "trap_hits": a.get("trap_hits"),
            "filter_result": a.get("filter_result"),
            "activity_start": a.get("activity_start"),
            "activity_end": a.get("activity_end"),
        }
        plugin_store.add_alert("snds", line, methods_str, meta)


@register("senderscore")
def run_senderscore():
    _ensure_senderscore_tables()
    cfg = plugin_store.load_plugin("senderscore", {
        "enabled": False,
        "schedule": {"enabled": False, "interval_minutes": 1440},
        "options": {"ip_source": "snds", "manual_ips": ""},
        "alerts": {"enabled": True, "change_threshold_percent": 5.0, "notify_on_measure_change": True},
        "delivery": {"email": {"enabled": False, "recipients": ""}, "slack": {"enabled": False, "webhook_url": ""}, "teams": {"enabled": False, "webhook_url": ""}, "message_template": "SenderScore alert {ip}: score {old_score} -> {new_score} (Δ{delta_percent}%), volume={volume}"},
    })
    if not cfg.get("enabled"):
        print("[worker] SenderScore disabled; skipping")
        return
    # Build IP list
    ips: list[str] = []
    try:
        if cfg["options"].get("ip_source") == "snds":
            cur = sqlite3.connect(snds_db.DB_PATH).cursor()
            cur.execute("SELECT DISTINCT ip_address FROM data_feed ORDER BY ip_address LIMIT 1000")
            ips = [row[0] for row in cur.fetchall() if row and row[0]]
        else:
            raw = cfg["options"].get("manual_ips", "")
            parts = re.split(r"[\s,]+", raw)
            ips = [p.strip() for p in parts if p.strip()]
    except Exception as e:
        print(f"[worker] SenderScore build IP list failed: {e}")
        return
    if not ips:
        print("[worker] SenderScore no IPs to query")
        return
    # Emulate human browsing cadence
    random.shuffle(ips)
    max_ips = int(os.getenv("SENDERSCORE_MAX_IPS_PER_RUN", "30"))
    ips = ips[: max(1, max_ips)]
    delay_min = float(os.getenv("SENDERSCORE_DELAY_MIN_SEC", "3.0"))
    delay_max = float(os.getenv("SENDERSCORE_DELAY_MAX_SEC", "6.0"))
    if delay_max < delay_min:
        delay_max = delay_min + 0.5
    session = _human_session()
    # Warm-up hit to set cookies
    try:
        session.get("https://senderscore.org/", timeout=15)
        time.sleep(random.uniform(delay_min, delay_max))
    except Exception:
        pass
    conn = sqlite3.connect(snds_db.DB_PATH)
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    alerts = []
    for ip in ips:
        info = _fetch_senderscore(ip, session)
        if not info:
            print(f"[worker] SenderScore: no info parsed for {ip}")
            continue
        score = int(info.get("score") or 0)
        volume = int(info.get("volume") or 0)
        measures_json = json.dumps(info)
        cur.execute(
            "INSERT INTO senderscore_daily (ip, observed_at, score, volume, measures) VALUES (?, ?, ?, ?, ?)",
            (ip, now, score, volume, measures_json),
        )
        # Compare with last record for this IP (prior to now)
        try:
            cur.execute(
                "SELECT score, volume, measures FROM senderscore_daily WHERE ip=? ORDER BY observed_at DESC LIMIT 2",
                (ip,),
            )
            rows = cur.fetchall()
            if len(rows) >= 2:
                new_score, _, new_measures = rows[0]
                old_score, _, old_measures = rows[1]
                delta = (new_score - old_score)
                # percent change relative to old
                delta_pct = (abs(delta) / max(1, old_score)) * 100.0
                threshold = float(cfg["alerts"].get("change_threshold_percent", 5.0))
                trigger = False
                reason = []
                if cfg["alerts"].get("enabled") and delta_pct > threshold:
                    trigger = True
                    reason.append(f"score Δ{delta_pct:.1f}%")
                # Reputation changes
                try:
                    old_obj = json.loads(old_measures) if old_measures else {}
                    new_obj = json.loads(new_measures) if new_measures else {}
                    old_rep = (old_obj.get("reputations") or {}) if isinstance(old_obj, dict) else {}
                    new_rep = (new_obj.get("reputations") or {}) if isinstance(new_obj, dict) else {}
                    if cfg["alerts"].get("notify_on_measure_change") and (old_rep != new_rep):
                        trigger = True
                        reason.append("reputation changed")
                    if cfg["alerts"].get("reputation_low_to_other"):
                        ups = []
                        for k, v in old_rep.items():
                            if isinstance(v, str) and v.strip().lower() == "low":
                                nv = new_rep.get(k)
                                if isinstance(nv, str) and nv.strip().lower() != "low":
                                    ups.append(k)
                        if ups:
                            trigger = True
                            reason.append("low→higher: " + ", ".join(ups))
                    # Spam traps threshold
                    st_thresh = int(cfg["alerts"].get("spam_trap_threshold", 0))
                    if st_thresh > 0:
                        st_val = new_rep.get("Spam Traps")
                        try:
                            # pull numeric from string like "123" or "123 hits"
                            m = re.search(r"(\d+)", str(st_val) if st_val is not None else "")
                            if m and int(m.group(1)) >= st_thresh:
                                trigger = True
                                reason.append(f"spam traps ≥ {st_thresh}")
                        except Exception:
                            pass
                except Exception:
                    pass
                # Volume vs average over last X days
                try:
                    days = int(cfg["alerts"].get("volume_avg_days", 7))
                    vth = float(cfg["alerts"].get("volume_change_threshold_percent", 20.0))
                    start = (datetime.utcnow() - timedelta(days=days)).isoformat()
                    cur.execute(
                        "SELECT avg(volume) FROM senderscore_daily WHERE ip=? AND observed_at >= ? AND observed_at < ?",
                        (ip, start, now),
                    )
                    avg_row = cur.fetchone()
                    avg_vol = float(avg_row[0]) if avg_row and avg_row[0] is not None else 0.0
                    if avg_vol > 0:
                        vdelta = (abs(volume - avg_vol) / avg_vol) * 100.0
                        if vdelta > vth:
                            trigger = True
                            reason.append(f"volume Δ{vdelta:.1f}% vs {days}d avg")
                except Exception:
                    pass
                if trigger:
                    alerts.append({
                        "ip": ip,
                        "old_score": int(old_score),
                        "new_score": int(new_score),
                        "delta_percent": round(delta_pct, 2),
                        "volume": volume,
                        "reason": ", ".join(reason),
                    })
        except Exception as e:
            print(f"[worker] SenderScore compare failed for {ip}: {e}")
            continue
        # Human-like delay between IP lookups
        time.sleep(random.uniform(delay_min, delay_max))
    conn.commit()
    conn.close()
    if not alerts:
        print("[worker] SenderScore: no alerts")
        return
    # Compose and deliver
    template = cfg["delivery"].get("message_template")
    lines = []
    for a in alerts:
        try:
            lines.append(template.format(**a))
        except Exception:
            lines.append(
                f"SenderScore alert {a['ip']}: {a['old_score']} -> {a['new_score']} (Δ{a['delta_percent']}%), volume={a['volume']}"
            )
    body = "\n".join(lines)
    methods = []
    if cfg["delivery"].get("email", {}).get("enabled"):
        _send_email(cfg["delivery"]["email"].get("recipients", ""), body, subject="SenderScore Alerts")
        methods.append("email")
    if cfg["delivery"].get("slack", {}).get("enabled"):
        _send_slack(cfg["delivery"]["slack"].get("webhook_url", ""), body)
        methods.append("slack")
    if cfg["delivery"].get("teams", {}).get("enabled"):
        _send_teams(cfg["delivery"]["teams"].get("webhook_url", ""), body)
        methods.append("teams")
    methods_str = ",".join(methods)
    for idx, a in enumerate(alerts):
        line = lines[idx] if idx < len(lines) else str(a)
        plugin_store.add_alert("senderscore", line, methods_str, a)


def sync_jobs(scheduler: BlockingScheduler):
    # Sync SNDS job based on plugin config
    cfg = plugin_store.load_plugin("snds", {
        "enabled": True,
        "schedule": {"enabled": False, "interval_minutes": 60},
        "alerts": {"enabled": True, "complaint_rate_threshold": 0.1, "trap_hits_threshold": 1, "filter_levels": ["YELLOW", "RED"]},
        "delivery": {"email": {"enabled": False, "recipients": ""}, "slack": {"enabled": False, "webhook_url": ""}, "teams": {"enabled": False, "webhook_url": ""}, "message_template": ""},
    })
    job_id = "plugin:snds"
    job = scheduler.get_job(job_id)
    try:
        if not cfg.get("enabled") or not cfg.get("schedule", {}).get("enabled"):
            if job:
                scheduler.remove_job(job_id)
                print("[worker] removed SNDS job (disabled)")
        else:
            minutes = max(1, int(cfg["schedule"].get("interval_minutes", 60)))
            scheduler.add_job(
                run_snds,
                "interval",
                minutes=minutes,
                id=job_id,
                replace_existing=True,
                coalesce=True,
                max_instances=1,
                misfire_grace_time=300,
            )
            print(f"[worker] scheduled SNDS every {minutes}m")
    except Exception as e:
        print(f"[worker] failed to schedule SNDS: {e}")

    # Placeholder for news plugin scheduling (no-op runner yet)
    try:
        news_cfg = plugin_store.load_plugin(
            "news",
            {"enabled": False, "schedule": {"enabled": False, "interval_minutes": 60}},
        )
        news_job_id = "plugin:news"
        njob = scheduler.get_job(news_job_id)
        if not news_cfg.get("enabled") or not news_cfg.get("schedule", {}).get("enabled"):
            if njob:
                scheduler.remove_job(news_job_id)
                print("[worker] removed News job (disabled)")
        else:
            # Dummy lambda until real runner exists
            def _run_news():
                print("[worker] News plugin placeholder run at", datetime.utcnow().isoformat())

            minutes = max(1, int(news_cfg["schedule"].get("interval_minutes", 60)))
            scheduler.add_job(
                _run_news,
                "interval",
                minutes=minutes,
                id=news_job_id,
                replace_existing=True,
                coalesce=True,
                max_instances=1,
                misfire_grace_time=300,
            )
            print(f"[worker] scheduled News every {minutes}m (placeholder)")
    except Exception as e:
        print(f"[worker] failed to schedule News: {e}")

    # SenderScore scheduling
    try:
        ss = plugin_store.load_plugin("senderscore", {"enabled": False, "schedule": {"enabled": False, "interval_minutes": 1440}})
        ss_job_id = "plugin:senderscore"
        job = scheduler.get_job(ss_job_id)
        if not ss.get("enabled") or not ss.get("schedule", {}).get("enabled"):
            if job:
                scheduler.remove_job(ss_job_id)
                print("[worker] removed SenderScore job (disabled)")
        else:
            minutes = max(1, int(ss["schedule"].get("interval_minutes", 1440)))
            scheduler.add_job(
                run_senderscore,
                "interval",
                minutes=minutes,
                id=ss_job_id,
                replace_existing=True,
                coalesce=True,
                max_instances=1,
                misfire_grace_time=600,
            )
            print(f"[worker] scheduled SenderScore every {minutes}m")
    except Exception as e:
        print(f"[worker] failed to schedule SenderScore: {e}")


def main():
    jobstores = {}
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        jobstores["default"] = SQLAlchemyJobStore(url=db_url)
        print("[worker] using SQLAlchemyJobStore with DATABASE_URL")
    else:
        jobstores["default"] = SQLAlchemyJobStore(url="sqlite:///jobs.sqlite")
        print("[worker] using local SQLite job store")

    scheduler = BlockingScheduler(jobstores=jobstores, timezone=TZ)

    # Periodically refresh jobs from plugin configs
    scheduler.add_job(
        lambda: sync_jobs(scheduler),
        "interval",
        minutes=1,
        id="system:sync",
        replace_existing=True,
        coalesce=True,
    )

    # Initial sync
    sync_jobs(scheduler)
    print("[worker] starting scheduler at", datetime.utcnow().isoformat())
    scheduler.start()


if __name__ == "__main__":
    main()
