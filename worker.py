import os
import time
import sqlite3
from datetime import datetime

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore

import requests
import smtplib
from email.message import EmailMessage

import snds_db
import plugin_store


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

