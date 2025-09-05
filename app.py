import os
import json
import sqlite3
from datetime import datetime

from flask import Flask, redirect, render_template, request, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from apscheduler.schedulers.background import BackgroundScheduler

import smtplib
from email.message import EmailMessage

import requests

import snds_db
import plugin_store


def create_app():
    app = Flask(__name__)
    app.secret_key = os.getenv("APP_SECRET_KEY", "dev-secret-change-me")

    # Simple in-memory user store for now; extend to DB later.
    admin_user = os.getenv("APP_ADMIN_USER", "admin")
    admin_pass = os.getenv("APP_ADMIN_PASS")
    if admin_pass:
        admin_hash = generate_password_hash(admin_pass)
    else:
        # For local dev convenience only
        admin_hash = generate_password_hash("admin")

    # Background scheduler
    scheduler = BackgroundScheduler(timezone=os.getenv("TZ", "UTC"))
    scheduler.start()
    # Plugin configuration persisted in plugins.db
    DEFAULT_SNDS_CONFIG = {
        "enabled": True,
        "schedule": {
            "enabled": False,
            "interval_minutes": int(os.getenv("APP_DEFAULT_INTERVAL_MIN", "60")),
        },
        "alerts": {
            "enabled": True,
            "complaint_rate_threshold": 0.1,  # percent
            "trap_hits_threshold": 1,
            "filter_levels": ["YELLOW", "RED"],
        },
        "delivery": {
            "email": {"enabled": False, "recipients": ""},
            "slack": {"enabled": False, "webhook_url": ""},
            "teams": {"enabled": False, "webhook_url": ""},
            "message_template": (
                "SNDS alert for {ip}: complaints={complaint_rate}% traps={trap_hits} "
                "filter={filter_result} window {activity_start}→{activity_end}"
            ),
        },
    }
    # Ensure defaults exist
    _ = plugin_store.load_plugin("snds", DEFAULT_SNDS_CONFIG)

    # Placeholder News plugin config
    DEFAULT_NEWS_CONFIG = {
        "enabled": False,
        "schedule": {
            "enabled": False,
            "interval_minutes": 60,
        },
        "alerts": {
            "enabled": True,
            "keywords": "",
            "sources": "",  # comma-separated domains or feeds
        },
        "delivery": {
            "email": {"enabled": False, "recipients": ""},
            "slack": {"enabled": False, "webhook_url": ""},
            "teams": {"enabled": False, "webhook_url": ""},
            "message_template": (
                "News alert: {title} — {url}"
            ),
        },
    }
    _ = plugin_store.load_plugin("news", DEFAULT_NEWS_CONFIG)

    def is_logged_in():
        return session.get("user") == admin_user

    def login_required(fn):
        from functools import wraps

        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not is_logged_in():
                return redirect(url_for("login", next=request.path))
            return fn(*args, **kwargs)

        return wrapper

    def evaluate_and_notify():
        """Evaluate SNDS alerts and send notifications as configured."""
        cfg = plugin_store.load_plugin("snds", DEFAULT_SNDS_CONFIG)
        if not cfg.get("enabled"):
            app.logger.info("Plugin disabled; skipping evaluation")
            return
        if not cfg["alerts"].get("enabled"):
            app.logger.info("Alerts disabled; skipping evaluation")
            return
        # Fetch recent rows and evaluate per IP (latest entries preferred)
        alerts = []
        seen_ips = set()
        try:
            cur = sqlite3.connect(snds_db.DB_PATH).cursor()
            cur.execute(
                """
                SELECT ip_address, activity_start, activity_end,
                       complaint_rate, trap_hits, filter_result
                FROM data_feed
                ORDER BY activity_end DESC
                LIMIT 1000
                """
            )
            rows = cur.fetchall()
        except Exception as e:
            app.logger.exception("Failed to load data_feed for alerts: %s", e)
            rows = []

        for r in rows:
            ip, astart, aend, complaint_text, trap_hits, filter_result = r
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
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
                alerts.append(
                    {
                        "ip": ip,
                        "activity_start": astart,
                        "activity_end": aend,
                        "complaint_rate": comp_val,
                        "trap_hits": hit_val,
                        "filter_result": filt,
                    }
                )

        if not alerts:
            app.logger.info("No alerts triggered")
            return

        # Compose and send using methods configured
        delivery = cfg.get("delivery", {})
        template = delivery.get("message_template", DEFAULT_SNDS_CONFIG["delivery"]["message_template"])
        message_lines = []
        for item in alerts:
            try:
                message_lines.append(template.format(**item))
            except Exception:
                message_lines.append(
                    f"SNDS alert for {item['ip']}: complaints={item['complaint_rate']}% "
                    f"traps={item['trap_hits']} filter={item['filter_result']}"
                )
        full_message = "\n".join(message_lines)

        if delivery.get("email", {}).get("enabled"):
            _send_email_alert(delivery.get("email", {}).get("recipients", ""), full_message)
        if delivery.get("slack", {}).get("enabled"):
            _send_slack_alert(delivery.get("slack", {}).get("webhook_url", ""), full_message)
        if delivery.get("teams", {}).get("enabled"):
            _send_teams_alert(delivery.get("teams", {}).get("webhook_url", ""), full_message)

    def _send_email_alert(to_addresses: str, body: str):
        emails = [e.strip() for e in (to_addresses or "").split(",") if e.strip()]
        if not emails:
            app.logger.warning("Email method enabled but no recipients configured")
            return
        host = os.getenv("SMTP_HOST")
        port = int(os.getenv("SMTP_PORT", "587"))
        user = os.getenv("SMTP_USER")
        pwd = os.getenv("SMTP_PASS")
        sender = os.getenv("SMTP_FROM", user or "alerts@example.com")
        if not host or not user or not pwd:
            app.logger.warning("SMTP not fully configured; skipping email send")
            return
        msg = EmailMessage()
        msg["Subject"] = "SNDS Alerts"
        msg["From"] = sender
        msg["To"] = ", ".join(emails)
        msg.set_content(body)
        try:
            with smtplib.SMTP(host, port, timeout=20) as s:
                s.starttls()
                s.login(user, pwd)
                s.send_message(msg)
            app.logger.info("Email alerts sent to %s", emails)
        except Exception as e:
            app.logger.exception("Failed to send email alerts: %s", e)

    def _send_slack_alert(webhook_url: str, body: str):
        if not webhook_url:
            app.logger.warning("Slack method enabled but webhook URL missing")
            return
        try:
            resp = requests.post(webhook_url, json={"text": body}, timeout=10)
            if resp.status_code >= 300:
                app.logger.warning("Slack webhook failed: %s %s", resp.status_code, resp.text)
            else:
                app.logger.info("Slack alert posted")
        except Exception as e:
            app.logger.exception("Slack alert error: %s", e)

    def _send_teams_alert(webhook_url: str, body: str):
        if not webhook_url:
            app.logger.warning("Teams method enabled but webhook URL missing")
            return
        try:
            # Teams incoming webhook accepts connector card JSON; minimal payload with text works for simple messages
            resp = requests.post(webhook_url, json={"text": body}, timeout=10)
            if resp.status_code >= 300:
                app.logger.warning("Teams webhook failed: %s %s", resp.status_code, resp.text)
            else:
                app.logger.info("Teams alert posted")
        except Exception as e:
            app.logger.exception("Teams alert error: %s", e)

    def ingest_and_alert():
        # Run the SNDS ingest using existing module
        try:
            snds_db.main()
        except Exception as e:
            app.logger.exception("Ingest failed: %s", e)
            return
        # Evaluate alert rules
        evaluate_and_notify()

    # Ephemeral runtime state
    schedule_state = {"job_id": None, "last_run_at": None}

    def reschedule_job():
        job_id = schedule_state.get("job_id") or "snds_ingest_job"
        # Remove existing
        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)
        cfg = plugin_store.load_plugin("snds", DEFAULT_SNDS_CONFIG)
        if cfg.get("enabled") and cfg["schedule"].get("enabled"):
            scheduler.add_job(
                ingest_and_alert,
                "interval",
                minutes=max(1, int(cfg["schedule"].get("interval_minutes", 60))),
                id=job_id,
                replace_existing=True,
                jitter=30,
            )
            schedule_state["job_id"] = job_id
    # Ensure scheduler reflects persisted settings on startup
    reschedule_job()

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if username == admin_user and check_password_hash(admin_hash, password):
                session["user"] = admin_user
                return redirect(url_for("dashboard"))
            flash("Invalid credentials", "error")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.pop("user", None)
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def dashboard():
        snds_cfg = plugin_store.load_plugin("snds", DEFAULT_SNDS_CONFIG)
        news_cfg = plugin_store.load_plugin("news", DEFAULT_NEWS_CONFIG)
        return render_template(
            "dashboard.html",
            schedule_job=schedule_state,
            has_key=bool(os.getenv("SNDS_KEY")),
            snds_cfg=snds_cfg,
            news_cfg=news_cfg,
        )

    @app.route("/plugins/snds/schedule", methods=["POST"])
    @login_required
    def update_schedule():
        cfg = plugin_store.load_plugin("snds", DEFAULT_SNDS_CONFIG)
        try:
            interval = int(request.form.get("interval_minutes", cfg["schedule"]["interval_minutes"]))
        except Exception:
            interval = cfg["schedule"]["interval_minutes"]
        enabled = request.form.get("enabled") == "on"
        cfg["schedule"]["interval_minutes"] = max(1, interval)
        cfg["schedule"]["enabled"] = enabled
        plugin_store.save_plugin("snds", cfg)
        reschedule_job()
        flash("SNDS schedule updated", "success")
        return redirect(url_for("dashboard"))

    @app.route("/run-now", methods=["POST"])
    @login_required
    def run_now():
        cfg = plugin_store.load_plugin("snds", DEFAULT_SNDS_CONFIG)
        if not cfg.get("enabled"):
            flash("SNDS plugin is disabled", "error")
            return redirect(url_for("dashboard"))
        ingest_and_alert()
        schedule_state["last_run_at"] = datetime.utcnow().isoformat()
        flash("Ingest triggered", "success")
        return redirect(url_for("dashboard"))

    @app.route("/plugins/snds/alerts", methods=["POST"])
    @login_required
    def update_snds_alerts():
        cfg = plugin_store.load_plugin("snds", DEFAULT_SNDS_CONFIG)
        enabled = request.form.get("alerts_enabled") == "on"
        try:
            comp_thresh = float(request.form.get("complaint_rate_threshold", cfg["alerts"]["complaint_rate_threshold"]))
        except Exception:
            comp_thresh = cfg["alerts"]["complaint_rate_threshold"]
        try:
            trap_thresh = int(request.form.get("trap_hits_threshold", cfg["alerts"]["trap_hits_threshold"]))
        except Exception:
            trap_thresh = cfg["alerts"]["trap_hits_threshold"]
        levels = []
        if request.form.get("level_yellow") == "on":
            levels.append("YELLOW")
        if request.form.get("level_red") == "on":
            levels.append("RED")
        cfg["alerts"].update({
            "enabled": enabled,
            "complaint_rate_threshold": comp_thresh,
            "trap_hits_threshold": trap_thresh,
            "filter_levels": levels,
        })
        plugin_store.save_plugin("snds", cfg)
        flash("SNDS alert rules saved", "success")
        return redirect(url_for("dashboard"))

    @app.route("/plugins/snds/delivery", methods=["POST"])
    @login_required
    def update_snds_delivery():
        cfg = plugin_store.load_plugin("snds", DEFAULT_SNDS_CONFIG)
        email_enabled = request.form.get("method_email") == "on"
        slack_enabled = request.form.get("method_slack") == "on"
        teams_enabled = request.form.get("method_teams") == "on"
        email_recipients = request.form.get("email_recipients", "").strip()
        slack_webhook_url = request.form.get("slack_webhook_url", "").strip()
        teams_webhook_url = request.form.get("teams_webhook_url", "").strip()
        message_template = request.form.get("message_template", cfg["delivery"]["message_template"]).strip()
        cfg["delivery"]["email"]["enabled"] = email_enabled
        cfg["delivery"]["email"]["recipients"] = email_recipients
        cfg["delivery"]["slack"]["enabled"] = slack_enabled
        cfg["delivery"]["slack"]["webhook_url"] = slack_webhook_url
        cfg["delivery"]["teams"]["enabled"] = teams_enabled
        cfg["delivery"]["teams"]["webhook_url"] = teams_webhook_url
        cfg["delivery"]["message_template"] = message_template
        plugin_store.save_plugin("snds", cfg)
        flash("SNDS delivery settings saved", "success")
        return redirect(url_for("dashboard"))

    @app.route("/plugins/snds/enable", methods=["POST"])
    @login_required
    def update_snds_enabled():
        cfg = plugin_store.load_plugin("snds", DEFAULT_SNDS_CONFIG)
        cfg["enabled"] = request.form.get("plugin_enabled") == "on"
        plugin_store.save_plugin("snds", cfg)
        reschedule_job()
        flash("SNDS plugin toggled", "success")
        return redirect(url_for("dashboard"))

    # News plugin placeholders — config only, no jobs yet
    @app.route("/plugins/news/enable", methods=["POST"])
    @login_required
    def update_news_enabled():
        cfg = plugin_store.load_plugin("news", DEFAULT_NEWS_CONFIG)
        cfg["enabled"] = request.form.get("plugin_enabled") == "on"
        plugin_store.save_plugin("news", cfg)
        flash("News plugin toggled", "success")
        return redirect(url_for("dashboard"))

    @app.route("/plugins/news/schedule", methods=["POST"])
    @login_required
    def update_news_schedule():
        cfg = plugin_store.load_plugin("news", DEFAULT_NEWS_CONFIG)
        try:
            interval = int(request.form.get("interval_minutes", cfg["schedule"]["interval_minutes"]))
        except Exception:
            interval = cfg["schedule"]["interval_minutes"]
        enabled = request.form.get("enabled") == "on"
        cfg["schedule"]["interval_minutes"] = max(1, interval)
        cfg["schedule"]["enabled"] = enabled
        plugin_store.save_plugin("news", cfg)
        flash("News schedule saved (placeholder)", "success")
        return redirect(url_for("dashboard"))

    @app.route("/plugins/news/alerts", methods=["POST"])
    @login_required
    def update_news_alerts():
        cfg = plugin_store.load_plugin("news", DEFAULT_NEWS_CONFIG)
        cfg["alerts"]["enabled"] = request.form.get("alerts_enabled") == "on"
        cfg["alerts"]["keywords"] = request.form.get("keywords", cfg["alerts"].get("keywords", "")).strip()
        cfg["alerts"]["sources"] = request.form.get("sources", cfg["alerts"].get("sources", "")).strip()
        plugin_store.save_plugin("news", cfg)
        flash("News alert rules saved (placeholder)", "success")
        return redirect(url_for("dashboard"))

    @app.route("/plugins/news/delivery", methods=["POST"])
    @login_required
    def update_news_delivery():
        cfg = plugin_store.load_plugin("news", DEFAULT_NEWS_CONFIG)
        email_enabled = request.form.get("method_email") == "on"
        slack_enabled = request.form.get("method_slack") == "on"
        teams_enabled = request.form.get("method_teams") == "on"
        email_recipients = request.form.get("email_recipients", "").strip()
        slack_webhook_url = request.form.get("slack_webhook_url", "").strip()
        teams_webhook_url = request.form.get("teams_webhook_url", "").strip()
        message_template = request.form.get("message_template", cfg["delivery"]["message_template"]).strip()
        cfg["delivery"]["email"]["enabled"] = email_enabled
        cfg["delivery"]["email"]["recipients"] = email_recipients
        cfg["delivery"]["slack"]["enabled"] = slack_enabled
        cfg["delivery"]["slack"]["webhook_url"] = slack_webhook_url
        cfg["delivery"]["teams"]["enabled"] = teams_enabled
        cfg["delivery"]["teams"]["webhook_url"] = teams_webhook_url
        cfg["delivery"]["message_template"] = message_template
        plugin_store.save_plugin("news", cfg)
        flash("News delivery settings saved (placeholder)", "success")
        return redirect(url_for("dashboard"))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
