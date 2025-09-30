import os
import json
import re
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
from worker import run_senderscore


def get_env(name, default=None):
    value = os.getenv(name)
    if value is not None:
        return value
    lowered = name.lower()
    for key, val in os.environ.items():
        if key.lower() == lowered:
            return val
    return default


def create_app():
    app = Flask(__name__)

    app.secret_key = get_env("APP_SECRET_KEY", "dev-secret-change-me")

    # Simple in-memory user store for now; extend to DB later.
    admin_user = get_env("APP_ADMIN_USER", "admin")
    admin_pass = get_env("APP_ADMIN_PASS")
    if admin_pass:
        admin_hash = generate_password_hash(admin_pass)
    else:
        # For local dev convenience only
        admin_hash = generate_password_hash("admin")

    # Background scheduler (disabled by default; worker handles scheduling)
    SCHEDULER_MODE = get_env("APP_SCHEDULER_MODE", "worker").lower()
    scheduler = None
    if SCHEDULER_MODE == "web":
        scheduler = BackgroundScheduler(timezone=get_env("TZ", "UTC"))
        scheduler.start()
    # Plugin configuration persisted in plugins.db
    DEFAULT_SNDS_CONFIG = {
        "enabled": True,
        "schedule": {
            "enabled": False,
            "interval_minutes": int(get_env("APP_DEFAULT_INTERVAL_MIN", "60")),
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

    # SenderScore plugin config
    DEFAULT_SS_CONFIG = {
        "enabled": False,
        "schedule": {"enabled": False, "interval_minutes": 1440},
        "options": {
            "ip_source": "snds",  # "snds" or "manual"
            "manual_ips": "",     # comma or newline separated
        },
        "alerts": {
            "enabled": True,
            "change_threshold_percent": 5.0,
            "notify_on_measure_change": True,
            "reputation_low_to_other": True,
            "spam_trap_threshold": 0,
            "volume_avg_days": 7,
            "volume_change_threshold_percent": 20.0,
        },
        "delivery": {
            "email": {"enabled": False, "recipients": ""},
            "slack": {"enabled": False, "webhook_url": ""},
            "teams": {"enabled": False, "webhook_url": ""},
            "message_template": (
                "SenderScore alert {ip}: score {old_score} -> {new_score} (Δ{delta_percent}%), volume={volume}; reason: {reason}"
            ),
        },
    }
    _ = plugin_store.load_plugin("senderscore", DEFAULT_SS_CONFIG)

    # UI preferences: user-defined IP labels (name + color)
    DEFAULT_UI_CONFIG = {
        "ip_labels": [
            # {"ips": ["1.2.3.4", "1.2.3.5"], "name": "Brand A", "color": "#ff9900"}
            # Back-compat also supports {"ip": "1.2.3.4", ...}
        ]
    }
    _ = plugin_store.load_plugin("ui", DEFAULT_UI_CONFIG)

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

        # Persist individual alert lines for dashboard visibility
        methods_used = []
        if delivery.get("email", {}).get("enabled"):
            methods_used.append("email")
        if delivery.get("slack", {}).get("enabled"):
            methods_used.append("slack")
        if delivery.get("teams", {}).get("enabled"):
            methods_used.append("teams")
        methods_str = ",".join(methods_used)
        for idx, item in enumerate(alerts):
            line = message_lines[idx] if idx < len(message_lines) else str(item)
            meta = {
                "ip": item.get("ip"),
                "complaint_rate": item.get("complaint_rate"),
                "trap_hits": item.get("trap_hits"),
                "filter_result": item.get("filter_result"),
                "activity_start": item.get("activity_start"),
                "activity_end": item.get("activity_end"),
            }
            plugin_store.add_alert("snds", line, methods_str, meta)

    def _send_email_alert(to_addresses: str, body: str):
        emails = [e.strip() for e in (to_addresses or "").split(",") if e.strip()]
        if not emails:
            app.logger.warning("Email method enabled but no recipients configured")
            return
        host = get_env("SMTP_HOST")
        port = int(get_env("SMTP_PORT", "587"))
        user = get_env("SMTP_USER")
        pwd = get_env("SMTP_PASS")
        sender = get_env("SMTP_FROM", user or "alerts@example.com")
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
        if not scheduler:
            return
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
    if scheduler:
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
        ss_cfg = plugin_store.load_plugin("senderscore", DEFAULT_SS_CONFIG)
        ui_cfg = plugin_store.load_plugin("ui", DEFAULT_UI_CONFIG)
        recent_alerts = plugin_store.list_alerts(limit=20)
        snds_alerts = plugin_store.list_alerts_by_plugin("snds", limit=10)
        ss_alerts = plugin_store.list_alerts_by_plugin("senderscore", limit=10)
        # Load recent SenderScore rows for quick verification
        ss_latest = []
        try:
            cur = sqlite3.connect(snds_db.DB_PATH).cursor()
            cur.execute(
                "SELECT observed_at, ip, score, volume, measures FROM senderscore_daily ORDER BY observed_at DESC LIMIT 20"
            )
            ss_latest = cur.fetchall()
        except Exception:
            ss_latest = []
        # Build quick lookup map for IP labels
        ip_label_map = {}
        try:
            for item in (ui_cfg.get("ip_labels") or []):
                name = (item.get("name") or "").strip()
                color = (item.get("color") or "").strip()
                if not name or not color:
                    continue
                # New format: list of IPs
                if isinstance(item.get("ips"), list):
                    for ip in item.get("ips"):
                        sip = (ip or "").strip()
                        if sip:
                            ip_label_map[sip] = {"name": name, "color": color}
                else:
                    ip = (item.get("ip") or "").strip()
                    if ip:
                        ip_label_map[ip] = {"name": name, "color": color}
        except Exception:
            ip_label_map = {}
        return render_template(
            "dashboard.html",
            schedule_job=schedule_state,
            has_key=bool(get_env("SNDS_KEY")),
            snds_cfg=snds_cfg,
            news_cfg=news_cfg,
            ss_cfg=ss_cfg,
            ui_cfg=ui_cfg,
            ip_label_map=ip_label_map,
            recent_alerts=recent_alerts,
            snds_alerts=snds_alerts,
            ss_alerts=ss_alerts,
            ss_latest=ss_latest,
        )

    @app.route("/settings")
    @login_required
    def settings():
        ui_cfg = plugin_store.load_plugin("ui", DEFAULT_UI_CONFIG)
        return render_template(
            "settings.html",
            ui_cfg=ui_cfg,
        )

    @app.route("/plugins", methods=["GET"])
    @login_required
    def plugins_page():
        snds_cfg = plugin_store.load_plugin("snds", DEFAULT_SNDS_CONFIG)
        news_cfg = plugin_store.load_plugin("news", DEFAULT_NEWS_CONFIG)
        ss_cfg = plugin_store.load_plugin("senderscore", DEFAULT_SS_CONFIG)
        return render_template(
            "plugins.html",
            has_key=bool(get_env("SNDS_KEY")),
            schedule_job=schedule_state,
            snds_cfg=snds_cfg,
            news_cfg=news_cfg,
            ss_cfg=ss_cfg,
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

    # SenderScore plugin routes
    @app.route("/plugins/senderscore/enable", methods=["POST"])
    @login_required
    def update_ss_enabled():
        cfg = plugin_store.load_plugin("senderscore", DEFAULT_SS_CONFIG)
        cfg["enabled"] = request.form.get("plugin_enabled") == "on"
        plugin_store.save_plugin("senderscore", cfg)
        flash("SenderScore plugin toggled", "success")
        return redirect(url_for("dashboard"))

    @app.route("/plugins/senderscore/schedule", methods=["POST"])
    @login_required
    def update_ss_schedule():
        cfg = plugin_store.load_plugin("senderscore", DEFAULT_SS_CONFIG)
        try:
            interval = int(request.form.get("interval_minutes", cfg["schedule"]["interval_minutes"]))
        except Exception:
            interval = cfg["schedule"]["interval_minutes"]
        enabled = request.form.get("enabled") == "on"
        cfg["schedule"]["interval_minutes"] = max(1, interval)
        cfg["schedule"]["enabled"] = enabled
        plugin_store.save_plugin("senderscore", cfg)
        flash("SenderScore schedule saved", "success")
        return redirect(url_for("dashboard"))

    @app.route("/plugins/senderscore/alerts", methods=["POST"])
    @login_required
    def update_ss_alerts():
        cfg = plugin_store.load_plugin("senderscore", DEFAULT_SS_CONFIG)
        cfg["alerts"]["enabled"] = request.form.get("alerts_enabled") == "on"
        try:
            cfg["alerts"]["change_threshold_percent"] = float(
                request.form.get(
                    "change_threshold_percent", cfg["alerts"]["change_threshold_percent"]
                )
            )
        except Exception:
            pass
        cfg["alerts"]["notify_on_measure_change"] = (
            request.form.get("notify_on_measure_change") == "on"
        )
        cfg["alerts"]["reputation_low_to_other"] = (
            request.form.get("reputation_low_to_other") == "on"
        )
        try:
            cfg["alerts"]["spam_trap_threshold"] = int(
                request.form.get(
                    "spam_trap_threshold", cfg["alerts"].get("spam_trap_threshold", 0)
                )
            )
        except Exception:
            pass
        try:
            cfg["alerts"]["volume_avg_days"] = int(
                request.form.get(
                    "volume_avg_days", cfg["alerts"].get("volume_avg_days", 7)
                )
            )
        except Exception:
            pass
        try:
            cfg["alerts"]["volume_change_threshold_percent"] = float(
                request.form.get(
                    "volume_change_threshold_percent",
                    cfg["alerts"].get("volume_change_threshold_percent", 20.0),
                )
            )
        except Exception:
            pass
        # Options
        source = request.form.get("ip_source", cfg["options"]["ip_source"]) or "snds"
        manual_ips = request.form.get("manual_ips", cfg["options"].get("manual_ips", ""))
        cfg["options"]["ip_source"] = source
        cfg["options"]["manual_ips"] = manual_ips
        plugin_store.save_plugin("senderscore", cfg)
        flash("SenderScore alert rules saved", "success")
        return redirect(url_for("dashboard"))

    @app.route("/plugins/senderscore/delivery", methods=["POST"])
    @login_required
    def update_ss_delivery():
        cfg = plugin_store.load_plugin("senderscore", DEFAULT_SS_CONFIG)
        email_enabled = request.form.get("method_email") == "on"
        slack_enabled = request.form.get("method_slack") == "on"
        teams_enabled = request.form.get("method_teams") == "on"
        cfg["delivery"]["email"]["enabled"] = email_enabled
        cfg["delivery"]["email"]["recipients"] = request.form.get("email_recipients", "").strip()
        cfg["delivery"]["slack"]["enabled"] = slack_enabled
        cfg["delivery"]["slack"]["webhook_url"] = request.form.get("slack_webhook_url", "").strip()
        cfg["delivery"]["teams"]["enabled"] = teams_enabled
        cfg["delivery"]["teams"]["webhook_url"] = request.form.get("teams_webhook_url", "").strip()
        cfg["delivery"]["message_template"] = request.form.get(
            "message_template", cfg["delivery"]["message_template"]
        ).strip()
        plugin_store.save_plugin("senderscore", cfg)
        flash("SenderScore delivery settings saved", "success")
        return redirect(url_for("dashboard"))

    @app.route("/plugins/senderscore/run-now", methods=["POST"])
    @login_required
    def run_ss_now():
        cfg = plugin_store.load_plugin("senderscore", DEFAULT_SS_CONFIG)
        if not cfg.get("enabled"):
            flash("SenderScore plugin is disabled", "error")
            return redirect(url_for("dashboard"))
        try:
            run_senderscore()
            flash("SenderScore run triggered", "success")
        except Exception as e:
            app.logger.exception("SenderScore run failed: %s", e)
            flash("SenderScore run failed; check logs", "error")
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

    @app.route("/ui/ip-labels", methods=["POST"])
    @login_required
    def update_ip_labels():
        cfg = plugin_store.load_plugin("ui", DEFAULT_UI_CONFIG)
        labels: list[dict] = []
        # Prefer structured inputs (arrays) with multi-IP support
        ips_blocks = request.form.getlist("ips[]") or request.form.getlist("ip[]")
        names = request.form.getlist("name[]")
        colors = request.form.getlist("color[]")
        if ips_blocks or names or colors:
            for ips_block, name, color in zip(ips_blocks, names, colors):
                name = (name or "").strip()
                color = (color or "#888888").strip()
                raw = (ips_block or "").strip()
                # Split on comma or whitespace, support commas and newlines
                parts = [p.strip() for p in re.split(r"[\s,]+", raw) if p.strip()]
                if not parts or not name:
                    continue
                if color and not color.startswith("#"):
                    color = f"#{color}"
                labels.append({"ips": parts, "name": name, "color": color})
        else:
            # Back-compat: parse CSV textarea if provided
            text = request.form.get("ip_labels_text", "")
            for raw in text.splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 2:
                    continue
                ip = parts[0]
                name = parts[1]
                color = parts[2] if len(parts) >= 3 else "#888888"
                if color and not color.startswith("#"):
                    color = f"#{color}"
                labels.append({"ip": ip, "name": name, "color": color})
        cfg["ip_labels"] = labels
        plugin_store.save_plugin("ui", cfg)
        flash("IP labels saved", "success")
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
    app.run(host="0.0.0.0", port=int(get_env("PORT", "5000")))
