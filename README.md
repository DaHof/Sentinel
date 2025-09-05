# Sentinel
Your always-on watchdog for platform updates, deliverability shifts, and consent compliance changes. Filters the noise. Flags what matters. Summarizes it for marketers, devs, and strategy leads.

## SNDS Data Capture
`snds_db.py` demonstrates how to pull daily metrics and IP status from Microsoft's Sender Support (SNDS) endpoints and store them in a SQLite database.  Sample complaint or trap messages are parsed so the recipient (`To` header) and full message are recorded for audit purposes.

Create a `.env` file by copying `.env.example` and set the `SNDS_KEY` (and optionally `SNDS_DB_PATH`) values. The script loads this file automatically when run.

Run:

```bash
python snds_db.py
```

This will create `snds.db` with tables for daily metrics, IP status, and sample messages including recipient data and the full message receipt.
