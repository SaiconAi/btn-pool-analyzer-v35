import base64
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
import http.cookiejar
import hmac
from xml.sax.saxutils import escape as xml_escape
from datetime import date, datetime, timedelta
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from zoneinfo import ZoneInfo

# ---------------------------------------------------------------------------
# V35 backend: V34 BaseScan endpoints are preserved; CRM reporting is additive.
# ---------------------------------------------------------------------------
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8765"))
BTN = "0x6C417845fACc97ebCE84FBfEE9A7460b0E5cfCf3"
BASESCAN = "https://basescan.org"
SHEET_ID = os.environ.get("GOOGLE_SHEET_ID", "1ZQDrHVckyG4tKPNSurzTKr72qUukT8YThG57JOjgQ7M")
SHEET_RANGE = "'CRM Wallets'!A:S"
KNOWN_ROUTE_CONTRACTS = {
    "0xc069bb46ba971c3bf5424fb505525db3006d8091",  # BTN/USDC pool
    "0x6c417845facc97ebce84fbfee9a7460b0e5cfcf3",  # BTN token
    "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",  # USDC on Base
    "0x2626664c2603336e57b271c5c0b26f421741e481",  # Uniswap Universal Router
}
POOL_WORKER_URL = os.environ.get("POOL_WORKER_URL", "https://btn-pool-api.luisedt.workers.dev")
DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
REPORTS_DIR = DATA_DIR / "reports"
SETTINGS_FILE = DATA_DIR / "report_settings.json"
HISTORY_FILE = DATA_DIR / "report_history.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

cookiejar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookiejar))
request_lock = threading.Lock()
last_request = 0.0
settings_lock = threading.Lock()
report_lock = threading.Lock()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
}

DEFAULT_SETTINGS = {
    "weekly_enabled": False,
    "weekly_day": "Friday",
    "monthly_enabled": False,
    "monthly_day": "1",
    "send_time": "09:00",
    "timezone": "America/Caracas",
    "last_weekly_run": "",
    "last_monthly_run": "",
}

WEEKDAYS = {"Monday": 0, "Tuesday": 1, "Wednesday": 2, "Thursday": 3,
            "Friday": 4, "Saturday": 5, "Sunday": 6}


def throttle(gap=0.18):
    global last_request
    with request_lock:
        now = time.time()
        wait = gap - (now - last_request)
        if wait > 0:
            time.sleep(wait)
        last_request = time.time()


def fetch_html(url, referer=None, retries=5):
    last = ""
    for attempt in range(retries):
        throttle()
        try:
            h = dict(HEADERS)
            if referer:
                h["Referer"] = referer
            req = urllib.request.Request(url, headers=h, method="GET")
            with opener.open(req, timeout=30) as resp:
                raw = resp.read()
            text = raw.decode("utf-8", "replace")
            low = text.lower()
            if "just a moment" in low and "cloudflare" in low:
                raise RuntimeError("BaseScan Cloudflare challenge received")
            if "access denied" in low:
