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
                raise RuntimeError("BaseScan denied the request")
            return text
        except Exception as e:
            last = str(e)
            time.sleep(min(8, 0.8 * (attempt + 1)))
    raise RuntimeError(last or "BaseScan request failed")


def init_session(wallet):
    url = f"{BASESCAN}/token/{BTN}?a={urllib.parse.quote(wallet)}"
    html = fetch_html(url)
    patterns = [r"var\s+sid\s*=\s*['\"]([^'\"]+)['\"]",
                r"\bsid\s*=\s*['\"]([^'\"]+)['\"]",
                r"[?&]sid=([A-Za-z0-9_-]+)"]
    sid = ""
    for pat in patterns:
        m = re.search(pat, html, re.I)
        if m:
            sid = m.group(1)
            break
    if not sid:
        raise RuntimeError("Could not obtain BaseScan session SID. BaseScan may have changed its page format.")
    return sid, url


def fetch_transfer_page(wallet, sid, page, page_size=100):
    params = {"m": "normal", "contractAddress": BTN, "a": wallet, "sid": sid,
              "p": str(page), "ps": str(page_size)}
    url = BASESCAN + "/token/generic-tokentxns2?" + urllib.parse.urlencode(params)
    referer = f"{BASESCAN}/token/{BTN}?a={wallet}"
    return fetch_html(url, referer=referer)


def load_settings():
    with settings_lock:
        try:
            data = json.loads(SETTINGS_FILE.read_text("utf-8"))
        except Exception:
            data = {}
        merged = dict(DEFAULT_SETTINGS)
        if isinstance(data, dict):
            merged.update(data)
        return merged


def save_settings(data):
    with settings_lock:
        current = load_settings_unlocked()
        current.update(data)
        tmp = SETTINGS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(current, indent=2), "utf-8")
        tmp.replace(SETTINGS_FILE)
        return current


def load_settings_unlocked():
    try:
        data = json.loads(SETTINGS_FILE.read_text("utf-8"))
    except Exception:
        data = {}
    merged = dict(DEFAULT_SETTINGS)
    if isinstance(data, dict):
        merged.update(data)
    return merged


def read_history():
    try:
        data = json.loads(HISTORY_FILE.read_text("utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def add_history(item):
    with report_lock:
        history = read_history()
        history.insert(0, item)
        HISTORY_FILE.write_text(json.dumps(history[:100], indent=2), "utf-8")


def check_admin(headers):
    expected = os.environ.get("ADMIN_API_KEY", "").strip()
    auth = headers.get("Authorization", "")
    supplied = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    return bool(expected) and bool(supplied) and hmac.compare_digest(supplied, expected)


def fetch_pool_swaps(start_date, end_date):
    collected = {}
    cursor = None
    indexed_block = None
    indexing_errors = False
    page = 0
    while True:
        page += 1
        if page > 10000:
            raise RuntimeError("Safety stop: pool query exceeded 10,000 pages. Narrow the date range.")
        params = {"start": start_date, "end": end_date, "limit": "1000"}
        if cursor:
            params["cursor"] = cursor
        url = POOL_WORKER_URL + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"User-Agent": "BTN-Analyzer-V35/1.0", "Cache-Control": "no-cache"})
        with urllib.request.urlopen(req, timeout=90) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not payload.get("ok"):
            raise RuntimeError(payload.get("error") or "Cloudflare Worker returned an error")
        indexed_block = payload.get("indexedBlock", indexed_block)
        indexing_errors = bool(payload.get("indexingErrors", indexing_errors))
        for swap in payload.get("swaps") or []:
            key = swap.get("id") or f"{swap.get('transaction', '')}:{swap.get('logIndex', '')}"
            if key:
                collected[key] = swap
        if not payload.get("hasMore"):
            break
        cursor = payload.get("nextCursor")
        if not cursor:
            raise RuntimeError("Worker reports more data but did not return nextCursor. Pagination cannot safely continue.")
        time.sleep(0.12)
    swaps = sorted(collected.values(), key=lambda x: str(x.get("date", "")))
    return swaps, indexed_block, indexing_errors


def get_google_credentials():
    raw = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "").strip()
    if not raw:
        encoded = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON_BASE64", "").strip()
        if encoded:
            raw = base64.b64decode(encoded).decode("utf-8")
    if not raw:
        raise RuntimeError("Google CRM connection is not configured. Add GOOGLE_SERVICE_ACCOUNT_JSON to the V35 backend environment.")
    try:
        info = json.loads(raw)
    except Exception as e:
        raise RuntimeError("GOOGLE_SERVICE_ACCOUNT_JSON is not valid JSON: " + str(e))
    try:
        from google.oauth2 import service_account
        from google.auth.transport.requests import AuthorizedSession
        creds = service_account.Credentials.from_service_account_info(
            info, scopes=["https://www.googleapis.com/auth/spreadsheets.readonly"])
        return AuthorizedSession(creds)
    except Exception as e:
        raise RuntimeError("Could not initialize Google Sheets credentials: " + str(e))


def load_crm():
    session = get_google_credentials()
    encoded_range = urllib.parse.quote(SHEET_RANGE, safe="")
    url = f"https://sheets.googleapis.com/v4/spreadsheets/{SHEET_ID}/values/{encoded_range}"
    response = session.get(url, params={"valueRenderOption": "FORMATTED_VALUE"}, timeout=60)
    if response.status_code != 200:
        detail = ""
        try:
            detail = response.json().get("error", {}).get("message", "")
        except Exception:
            detail = response.text[:300]
        raise RuntimeError(f"Google Sheets read failed ({response.status_code}). Confirm the service-account email has Viewer access to the CRM. {detail}")
    values = response.json().get("values", [])
    if not values:
        raise RuntimeError("The CRM Wallets tab returned no data.")
    headers = [str(x).strip() for x in values[0]]
    records = {}
    for row in values[1:]:
        row = list(row) + [""] * max(0, len(headers) - len(row))
        item = {headers[i]: (str(row[i]).strip() if i < len(row) else "") for i in range(len(headers))}
        wallet = item.get("Wallet (full address)", "").lower()
        if re.fullmatch(r"0x[a-f0-9]{40}", wallet):
            records[wallet] = item
    return records, len(values) - 1


def wallet_stats(swaps):
    stats = {}
    for swap in swaps:
        wallet = str(swap.get("wallet") or "").lower()
        if not re.fullmatch(r"0x[a-f0-9]{40}", wallet) or wallet in KNOWN_ROUTE_CONTRACTS:
            continue
        kind = str(swap.get("type") or "").upper()
        item = stats.setdefault(wallet, {"wallet": wallet, "buy_btn": 0.0, "sell_btn": 0.0,
                                         "buy_usdc": 0.0, "sell_usdc": 0.0,
                                         "buy_swaps": 0, "sell_swaps": 0})
        btn = float(swap.get("btnAmount") or 0)
        usdc = float(swap.get("usdcAmount") or 0)
        if kind == "BUY":
            item["buy_btn"] += btn
            item["buy_usdc"] += usdc
            item["buy_swaps"] += 1
        elif kind == "SELL":
            item["sell_btn"] += btn
            item["sell_usdc"] += usdc
            item["sell_swaps"] += 1
    return stats


def classify_wallet(wallet, crm):
    found = crm.get(wallet.lower())
    if not found:
        return {"wallet": wallet, "account": "", "team": "", "leader": "",
                "type": "External", "group": "Unidentified: not in the CRM", "frozen": "",
                "registered": "", "web_app": "", "in_crm": False}
    return {"wallet": wallet,
            "account": found.get("Account", ""),
            "team": found.get("Team", ""),
            "leader": found.get("Leader", ""),
            "type": found.get("Type", "") or "Unclassified (CRM)",
            "group": found.get("Group (for the report)", "") or found.get("Team", "") or found.get("Account", "") or "CRM wallet (no group)",
            "frozen": found.get("Frozen", ""),
            "registered": found.get("Registered in the app", ""),
            "web_app": found.get("Used the web app", ""),
            "in_crm": True}


def build_report_data(start_date, end_date):
    swaps, indexed_block, indexing_errors = fetch_pool_swaps(start_date, end_date)
    if not swaps:
        raise RuntimeError("No pool swaps were found for the selected date range.")
    crm, crm_rows = load_crm()
    stats = wallet_stats(swaps)
    enriched = []
    for wallet, item in stats.items():
        enriched.append({**item, **classify_wallet(wallet, crm)})
    buyers = sorted([x for x in enriched if x["buy_swaps"]], key=lambda x: x["buy_btn"], reverse=True)[:20]
    sellers = sorted([x for x in enriched if x["sell_swaps"]], key=lambda x: x["sell_btn"], reverse=True)[:20]

    groups = {}
    for item in enriched:
        key = item["group"]
        group = groups.setdefault(key, {"group": key, "type": item["type"], "wallets": 0,
                                         "buy_btn": 0.0, "sell_btn": 0.0,
                                         "buy_usdc": 0.0, "sell_usdc": 0.0,
                                         "buy_swaps": 0, "sell_swaps": 0})
        group["wallets"] += 1
        for field in ("buy_btn", "sell_btn", "buy_usdc", "sell_usdc", "buy_swaps", "sell_swaps"):
            group[field] += item[field]
    total_sell_usdc = sum(x["sell_usdc"] for x in enriched)
    total_buy_usdc = sum(x["buy_usdc"] for x in enriched)
    group_rows = sorted(groups.values(), key=lambda x: x["sell_usdc"], reverse=True)
    for group in group_rows:
        group["sell_share"] = (group["sell_usdc"] / total_sell_usdc * 100) if total_sell_usdc else 0
        group["buy_share"] = (group["buy_usdc"] / total_buy_usdc * 100) if total_buy_usdc else 0

    unknown = [x for x in enriched if not x["in_crm"]]
    buyers = [{**x, "rank": i + 1} for i, x in enumerate(buyers)]
    sellers = [{**x, "rank": i + 1} for i, x in enumerate(sellers)]
    result = {
        "start_date": start_date, "end_date": end_date,
        "swap_count": len(swaps), "wallet_count": len(enriched),
        "buy_count": sum(1 for s in swaps if str(s.get("type", "")).upper() == "BUY"),
        "sell_count": sum(1 for s in swaps if str(s.get("type", "")).upper() == "SELL"),
        "buy_btn": sum(x["buy_btn"] for x in enriched),
        "sell_btn": sum(x["sell_btn"] for x in enriched),
        "buy_usdc": total_buy_usdc, "sell_usdc": total_sell_usdc,
        "net_btn": sum(x["buy_btn"] - x["sell_btn"] for x in enriched),
        "indexed_block": indexed_block, "indexing_errors": indexing_errors,
        "crm_rows": crm_rows, "crm_wallets_matched": sum(1 for x in enriched if x["in_crm"]),
        "crm_wallets_unmatched": len(unknown),
        "buyers": buyers, "sellers": sellers, "groups": group_rows,
        "unknown_wallets": sorted(unknown, key=lambda x: x["buy_usdc"] + x["sell_usdc"], reverse=True)[:100],
    }
    return result


def money(value, digits=2):
    return f"{float(value or 0):,.{digits}f}"


def generate_pdf(report, report_id):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    except Exception as e:
        raise RuntimeError("PDF engine is not installed: " + str(e))
    path = REPORTS_DIR / f"{report_id}.pdf"
    doc = SimpleDocTemplate(str(path), pagesize=landscape(A4), rightMargin=12*mm,
                            leftMargin=12*mm, topMargin=12*mm, bottomMargin=12*mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallCell", parent=styles["BodyText"], fontSize=7, leading=8))
    story = [Paragraph("BTN Price Influence Report", styles["Title"]),
             Paragraph(f"BTN/USDC Pool · {report['start_date']} to {report['end_date']}", styles["Heading2"]),
             Spacer(1, 5*mm)]
    metrics = [
        ["Total swaps", "Buy swaps", "Sell swaps", "Trader wallets", "CRM matched", "Not in CRM"],
        [f"{report['swap_count']:,}", f"{report['buy_count']:,}", f"{report['sell_count']:,}",
         f"{report['wallet_count']:,}", f"{report['crm_wallets_matched']:,}", f"{report['crm_wallets_unmatched']:,}"],
        ["BTN bought", "BTN sold", "Net BTN flow", "Buy volume (USDC)", "Sell volume (USDC)", "Indexed block"],
        [money(report["buy_btn"], 4), money(report["sell_btn"], 4), money(report["net_btn"], 4),
         money(report["buy_usdc"]), money(report["sell_usdc"]), str(report.get("indexed_block") or "—")],
    ]
    t = Table(metrics, colWidths=[doc.width/6]*6)
    t.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e8edf4")),
                           ("BACKGROUND", (0,2), (-1,2), colors.HexColor("#e8edf4")),
                           ("GRID", (0,0), (-1,-1), .4, colors.HexColor("#c8d0dc")),
                           ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
                           ("FONTSIZE", (0,0), (-1,-1), 8),
                           ("FONTNAME", (0,1), (-1,1), "Helvetica-Bold"),
                           ("FONTNAME", (0,3), (-1,3), "Helvetica-Bold"),
                           ("PADDING", (0,0), (-1,-1), 6)]))
    story += [t, Spacer(1, 6*mm)]

    def add_table(title, headers, rows, widths=None):
        story.append(Paragraph(title, styles["Heading2"]))
        data = [[Paragraph(str(h), styles["SmallCell"]) for h in headers]]
        for row in rows:
            data.append([Paragraph(str(v if v is not None else ""), styles["SmallCell"]) for v in row])
        tbl = Table(data, repeatRows=1, colWidths=widths)
        tbl.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e8edf4")),
                                 ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#c8d0dc")),
                                 ("VALIGN", (0,0), (-1,-1), "TOP"),
                                 ("FONTSIZE", (0,0), (-1,-1), 7),
                                 ("PADDING", (0,0), (-1,-1), 4)]))
        story.append(tbl)
        story.append(Spacer(1, 4*mm))

    buyer_rows = [[x["rank"], x["wallet"], money(x["buy_btn"], 4), money(x["buy_usdc"]), x["buy_swaps"],
                   x["type"], x["group"], x["account"], x["leader"]] for x in report["buyers"]]
    seller_rows = [[x["rank"], x["wallet"], money(x["sell_btn"], 4), money(x["sell_usdc"]), x["sell_swaps"],
                    x["type"], x["group"], x["account"], x["leader"]] for x in report["sellers"]]
    add_table("Top 20 Buyer Wallets", ["#", "Wallet", "BTN bought", "USDC spent", "Swaps", "Type", "Group", "Account", "Leader"], buyer_rows,
              [9*mm, 40*mm, 20*mm, 20*mm, 12*mm, 18*mm, 48*mm, 22*mm, 30*mm])
    add_table("Top 20 Seller Wallets", ["#", "Wallet", "BTN sold", "USDC received", "Swaps", "Type", "Group", "Account", "Leader"], seller_rows,
              [9*mm, 40*mm, 20*mm, 22*mm, 12*mm, 18*mm, 48*mm, 22*mm, 30*mm])
    group_rows = [[x["group"], x["type"], x["wallets"], money(x["buy_btn"], 4), money(x["sell_btn"], 4),
                   money(x["buy_usdc"]), money(x["sell_usdc"]), f"{x['sell_share']:.2f}%"] for x in report["groups"]]
    add_table("Buying and Selling Pressure by CRM Group", ["Group", "Type", "Wallets", "BTN bought", "BTN sold", "USDC spent", "USDC received", "Sell share"], group_rows,
              [53*mm, 20*mm, 15*mm, 22*mm, 22*mm, 22*mm, 25*mm, 18*mm])
    unknown_rows = [[x["wallet"], money(x["buy_btn"], 4), money(x["sell_btn"], 4), money(x["buy_usdc"]), money(x["sell_usdc"])]
                    for x in report["unknown_wallets"]]
    if unknown_rows:
        add_table("Wallets Not Found in CRM (top 100 by activity)", ["Wallet", "BTN bought", "BTN sold", "USDC spent", "USDC received"], unknown_rows,
                  [65*mm, 25*mm, 25*mm, 25*mm, 30*mm])
    note = "CRM source: CRM Wallets tab, read-only. External means the wallet was not found in the CRM."
    if report.get("indexing_errors"):
        note += " WARNING: The Graph subgraph reported indexing errors for this query."
    story.append(Paragraph(note, styles["Italic"]))
    doc.build(story)
    return path


def send_telegram_document(path, caption):
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        raise RuntimeError("Telegram is not configured. Add TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to the V35 backend environment.")
    boundary = "----BTNReportBoundary7MA4YWxkTrZu0gW"
    filename = path.name
    with open(path, "rb") as f:
        file_data = f.read()
    body = bytearray()
    def field(name, value):
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        body.extend(str(value).encode())
        body.extend(b"\r\n")
    field("chat_id", chat_id)
    field("caption", caption[:900])
    body.extend(f"--{boundary}\r\n".encode())
    body.extend(f'Content-Disposition: form-data; name="document"; filename="{filename}"\r\n'.encode())
    body.extend(b"Content-Type: application/pdf\r\n\r\n")
    body.extend(file_data)
    body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendDocument", data=bytes(body),
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}, method="POST")
    with urllib.request.urlopen(req, timeout=90) as response:
        result = json.loads(response.read().decode("utf-8"))
    if not result.get("ok"):
        raise RuntimeError(result.get("description", "Telegram sendDocument failed"))
    return True


def execute_report(start_date, end_date, send_telegram=False, report_type="Custom"):
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", start_date or "") or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", end_date or ""):
        raise RuntimeError("Dates must use YYYY-MM-DD format.")
    start = date.fromisoformat(start_date)
    end = date.fromisoformat(end_date)
    if start > end:
        raise RuntimeError("Start date cannot be after end date.")
    if (end - start).days > 366:
        raise RuntimeError("The maximum custom report range is 366 days.")
    report = build_report_data(start_date, end_date)
    report_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
    pdf_path = generate_pdf(report, report_id)
    sent = False
    telegram_error = ""
    if send_telegram:
        caption = f"{report_type} BTN Price Influence Report · {start_date} to {end_date} · {report['swap_count']:,} swaps"
        try:
            send_telegram_document(pdf_path, caption)
            sent = True
        except Exception as e:
            telegram_error = str(e)
    item = {"id": report_id, "type": report_type, "start_date": start_date, "end_date": end_date,
            "swap_count": report["swap_count"], "wallet_count": report["wallet_count"],
            "telegram_sent": sent, "telegram_error": telegram_error,
            "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "filename": pdf_path.name}
    add_history(item)
    return {"report_id": report_id, "filename": pdf_path.name, "download_path": f"/crm-report-file?id={report_id}",
            "telegram_sent": sent, "telegram_error": telegram_error,
            "summary": {k: report[k] for k in ["swap_count", "wallet_count", "buy_count", "sell_count", "crm_wallets_matched", "crm_wallets_unmatched", "buy_btn", "sell_btn", "buy_usdc", "sell_usdc"]}}


def scheduled_report(report_type, start_date, end_date, run_key):
    try:
        result = execute_report(start_date, end_date, True, report_type)
        if result.get("telegram_sent"):
            print(f"[SCHEDULER] {report_type} report sent: {result['filename']}")
        else:
            print(f"[SCHEDULER] {report_type} PDF generated but Telegram delivery failed: {result.get('telegram_error', 'unknown error')}")
    except Exception as e:
        print(f"[SCHEDULER] {report_type} report failed: {e}")
        add_history({"id": "failed-" + str(int(time.time())), "type": report_type,
                     "start_date": start_date, "end_date": end_date, "telegram_sent": False,
                     "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z", "error": str(e)})


def scheduler_loop():
    while True:
        try:
            cfg = load_settings()
            tz = ZoneInfo(cfg.get("timezone") or "America/Caracas")
            now = datetime.now(tz)
            hhmm = now.strftime("%H:%M")
            if hhmm == cfg.get("send_time", "09:00"):
                if cfg.get("weekly_enabled") and now.weekday() == WEEKDAYS.get(cfg.get("weekly_day"), 4):
                    key = now.strftime("%Y-%m-%d")
                    if cfg.get("last_weekly_run") != key:
                        yesterday = now.date() - timedelta(days=1)
                        start = yesterday - timedelta(days=6)
                        save_settings({"last_weekly_run": key})
                        threading.Thread(target=scheduled_report, args=("Weekly", start.isoformat(), yesterday.isoformat(), key), daemon=True).start()
                if cfg.get("monthly_enabled"):
                    day_value = str(cfg.get("monthly_day", "1"))
                    last_day = (now.date().replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
                    due = (day_value == "last" and now.date() == last_day) or (day_value != "last" and now.day == int(day_value))
                    key = now.strftime("%Y-%m")
                    if due and cfg.get("last_monthly_run") != key:
                        first_this = now.date().replace(day=1)
                        end = first_this - timedelta(days=1)
                        start = end.replace(day=1)
                        save_settings({"last_monthly_run": key})
                        threading.Thread(target=scheduled_report, args=("Monthly", start.isoformat(), end.isoformat(), key), daemon=True).start()
        except Exception as e:
            print("[SCHEDULER] loop error:", e)
        time.sleep(30)


class Handler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[HTTP]", fmt % args)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        super().end_headers()

    def send_json(self, obj, code=200):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_bytes(self, data, content_type, filename=None):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(data)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 2_000_000:
            raise RuntimeError("Request body is too large.")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(p.query)

        if p.path == "/health":
            self.send_json({"ok": True, "source": "BaseScan direct table", "version": "V35", "crm_reports": True})
            return

        # V34-compatible BaseScan endpoints.
        if p.path == "/basescan-init":
            wallet = (q.get("wallet") or [""])[0].strip()
            if not (wallet.startswith("0x") and len(wallet) == 42):
                self.send_json({"ok": False, "error": "Invalid wallet"}, 400)
                return
            try:
                sid, _ = init_session(wallet)
                self.send_json({"ok": True, "sid": sid})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, 502)
            return

        if p.path == "/basescan-page":
            wallet = (q.get("wallet") or [""])[0].strip()
            sid = (q.get("sid") or [""])[0].strip()
            try:
                page = max(1, int((q.get("page") or ["1"])[0]))
            except Exception:
                page = 1
            try:
                html = fetch_transfer_page(wallet, sid, page, 100)
                total = None
                for pat in [r"var\s+totaltxns\s*=\s*['\"]([\d,]+)['\"]",
                            r"\btotaltxns\s*=\s*['\"]([\d,]+)['\"]",
                            r"id=['\"]totaltxns['\"][^>]*>\s*([\d,]+)",
                            r"total\s+of\s+([\d,]+)\s+transactions"]:
                    m = re.search(pat, html, re.I)
                    if m:
                        try:
                            total = int(m.group(1).replace(",", ""))
                            break
                        except Exception:
                            pass
                total_pages = None
                for pat in [r"var\s+totalpages\s*=\s*['\"]?(\d+)", r"\btotalpages\s*=\s*['\"]?(\d+)", r"var\s+totalPages\s*=\s*['\"]?(\d+)"]:
                    m = re.search(pat, html, re.I)
                    if m:
                        try:
                            total_pages = int(m.group(1))
                            break
                        except Exception:
                            pass
                self.send_json({"ok": True, "page": page, "html": html, "total_txns": total, "total_pages": total_pages})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e), "page": page}, 502)
            return

        if p.path in ("/crm-config", "/crm-history"):
            if not check_admin(self.headers):
                self.send_json({"ok": False, "error": "Unauthorized. Check the V35 admin API key."}, 401)
                return
            if p.path == "/crm-config":
                cfg = load_settings()
                cfg.pop("last_weekly_run", None)
                cfg.pop("last_monthly_run", None)
                self.send_json({"ok": True, "settings": cfg})
            else:
                try:
                    limit = min(50, max(1, int((q.get("limit") or ["20"])[0])))
                except Exception:
                    limit = 20
                self.send_json({"ok": True, "history": read_history()[:limit]})
            return

        if p.path == "/crm-report-file":
            if not check_admin(self.headers):
                self.send_json({"ok": False, "error": "Unauthorized."}, 401)
                return
            report_id = (q.get("id") or [""])[0]
            if not re.fullmatch(r"\d{8}_\d{6}_\d+", report_id):
                self.send_json({"ok": False, "error": "Invalid report id."}, 400)
                return
            file_path = REPORTS_DIR / f"{report_id}.pdf"
            if not file_path.exists():
                self.send_json({"ok": False, "error": "Report file not found."}, 404)
                return
            self.send_bytes(file_path.read_bytes(), "application/pdf", file_path.name)
            return

        return super().do_GET()

    def do_POST(self):
        p = urllib.parse.urlparse(self.path)
        if p.path not in ("/crm-config", "/crm-report"):
            self.send_json({"ok": False, "error": "Not found"}, 404)
            return
        if not check_admin(self.headers):
            self.send_json({"ok": False, "error": "Unauthorized. Check the V35 admin API key."}, 401)
            return
        try:
            data = self.read_json()
            if p.path == "/crm-config":
                weekly_day = data.get("weekly_day", "Friday")
                monthly_day = str(data.get("monthly_day", "1"))
                send_time = data.get("send_time", "09:00")
                timezone = data.get("timezone", "America/Caracas")
                if weekly_day not in WEEKDAYS:
                    raise RuntimeError("Invalid weekly delivery day.")
                if monthly_day not in {"1", "5", "10", "15", "20", "25", "last"}:
                    raise RuntimeError("Invalid monthly delivery day.")
                if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", send_time):
                    raise RuntimeError("Delivery time must use HH:MM (24-hour format).")
                ZoneInfo(timezone)
                cfg = save_settings({"weekly_enabled": bool(data.get("weekly_enabled")),
                                     "weekly_day": weekly_day,
                                     "monthly_enabled": bool(data.get("monthly_enabled")),
                                     "monthly_day": monthly_day,
                                     "send_time": send_time,
                                     "timezone": timezone})
                cfg.pop("last_weekly_run", None)
                cfg.pop("last_monthly_run", None)
                self.send_json({"ok": True, "settings": cfg})
                return
            if p.path == "/crm-report":
                start_date = str(data.get("start_date", ""))
                end_date = str(data.get("end_date", ""))
                send = bool(data.get("send_telegram", False))
                result = execute_report(start_date, end_date, send, "Custom")
                self.send_json({"ok": True, **result})
                return
        except Exception as e:
            self.send_json({"ok": False, "error": str(e)}, 400)


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print("=" * 78)
    print(" BTN POOL & WALLET ANALYZER V35 - CRM REPORT MODULE")
    print(" Existing BaseScan endpoints preserved; CRM/Telegram features are additive.")
    print(" Listening on", HOST, PORT)
    print(" Pool Worker:", POOL_WORKER_URL)
    print("=" * 78)
    threading.Thread(target=scheduler_loop, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
