# === Mirror OS Pre-Beta Script v7.2 ===
# Flask server for Pre-Beta Ledger
# v7.2: Added STATUS-001 rule with minimal normalization

# --- Core Libraries ---
import os
import re
import json
import threading
import time
from datetime import datetime, timezone

# --- Third-Party Libraries ---
import requests
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from dotenv import load_dotenv
import pytz
import dateparser
import hmac
import logging

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('mirror_os.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- Global Config ---
STATE_FILE = "state.json"
load_dotenv()
app = Flask(__name__)

# --- Thread lock for state operations ---
state_lock = threading.Lock()

# --- Airtable ---
AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = os.getenv("AIRTABLE_TABLE_NAME")
AIRTABLE_API_URL = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_NAME}"

# v7.1: Connection pooling for Airtable requests
airtable_session = requests.Session()
airtable_session.headers.update({
    "Authorization": f"Bearer {AIRTABLE_API_KEY}",
    "Content-Type": "application/json"
})

# --- Security ---
API_SECRET_TOKEN = os.getenv("API_SECRET_TOKEN")
PROTECTED_PATHS = {"/process"}

# CORS whitelist from environment
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
CORS(app, resources={
    r"/process": {"origins": ALLOWED_ORIGINS, "methods": ["POST"]},
    r"/ledger/*": {"origins": ALLOWED_ORIGINS, "methods": ["GET"]},
    r"/health": {"origins": "*", "methods": ["GET"]},
    r"/debug-token": {"origins": ALLOWED_ORIGINS, "methods": ["GET"]},
    r"/recent-errors": {"origins": ALLOWED_ORIGINS, "methods": ["GET"]}
})

# Strict session ID validation
SESSION_ID_RE = re.compile(r'^[A-Za-z0-9-]{3,64}$')

def validate_session_id(sid: str) -> bool:
    """Strict validation: 3-64 chars, alphanumeric + hyphen only"""
    if not sid or not isinstance(sid, str):
        return False
    return bool(SESSION_ID_RE.match(sid))

@app.before_request
def verify_token():
    """Only check API Token on PROTECTED_PATHS; supports Bearer or X-API-Token"""
    if request.path not in PROTECTED_PATHS:
        return

    auth_header = request.headers.get("Authorization", "")
    supplied = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""

    if not supplied:
        supplied = request.headers.get("X-API-Token", "").strip()

    if not (API_SECRET_TOKEN and supplied and hmac.compare_digest(supplied, API_SECRET_TOKEN)):
        return jsonify({"error": "Unauthorized: Invalid API Token"}), 401

# --- Error Tracking (v7.1) ---
RECENT_ERRORS = []
MAX_ERRORS = 20

def log_error(where: str, msg: str):
    """Thread-safe error logging with size limit"""
    with state_lock:
        err = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "location": where,
            "message": str(msg)[:500]  # Truncate long errors
        }
        RECENT_ERRORS.append(err)
        if len(RECENT_ERRORS) > MAX_ERRORS:
            RECENT_ERRORS.pop(0)
    
    logger.error(json.dumps(err))

# --- In-Memory State ---
STATE_STORAGE = {}

def save_state_to_file():
    """Thread-safe state persistence"""
    with state_lock:
        with open(STATE_FILE, 'w') as f:
            json.dump(STATE_STORAGE, f, indent=2)
        logger.info(f"State saved to {STATE_FILE}")

def load_state_from_file():
    """Thread-safe state loading"""
    global STATE_STORAGE
    with state_lock:
        try:
            with open(STATE_FILE, 'r') as f:
                STATE_STORAGE = json.load(f)
                logger.info(f"State loaded from {STATE_FILE}")
        except FileNotFoundError:
            logger.info("No state file found, starting fresh.")
        except json.JSONDecodeError:
            logger.warning("State file corrupted, starting fresh.")

def get_current_baseline(session_id: str) -> dict:
    """Read current baseline values from in-memory state"""
    with state_lock:
        state = STATE_STORAGE.get(session_id, {})
        return {
            "NUM-001": state.get("NUM-001"),
            "DATE-001A": state.get("DATE-001A"),
            "STATUS-001": state.get("STATUS-001")
        }

# v7.1: Retry logic with exponential backoff
def airtable_request_with_retry(method: str, url: str, max_attempts: int = 3, base_delay: float = 1.0, **kwargs):
    """
    Make Airtable request with exponential backoff retry
    Args:
        method: 'GET' or 'POST'
        url: Full Airtable API URL
        max_attempts: Maximum retry attempts
        base_delay: Initial delay in seconds (doubles each retry)
        **kwargs: Additional arguments for requests (data, params, etc.)
    Returns:
        requests.Response object
    """
    for attempt in range(max_attempts):
        try:
            if method.upper() == 'GET':
                resp = airtable_session.get(url, timeout=10, **kwargs)
            else:
                resp = airtable_session.post(url, timeout=10, **kwargs)
            
            # Retry on rate limit or server errors
            if resp.status_code == 429 or 500 <= resp.status_code < 600:
                raise requests.exceptions.RequestException(
                    f"Retryable error {resp.status_code}: {resp.text[:200]}"
                )
            
            resp.raise_for_status()
            return resp
            
        except requests.exceptions.RequestException as e:
            log_error("airtable_retry", f"Attempt {attempt+1}/{max_attempts}: {e}")
            
            if attempt == max_attempts - 1:
                raise  # Re-raise on final attempt
            
            delay = base_delay * (2 ** attempt)  # 1s, 2s, 4s
            logger.info(f"Retrying in {delay}s...")
            time.sleep(delay)

def airtable_get_ledger(session_id: str, limit: int = 100, offset_token: str = None):
    """
    Fetch events from Airtable with proper pagination support.
    Returns: (events_list, next_offset_token)
    """
    if not all([AIRTABLE_API_KEY, AIRTABLE_BASE_ID, AIRTABLE_TABLE_NAME]):
        raise Exception("Airtable configuration missing")
    
    params = {
        "filterByFormula": f"{{session_id}}='{session_id}'",
        "pageSize": min(int(limit), 200),
        "sort[0][field]": "created_at",
        "sort[0][direction]": "desc"
    }
    
    if offset_token:
        params["offset"] = offset_token
    
    resp = airtable_request_with_retry('GET', AIRTABLE_API_URL, params=params)
    data = resp.json()
    
    events = [record["fields"] for record in data.get("records", [])]
    next_offset = data.get("offset")
    
    return events, next_offset

# --- Helpers ---
def extract_financial_number(text: str) -> float | None:
    """Extract numbers with budget/financial context only"""
    patterns = [
        r'(?:budget|cost|price|amount|funding|spend(?:ing)?)\s*(?:is|of|:|to)?\s*[\$€£¥]?\s*(\d[\d,]*\.?\d*)',
        r'[\$€£¥]\s*(\d[\d,]*\.?\d*)',
        r'\b(\d[\d,]*\.?\d*)\s*(?:dollars|euros|pounds|yen|ntd|usd|eur|gbp|jpy)\b',
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            num_str = match.group(1).replace(',', '')
            try:
                return float(num_str)
            except ValueError:
                continue
    return None

def normalize_status(text: str) -> str | None:
    """
    Normalize status keywords to standard values (minimal set to avoid false positives)
    Returns: normalized status string or None
    """
    text_lower = text.lower()
    
    # Minimal normalization map - Phase 1
    status_map = {
        'active': ['active', 'in progress', 'ongoing'],
        'paused': ['paused', 'on hold'],
        'done': ['done', 'completed', 'finished'],
        'blocked': ['blocked', 'stuck']
    }
    
    for normalized, variants in status_map.items():
        if any(variant in text_lower for variant in variants):
            return normalized
    
    return None

def extract_and_format_date(text: str) -> tuple[str | None, str | None]:
    """
    Pre-filter with regex before dateparser to handle complex messages
    Returns (date, warning) tuple
    """
    # Pattern 1: ISO format YYYY-MM-DD
    iso_match = re.search(r'\b(\d{4}-\d{2}-\d{2})\b', text)
    if iso_match:
        try:
            parsed = dateparser.parse(
                iso_match.group(1),
                settings={'RETURN_AS_TIMEZONE_AWARE': True, 'TIMEZONE': 'Asia/Taipei'}
            )
            if parsed:
                return parsed.strftime('%Y-%m-%d'), None
        except:
            pass
    
    # Pattern 2: Month name formats
    month_pattern = r'\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4})\b'
    month_match = re.search(month_pattern, text, re.IGNORECASE)
    if month_match:
        try:
            parsed = dateparser.parse(
                month_match.group(1),
                settings={'PREFER_DATES_FROM': 'future', 'RETURN_AS_TIMEZONE_AWARE': True, 'TIMEZONE': 'Asia/Taipei'}
            )
            if parsed:
                return parsed.strftime('%Y-%m-%d'), None
        except:
            pass
    
    # Pattern 3: Slash or dash formats
    slash_pattern = r'\b(\d{1,2}[/-]\d{1,2}[/-]\d{4})\b'
    slash_match = re.search(slash_pattern, text)
    if slash_match:
        try:
            parsed = dateparser.parse(
                slash_match.group(1),
                settings={'PREFER_DATES_FROM': 'future', 'RETURN_AS_TIMEZONE_AWARE': True, 'TIMEZONE': 'Asia/Taipei'}
            )
            if parsed:
                return parsed.strftime('%Y-%m-%d'), None
        except:
            pass
    
    # Pattern 4: Context-based extraction
    context_pattern = r'(?:deadline|due|by|before|until)\s+(.{0,40})'
    context_match = re.search(context_pattern, text, re.IGNORECASE)
    if context_match:
        date_text = context_match.group(1)
        try:
            parsed = dateparser.parse(
                date_text,
                settings={'PREFER_DATES_FROM': 'future', 'RETURN_AS_TIMEZONE_AWARE': True, 'TIMEZONE': 'Asia/Taipei'}
            )
            if parsed:
                warning = None
                relative_keywords = ['next', 'in', 'after', 'later', 'tomorrow', 'week', 'month']
                if any(kw in date_text.lower() for kw in relative_keywords):
                    warning = f"Relative date detected: '{date_text.strip()}' parsed as {parsed.date()}"
                return parsed.strftime('%Y-%m-%d'), warning
        except:
            pass
    
    # Fallback: Try parsing the entire text
    try:
        parsed_date = dateparser.parse(
            text,
            settings={'PREFER_DATES_FROM': 'future', 'RETURN_AS_TIMEZONE_AWARE': True, 'TIMEZONE': 'Asia/Taipei'}
        )
        if parsed_date:
            warning = None
            relative_keywords = ['next', 'in', 'after', 'later', 'tomorrow', 'week', 'month']
            if any(kw in text.lower() for kw in relative_keywords):
                warning = f"Relative date detected: '{text}' parsed as {parsed_date.date()}"
            return parsed_date.strftime('%Y-%m-%d'), warning
    except:
        pass
    
    return None, None

def create_ledger_event(session_id, turn_id, rule_id, severity, note) -> dict:
    now_utc = datetime.now(timezone.utc)
    taipei_tz = pytz.timezone('Asia/Taipei')
    now_taipei = now_utc.astimezone(taipei_tz)

    return {
        "event_id": f"{rule_id}-{turn_id}-{int(now_utc.timestamp() * 1000)}",
        "session_id": session_id,
        "turn_id": int(turn_id),
        "rule_id": rule_id,
        "severity": severity,
        "note": note,
        "created_at": now_utc.isoformat(),
        "created_at_local": now_taipei.isoformat()
    }

def log_to_airtable(event_data: dict) -> dict:
    """
    Log event to Airtable with retry logic
    Returns: {"success": bool, "error": str or None}
    """
    if not all([AIRTABLE_API_KEY, AIRTABLE_BASE_ID, AIRTABLE_TABLE_NAME]):
        logger.warning("Airtable env missing. Skip log.")
        return {"success": False, "error": "Airtable configuration missing"}
    
    payload = json.dumps({"records": [{"fields": event_data}]})
    
    try:
        resp = airtable_request_with_retry('POST', AIRTABLE_API_URL, data=payload)
        logger.info(f"Event {event_data['event_id']} logged to Airtable.")
        return {"success": True, "error": None}
    except requests.exceptions.RequestException as e:
        error_msg = f"Airtable error: {str(e)}"
        log_error("airtable_post", error_msg)
        return {"success": False, "error": error_msg}

# --- Endpoints ---
@app.route('/process', methods=['POST'])
def process_message():
    """Process message with input validation and drift detection"""
    data = request.json
    
    session_id = data.get("session_id")
    turn_id_raw = data.get("turn_id")
    message_text = data.get("message_text")

    if not all([session_id, turn_id_raw is not None, message_text]):
        return jsonify({"error": "Missing session_id, turn_id, or message_text"}), 400

    if not validate_session_id(session_id):
        return jsonify({"error": "Invalid session_id format (alphanumeric + hyphen, 3-64 chars)"}), 400

    try:
        turn_id = int(turn_id_raw)
        if turn_id < 0:
            return jsonify({"error": "turn_id must be non-negative"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "turn_id must be a valid integer"}), 400

    with state_lock:
        if session_id not in STATE_STORAGE:
            STATE_STORAGE[session_id] = {}

    events = []
    warnings = []
    airtable_errors = []

    # Budget extraction
    extracted_num = extract_financial_number(message_text)
    if extracted_num is not None:
        rule_id = "NUM-001"
        
        with state_lock:
            prev = STATE_STORAGE[session_id].get(rule_id)
            
            if prev is None:
                severity, note = "info", f"Baseline budget set: {extracted_num}"
            elif prev != extracted_num:
                severity, note = "warn", f"Budget drift: {prev} -> {extracted_num}"
            else:
                severity, note = "info", f"Budget confirmed {extracted_num}, no drift."
            
            STATE_STORAGE[session_id][rule_id] = extracted_num
        
        save_state_to_file()
        event = create_ledger_event(session_id, turn_id, rule_id, severity, note)
        events.append(event)
        
        airtable_result = log_to_airtable(event)
        if not airtable_result["success"]:
            airtable_errors.append(airtable_result["error"])

    # Deadline extraction
    extracted_date, date_warning = extract_and_format_date(message_text)
    if extracted_date is not None:
        if date_warning:
            warnings.append(date_warning)
        
        rule_id = "DATE-001A"
        
        with state_lock:
            prev = STATE_STORAGE[session_id].get(rule_id)
            
            if prev is None:
                severity, note = "info", f"Baseline deadline set: {extracted_date}"
            elif prev != extracted_date:
                severity, note = "warn", f"Deadline drift: {prev} -> {extracted_date}"
            else:
                severity, note = "info", f"Deadline confirmed {extracted_date}, no drift."
            
            STATE_STORAGE[session_id][rule_id] = extracted_date
        
        save_state_to_file()
        event = create_ledger_event(session_id, turn_id, rule_id, severity, note)
        events.append(event)
        
        airtable_result = log_to_airtable(event)
        if not airtable_result["success"]:
            airtable_errors.append(airtable_result["error"])

    # v7.2: Status extraction
    status = normalize_status(message_text)
    if status is not None:
        rule_id = "STATUS-001"
        
        with state_lock:
            prev = STATE_STORAGE[session_id].get(rule_id)
            
            if prev is None:
                severity, note = "info", f"Baseline status set: {status}"
            elif prev != status:
                severity, note = "warn", f"Status drift: {prev} -> {status}"
            else:
                severity, note = "info", f"Status confirmed {status}, no drift."
            
            STATE_STORAGE[session_id][rule_id] = status
        
        save_state_to_file()
        event = create_ledger_event(session_id, turn_id, rule_id, severity, note)
        events.append(event)
        
        airtable_result = log_to_airtable(event)
        if not airtable_result["success"]:
            airtable_errors.append(airtable_result["error"])

    for e in events:
        logger.info(f"Ledger Event: {json.dumps(e, indent=2)}")

    if not events:
        return jsonify({"message": "No trackable data found."})

    response = {"events": events}
    
    if warnings:
        response["warnings"] = warnings
    if airtable_errors:
        response["airtable_errors"] = airtable_errors

    return jsonify(response)

@app.route('/ledger/<session_id>', methods=['GET'])
def ledger(session_id):
    """
    Get ledger with correct baseline and pagination
    Query params: ?limit=100&offset=<token>
    """
    if not validate_session_id(session_id):
        return jsonify({"error": "Invalid session_id format"}), 400
    
    try:
        limit = int(request.args.get("limit", 100))
        offset_token = request.args.get("offset")
        
        events, next_offset = airtable_get_ledger(session_id, limit, offset_token)
        current_state = get_current_baseline(session_id)
        
        payload = {
            "session_id": session_id,
            "events": events,
            "current_state": current_state,
            "pagination": {
                "limit": limit,
                "returned": len(events),
                "next_offset": next_offset
            }
        }
        
        resp = make_response(jsonify(payload), 200)
        resp.headers["Cache-Control"] = "public, max-age=5"
        return resp
        
    except Exception as e:
        log_error("ledger_fetch", str(e))
        return jsonify({"error": "Failed to fetch ledger"}), 502

@app.route('/recent-errors', methods=['GET'])
def recent_errors():
    """v7.1: Get recent errors for debugging"""
    with state_lock:
        return jsonify({"errors": list(RECENT_ERRORS), "count": len(RECENT_ERRORS)})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "ok": True,
        "token_loaded": bool(API_SECRET_TOKEN),
        "airtable_configured": all([AIRTABLE_API_KEY, AIRTABLE_BASE_ID, AIRTABLE_TABLE_NAME]),
        "now": datetime.now(timezone.utc).isoformat()
    })

@app.route('/debug-token', methods=['GET'])
def debug_token():
    """Only shows if token is configured, not the actual value"""
    return jsonify({
        "token_configured": bool(API_SECRET_TOKEN),
        "token_length": len(API_SECRET_TOKEN) if API_SECRET_TOKEN else 0
    })

# --- Startup ---
if __name__ == '__main__':
    load_state_from_file()
    logger.info("\n🚀 Mirror OS Pre-Beta API v7.2 Starting...")
    logger.info(f"   Token Protected: {bool(API_SECRET_TOKEN)}")
    logger.info(f"   Airtable Ready: {all([AIRTABLE_API_KEY, AIRTABLE_BASE_ID, AIRTABLE_TABLE_NAME])}")
    logger.info(f"   Allowed Origins: {ALLOWED_ORIGINS}")
    logger.info(f"   State File: {STATE_FILE}")
    logger.info(f"   Retry: 3 attempts with exponential backoff (1s, 2s, 4s)")
    logger.info(f"   Rules: NUM-001, DATE-001A, STATUS-001\n")
    app.run(debug=True, port=5001)