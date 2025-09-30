# === Mirror OS Pre-Beta Script v7 ===
# Flask server for Pre-Beta Ledger
# v7: Critical fixes - baseline, pagination, CORS, session validation

# --- Core Libraries ---
import os
import re
import json
import threading
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

# --- Security ---
API_SECRET_TOKEN = os.getenv("API_SECRET_TOKEN")
PROTECTED_PATHS = {"/process"}

# CRITICAL FIX 3: CORS whitelist from environment
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
CORS(app, resources={
    r"/process": {"origins": ALLOWED_ORIGINS, "methods": ["POST"]},
    r"/ledger/*": {"origins": ALLOWED_ORIGINS, "methods": ["GET"]},
    r"/health": {"origins": "*", "methods": ["GET"]},
    r"/debug-token": {"origins": ALLOWED_ORIGINS, "methods": ["GET"]}
})

# CRITICAL FIX 4: Stricter session ID validation
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

# CRITICAL FIX 1: Get baseline from STATE_STORAGE, not events
def get_current_baseline(session_id: str) -> dict:
    """Read current baseline values from in-memory state"""
    with state_lock:
        state = STATE_STORAGE.get(session_id, {})
        return {
            "NUM-001": state.get("NUM-001"),
            "DATE-001A": state.get("DATE-001A")
        }

# CRITICAL FIX 2: Correct Airtable pagination with offset tokens
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
    
    headers = {"Authorization": f"Bearer {AIRTABLE_API_KEY}"}
    
    try:
        resp = requests.get(AIRTABLE_API_URL, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        
        events = [record["fields"] for record in data.get("records", [])]
        next_offset = data.get("offset")  # String token for next page, or None
        
        return events, next_offset
    except requests.exceptions.RequestException as e:
        logger.error(f"Airtable fetch error: {e}")
        raise

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

def extract_and_format_date(text: str) -> tuple[str | None, str | None]:
    """
    v6.1: Pre-filter with regex before dateparser to handle complex messages
    Returns (date, warning) tuple
    """
    # Pattern 1: ISO format YYYY-MM-DD (most reliable)
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
    
    # Pattern 2: Month name formats (e.g., "Dec 31, 2025", "December 31, 2025")
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
    
    # Pattern 3: Slash or dash formats (e.g., "12/31/2025", "31-12-2025")
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
    
    # Pattern 4: Context-based extraction (deadline, due, by keywords)
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
                # Check for relative date keywords
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
    Log event to Airtable
    Returns: {"success": bool, "error": str or None}
    """
    if not all([AIRTABLE_API_KEY, AIRTABLE_BASE_ID, AIRTABLE_TABLE_NAME]):
        logger.warning("Airtable env missing. Skip log.")
        return {"success": False, "error": "Airtable configuration missing"}
    
    headers = {"Authorization": f"Bearer {AIRTABLE_API_KEY}", "Content-Type": "application/json"}
    payload = json.dumps({"records": [{"fields": event_data}]})
    
    try:
        resp = requests.post(AIRTABLE_API_URL, headers=headers, data=payload, timeout=10)
        resp.raise_for_status()
        logger.info(f"Event {event_data['event_id']} logged to Airtable.")
        return {"success": True, "error": None}
    except requests.exceptions.RequestException as e:
        error_msg = f"Airtable error: {str(e)}"
        if 'resp' in locals():
            error_msg += f" | Response: {resp.text}"
        logger.error(error_msg)
        return {"success": False, "error": error_msg}

# --- Endpoints ---
@app.route('/process', methods=['POST'])
def process_message():
    """Process message with input validation and drift detection"""
    data = request.json
    
    # Validate required fields
    session_id = data.get("session_id")
    turn_id_raw = data.get("turn_id")
    message_text = data.get("message_text")

    if not all([session_id, turn_id_raw is not None, message_text]):
        return jsonify({"error": "Missing session_id, turn_id, or message_text"}), 400

    # CRITICAL FIX 4: Validate session_id format
    if not validate_session_id(session_id):
        return jsonify({"error": "Invalid session_id format (alphanumeric + hyphen, 3-64 chars)"}), 400

    # Validate turn_id is valid integer
    try:
        turn_id = int(turn_id_raw)
        if turn_id < 0:
            return jsonify({"error": "turn_id must be non-negative"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "turn_id must be a valid integer"}), 400

    # Initialize session state with lock
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

    # Print events to console
    for e in events:
        logger.info(f"Ledger Event: {json.dumps(e, indent=2)}")

    # Build response
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
    CRITICAL FIX 1 & 2: Get ledger with correct baseline and pagination
    Query params: ?limit=100&offset=<token>
    """
    # CRITICAL FIX 4: Validate session_id
    if not validate_session_id(session_id):
        return jsonify({"error": "Invalid session_id format"}), 400
    
    try:
        limit = int(request.args.get("limit", 100))
        offset_token = request.args.get("offset")
        
        # Fetch from Airtable with pagination
        events, next_offset = airtable_get_ledger(session_id, limit, offset_token)
        
        # CRITICAL FIX 1: Get baseline from STATE_STORAGE
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
        logger.error(f"Ledger fetch failed: {e}")
        return jsonify({"error": "Failed to fetch ledger"}), 502

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
    logger.info("\n🚀 Mirror OS Pre-Beta API v7 Starting...")
    logger.info(f"   Token Protected: {bool(API_SECRET_TOKEN)}")
    logger.info(f"   Airtable Ready: {all([AIRTABLE_API_KEY, AIRTABLE_BASE_ID, AIRTABLE_TABLE_NAME])}")
    logger.info(f"   Allowed Origins: {ALLOWED_ORIGINS}")
    logger.info(f"   State File: {STATE_FILE}\n")
    app.run(debug=True, port=5001)