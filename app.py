# === Mirror OS Pre-Beta Script v4 ===
# This script runs a simple Flask web server that listens for user messages,
# parses them for budget numbers and deadlines, detects changes (drift)
# from previously seen values, and logs these events to Airtable.

# --- Core Libraries ---
import os
import re
import json
from datetime import datetime, timezone

# --- Third-Party Libraries ---
import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import pytz 
import dateparser 

# --- Global Constants & Configuration ---
STATE_FILE = "state.json" # The file used for the script's memory

# Load environment variables from the .env file
load_dotenv()

# Initialize the Flask web application
app = Flask(__name__)

# --- Airtable Configuration ---
# Read credentials and settings from environment variables
AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = os.getenv("AIRTABLE_TABLE_NAME")
API_SECRET_TOKEN = os.getenv("API_SECRET_TOKEN") # The "Door Key" for our server
AIRTABLE_API_URL = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_NAME}"

# --- In-Memory State ---
# This dictionary holds the last known values for budgets and dates for each session.
# It is loaded from STATE_FILE at startup.
STATE_STORAGE = {}

# ==============================================================================
# === HELPER FUNCTIONS =========================================================
# ==============================================================================

def save_state_to_file():
    """Saves the current STATE_STORAGE dictionary to a JSON file."""
    with open(STATE_FILE, 'w') as f:
        json.dump(STATE_STORAGE, f, indent=2)
    print(f"🧠 State saved to {STATE_FILE}")

def load_state_from_file():
    """Loads the state from a JSON file into STATE_STORAGE if the file exists."""
    global STATE_STORAGE
    try:
        with open(STATE_FILE, 'r') as f:
            STATE_STORAGE = json.load(f)
            print(f"🧠 State successfully loaded from {STATE_FILE}")
    except FileNotFoundError:
        print(f"🧠 {STATE_FILE} not found. Starting with a fresh state.")
    except json.JSONDecodeError:
        print(f"🧠 Error reading {STATE_FILE}. Starting with a fresh state.")

def extract_financial_number(text: str) -> float | None:
    """Extracts the first number from text, handling commas and decimals."""
    # This regex ensures the match starts with a digit.
    match = re.search(r'(\d[\d,]*\.?\d*)', text)
    if match:
        numeric_string = match.group(1).replace(',', '')
        if numeric_string:
            return float(numeric_string)
    return None

def extract_and_format_date(text: str) -> str | None:
    """Intelligently extracts a date from text, including relative dates."""
    # dateparser finds dates like "tomorrow" or "next Monday".
    # PREFER_DATES_FROM: 'future' helps resolve ambiguities (e.g., ensures "Monday" is next Monday).
    parsed_date = dateparser.parse(text, settings={'PREFER_DATES_FROM': 'future'})
    if parsed_date:
        return parsed_date.strftime('%Y-%m-%d')
    return None

def create_ledger_event(session_id, turn_id, rule_id, severity, note) -> dict:
    """Builds a standardized Ledger Event dictionary."""
    now_utc = datetime.now(timezone.utc)
    taipei_tz = pytz.timezone('Asia/Taipei')
    now_taipei = now_utc.astimezone(taipei_tz)

    event = {
        "event_id": f"{rule_id}-{turn_id}-{int(now_utc.timestamp() * 1000)}",
        "session_id": session_id,
        "turn_id": int(turn_id),
        "rule_id": rule_id,
        "severity": severity,
        "note": note,
        "created_at": now_utc.isoformat(),
        "created_at_local": now_taipei.isoformat()
    }
    return event

def log_to_airtable(event_data: dict):
    """Sends the event data to the Airtable API."""
    if not all([AIRTABLE_API_KEY, AIRTABLE_BASE_ID, AIRTABLE_TABLE_NAME]):
        print("💡 Airtable env variables not set. Skipping Airtable log.")
        return

    headers = {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}", # Uses the "Vault Key"
        "Content-Type": "application/json"
    }
    payload = json.dumps({"records": [{"fields": event_data}]})
    
    try:
        response = requests.post(AIRTABLE_API_URL, headers=headers, data=payload)
        response.raise_for_status()
        print(f"✅ Event '{event_data['event_id']}' logged to Airtable successfully.")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error logging to Airtable: {e}")
        if 'response' in locals():
            print(f"   Response Body: {response.text}")

# ==============================================================================
# === MAIN API ENDPOINT ========================================================
# ==============================================================================

@app.before_request
def verify_token():
    """A security check that runs before every request."""
    # This function acts as the "Front Door" security guard.
    if API_SECRET_TOKEN:
        auth_header = request.headers.get('X-API-Token')
        if auth_header != API_SECRET_TOKEN:
            # If the "Door Key" is wrong, reject the request immediately.
            return jsonify({"error": "Unauthorized: Invalid API Token"}), 401

@app.route('/process', methods=['POST'])
def process_message():
    """Receives user messages, processes them, and returns ledger events."""
    data = request.json
    session_id = data.get("session_id")
    turn_id = data.get("turn_id")
    message_text = data.get("message_text")

    if not all([session_id, turn_id, message_text]):
        return jsonify({"error": "Missing session_id, turn_id, or message_text"}), 400

    if session_id not in STATE_STORAGE:
        STATE_STORAGE[session_id] = {}

    events = []
    
    # --- Process Numbers (Budget) ---
    extracted_num = extract_financial_number(message_text)
    if extracted_num is not None:
        rule_id = "NUM-001"
        previous_value = STATE_STORAGE[session_id].get(rule_id)
        
        if previous_value is None:
            severity = "info"
            note = f"Baseline for budget set: {extracted_num}"
        elif previous_value != extracted_num:
            severity = "warn"
            note = f"Budget drift detected: {previous_value} -> {extracted_num}"
        else:
            severity = "info"
            note = f"Budget confirmed at {extracted_num}, no drift."
            
        STATE_STORAGE[session_id][rule_id] = extracted_num
        save_state_to_file() # Save memory to file after updating
        event = create_ledger_event(session_id, turn_id, rule_id, severity, note)
        events.append(event)

    # --- Process Dates (Deadline) ---
    extracted_date = extract_and_format_date(message_text)
    if extracted_date is not None:
        rule_id = "DATE-001"
        previous_value = STATE_STORAGE[session_id].get(rule_id)
        
        if previous_value is None:
            severity = "info"
            note = f"Baseline for deadline set: {extracted_date}"
        elif previous_value != extracted_date:
            severity = "warn"
            note = f"Deadline drift detected: {previous_value} -> {extracted_date}"
        else:
            severity = "info"
            note = f"Deadline confirmed at {extracted_date}, no drift."
        
        STATE_STORAGE[session_id][rule_id] = extracted_date
        save_state_to_file() # Save memory to file after updating
        event = create_ledger_event(session_id, turn_id, rule_id, severity, note)
        events.append(event)

    # --- Return all generated events for this turn ---
    if not events:
        return jsonify({"message": "No trackable data (number/date) found in message."})

    for event in events:
        print("\n--- 💎 Ledger Event Generated ---")
        print(json.dumps(event, indent=2))
        print("--------------------------------\n")
        log_to_airtable(event)
        
    return jsonify(events)

# ==============================================================================
# === SCRIPT STARTUP ===========================================================
# ==============================================================================

if __name__ == '__main__':
    # Load the state from the JSON file when the server starts
    load_state_from_file() 
    # Run the Flask application
    app.run(debug=True, port=5001)