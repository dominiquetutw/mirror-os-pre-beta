import os
import re
import json
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import requests
from dateutil.parser import parse as parse_date
from dotenv import load_dotenv
import pytz # --- CHANGED v2 ---: 引入 pytz 函式庫來處理時區
import dateparser # --- CHANGED v3 ---: 引入新的日期解析函式庫

# --- 1. 設定與初始化 ---

# 載入 .env 文件中的環境變數
load_dotenv()

# 初始化 Flask App
app = Flask(__name__)

# 從環境變數讀取 Airtable 配置
AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = os.getenv("AIRTABLE_TABLE_NAME")
API_SECRET_TOKEN = os.getenv("API_SECRET_TOKEN") # --- CHANGED v2 ---: 讀取 API 安全金鑰
AIRTABLE_API_URL = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_NAME}"

# In-memory storage
STATE_STORAGE = {}

# --- 2. 核心功能函式 ---

# --- CHANGED v2 ---: 更新了 Regex，使其更具彈性
def extract_financial_number(text: str) -> float | None:
    """從文字中提取第一個數字（處理貨幣符號、千分位、小數點）"""
    # 修正後的 Regex：確保匹配的字串必須以數字開頭
    match = re.search(r'(\d[\d,]*\.?\d*)', text)
    if match:
        # 移除逗號並轉換為浮點數以支援小數
        numeric_string = match.group(1).replace(',', '')
        if numeric_string:
            return float(numeric_string)
    return None

def extract_and_format_date(text: str) -> str | None:
    """從文字中智能提取日期（包括相對日期如 "tomorrow"）並格式化為 YYYY-MM-DD"""
    # dateparser 會自動在句子中尋找它能理解的日期，不需要 regex
    # settings={'PREFER_DATES_FROM': 'future'} 確保 "next Monday" 會找到未來的星期一
    parsed_date = dateparser.parse(text, settings={'PREFER_DATES_FROM': 'future'})
    if parsed_date:
        return parsed_date.strftime('%Y-%m-%d')
    return None

def create_ledger_event(session_id, turn_id, rule_id, severity, note) -> dict:
    """建立標準格式的 Ledger Event 物件"""
    now_utc = datetime.now(timezone.utc)
    
    # --- CHANGED v2 ---: 使用毫秒級 timestamp 避免碰撞
    event_id = f"{rule_id}-{turn_id}-{int(now_utc.timestamp() * 1000)}"
    
    # --- CHANGED v2 ---: 新增 Asia/Taipei 本地時間
    taipei_tz = pytz.timezone('Asia/Taipei')
    now_taipei = now_utc.astimezone(taipei_tz)

    event = {
        "event_id": event_id,
        "session_id": session_id,
        "turn_id": int(turn_id),
        "rule_id": rule_id,
        "severity": severity,
        "note": note,
        "created_at": now_utc.isoformat(), # UTC 時間
        "created_at_local": now_taipei.isoformat() # 台北時區時間
    }
    return event

def log_to_airtable(event_data: dict):
    """將 Event 寫入 Airtable"""
    if not all([AIRTABLE_API_KEY, AIRTABLE_BASE_ID, AIRTABLE_TABLE_NAME]):
        print("💡 Airtable env variables not set. Skipping Airtable log.")
        return

    headers = {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
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

# --- 3. API 端點 (Endpoint) ---

# --- CHANGED v2 ---: 新增 before_request 來做 Token 驗證
@app.before_request
def verify_token():
    """在每個請求前驗證 API Token"""
    if API_SECRET_TOKEN: # 只有在 .env 中設定了 TOKEN 才啟用驗證
        auth_header = request.headers.get('X-API-Token')
        if auth_header != API_SECRET_TOKEN:
            return jsonify({"error": "Unauthorized: Invalid API Token"}), 401

@app.route('/process', methods=['POST'])
def process_message():
    """接收使用者訊息，進行解析、比對並生成事件"""
    data = request.json
    session_id = data.get("session_id")
    turn_id = data.get("turn_id")
    message_text = data.get("message_text")

    if not all([session_id, turn_id, message_text]):
        return jsonify({"error": "Missing session_id, turn_id, or message_text"}), 400

    if session_id not in STATE_STORAGE:
        STATE_STORAGE[session_id] = {}

    events = []
    
    # --- 處理數字 (Budget) ---
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
        event = create_ledger_event(session_id, turn_id, rule_id, severity, note)
        events.append(event)

    # --- 處理日期 (Deadline) ---
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
        event = create_ledger_event(session_id, turn_id, rule_id, severity, note)
        events.append(event)

    # --- 處理與輸出事件 ---
    if not events:
        return jsonify({"message": "No trackable data (number/date) found in message."})

    for event in events:
        print("\n--- 💎 Ledger Event Generated (v2) ---")
        print(json.dumps(event, indent=2))
        print("-------------------------------------\n")
        log_to_airtable(event)
        
    return jsonify(events)

# --- 4. 啟動伺服器 ---

if __name__ == '__main__':
    app.run(debug=True, port=5001)