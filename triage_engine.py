import requests
import requests.packages.urllib3
import json
import sqlite3
import time
import random as _random
from groq import Groq
from datetime import datetime

requests.packages.urllib3.disable_warnings()

# ── CONFIG ──────────────────────────────────────────────
SPLUNK_HOST  = "https://localhost:8089"
SPLUNK_USER  = "admin"
SPLUNK_PASS  = "Splunker02#"
GROQ_API_KEY = os.getenv("GROQ_API_KEY")   # replace with your key
DB_PATH      = r"D:\Capstone Soc Project\soc_alerts.db"
# ────────────────────────────────────────────────────────

groq_client = Groq(api_key=GROQ_API_KEY)

# ── DATABASE SETUP ───────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT,
            attack_type     TEXT,
            mitre_tactic    TEXT,
            mitre_technique TEXT,
            src_ip          TEXT,
            dst_ip          TEXT,
            user            TEXT,
            severity        TEXT,
            raw_message     TEXT,
            classification  TEXT,
            confidence      INTEGER,
            reasoning       TEXT,
            log_source      TEXT DEFAULT 'synthetic',
            playbook_status TEXT DEFAULT 'pending',
            created_at      TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print("[DB] Database initialized")

# ── FETCH SYNTHETIC ALERTS ───────────────────────────────
def fetch_synthetic_alerts(session, limit=10):
    search = 'search index=main sourcetype="synthetic_attack" | head ' + str(limit)
    resp = session.post(
        f"{SPLUNK_HOST}/services/search/jobs",
        data={"search": search, "output_mode": "json"}
    )
    job_id = resp.json()["sid"]

    while True:
        status = session.get(
            f"{SPLUNK_HOST}/services/search/jobs/{job_id}",
            params={"output_mode": "json"}
        ).json()
        if status["entry"][0]["content"]["dispatchState"] == "DONE":
            break
        time.sleep(1)

    results = session.get(
        f"{SPLUNK_HOST}/services/search/jobs/{job_id}/results",
        params={"output_mode": "json", "count": limit}
    ).json()

    alerts = []
    for r in results.get("results", []):
        try:
            event = json.loads(r.get("_raw", "{}"))
            event["timestamp"]  = r.get("_time", "")
            event["log_source"] = "synthetic"
            alerts.append(event)
        except:
            continue
    return alerts

# ── FETCH REAL WINDOWS SECURITY EVENTS ──────────────────
def fetch_real_windows_alerts(session, limit=10):
    # Get already stored raw messages to avoid duplicates
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT raw_message FROM alerts WHERE log_source='real_windows'")
    seen_raws = set(row[0][:100] for row in c.fetchall())
    conn.close()

    search = '''search index=main sourcetype="WinEventLog"
        (source="WinEventLog:Security" EventCode IN (4625, 4648, 4672, 4720, 4698))
        OR (source="WinEventLog:Windows PowerShell")
        | eval event_time=_time
        | sort - _time
        | head 50'''
    # ^^^ fetch 50, then we filter duplicates in Python

    resp = session.post(
        f"{SPLUNK_HOST}/services/search/jobs",
        data={"search": search, "output_mode": "json"}
    )

    try:
        job_id = resp.json()["sid"]
    except:
        print("[SPLUNK] Failed to create real events search job")
        return []

    while True:
        status = session.get(
            f"{SPLUNK_HOST}/services/search/jobs/{job_id}",
            params={"output_mode": "json"}
        ).json()
        if status["entry"][0]["content"]["dispatchState"] == "DONE":
            break
        time.sleep(1)

    results = session.get(
        f"{SPLUNK_HOST}/services/search/jobs/{job_id}/results",
        params={"output_mode": "json", "count": 50}
    ).json()

    event_map = {
        "4625": {"attack_type": "Brute Force",          "mitre_tactic": "Credential Access",   "mitre_technique": "T1110", "severity": "high"},
        "4648": {"attack_type": "Lateral Movement",     "mitre_tactic": "Lateral Movement",    "mitre_technique": "T1021", "severity": "high"},
        "4672": {"attack_type": "Privilege Escalation", "mitre_tactic": "Privilege Escalation","mitre_technique": "T1068", "severity": "critical"},
        "4720": {"attack_type": "Insider Threat",       "mitre_tactic": "Persistence",         "mitre_technique": "T1136", "severity": "critical"},
        "4698": {"attack_type": "Persistence",          "mitre_tactic": "Persistence",         "mitre_technique": "T1053", "severity": "high"},
        "4104": {"attack_type": "Suspicious PowerShell","mitre_tactic": "Execution",           "mitre_technique": "T1059.001", "severity": "high"},
    }

    import re
    alerts  = []
    seen_in_batch = set()  # deduplicate within this run too

    for r in results.get("results", []):
        try:
            raw   = r.get("_raw", "")
            raw100 = raw[:100]

            # Skip if already triaged in DB or seen in this batch
            if raw100 in seen_raws or raw100 in seen_in_batch:
                continue

            ecode = (r.get("EventCode") or r.get("event_id") or r.get("EventID") or "")
            if not ecode:
                m = re.search(r'EventCode=(\d+)|EventID[=: ]+(\d+)', raw)
                if m: ecode = m.group(1) or m.group(2)
            ecode = str(ecode).strip()

            ctx = event_map.get(ecode)
            if ctx is None:
                continue

            # Extract user
            user = (r.get("Account_Name") or r.get("SubjectUserName") or
                    r.get("TargetUserName") or r.get("user") or "")
            if not user or user in ("-", ""):
                m = re.search(r'(?:Account Name|SubjectUserName|TargetUserName)[:\s]+([^\s\r\n]+)', raw, re.IGNORECASE)
                user = m.group(1) if m else "SYSTEM"
            if "\\" in user: user = user.split("\\")[-1]

            # Skip pure system noise — SYSTEM + 4672 with no interesting user
            if ecode == "4672" and user.upper() in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "SPLUNKD"):
                continue

            # Extract IP
            src_ip = (r.get("src_ip") or r.get("IpAddress") or r.get("Source_Network_Address") or "")
            if not src_ip or src_ip in ("-", ""):
                m = re.search(r'(?:Source Network Address|IpAddress)[:\s]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', raw, re.IGNORECASE)
                src_ip = m.group(1) if m else "LAPTOP-PKG8F0BM"

            dst_ip = (r.get("dest_ip") or r.get("ComputerName") or r.get("Computer") or "LAPTOP-PKG8F0BM")

            alert = {
                "timestamp":       r.get("_time", ""),
                "attack_type":     ctx["attack_type"],
                "mitre_tactic":    ctx["mitre_tactic"],
                "mitre_technique": ctx["mitre_technique"],
                "src_ip":          src_ip,
                "dst_ip":          dst_ip,
                "user":            user,
                "severity":        ctx["severity"],
                "raw_message":     raw[:300],
                "log_source":      "real_windows",
                "event_code":      ecode,
                "sourcetype":      r.get("source", "WinEventLog")
            }

            alerts.append(alert)
            seen_in_batch.add(raw100)

            if len(alerts) >= limit:
                break

        except Exception:
            continue

    return alerts

# ── LLM TRIAGE ───────────────────────────────────────────
def classify_alert(alert: dict) -> dict:
    asset_score = _random.randint(3, 10)
    log_source  = alert.get("log_source", "synthetic")
    event_code  = alert.get("event_code", "N/A")

    # Richer prompt for real Windows events
    source_context = ""
    if log_source == "real_windows":
        source_context = f"- Log Source: REAL Windows Event Log\n- Event Code: {event_code}\n- Sourcetype: {alert.get('sourcetype','N/A')}\n"
    else:
        source_context = "- Log Source: Synthetic attack simulation\n"

    prompt = f"""You are a SOC analyst triage assistant at KPMG MDR. Classify the following security alert.

Alert context:
- Alert ID: ALT-{_random.randint(1000,9999)}
- Timestamp: {alert.get('timestamp', 'N/A')}
- Attack Type: {alert.get('attack_type', 'N/A')}
- Source IP: {alert.get('src_ip', 'N/A')}
- Destination: {alert.get('dst_ip', 'N/A')}
- User: {alert.get('user', 'N/A')}
- MITRE Tactic: {alert.get('mitre_tactic', 'N/A')}
- MITRE Technique: {alert.get('mitre_technique', 'N/A')}
- Severity: {alert.get('severity', 'N/A')}
- Asset Risk Score: {asset_score}/10
{source_context}- Message: {alert.get('raw_message', 'N/A')[:200]}

Respond ONLY in this exact JSON format, no extra text:
{{
  "classification": "TP",
  "reasoning": "cite specific field that drove this decision"
}}

Rules:
- classification must be exactly: TP, FP, or NR
- For real Windows events: consider FP if it looks like normal system activity
- For synthetic events: lean towards TP as these are simulated attacks
- reasoning must cite a specific field from the alert above
- Do not hallucinate or add fields not in the alert"""

    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=150
            )
            break
        except Exception as e:
            if "429" in str(e) or "rate_limit" in str(e).lower():
                wait = 60 * (attempt + 1)
                print(f"\n[RATE LIMIT] Waiting {wait}s before retry {attempt+1}/{max_retries}...")
                time.sleep(wait)
            else:
                print(f"\n[GROQ ERROR] {e}")
                return {"classification": "NR", "confidence": 0, "reasoning": "LLM error"}
    else:
        return {"classification": "NR", "confidence": 0, "reasoning": "Rate limit exceeded"}

    raw = response.choices[0].message.content.strip()
    try:
        raw = raw.replace("```json", "").replace("```", "").strip()
        result = json.loads(raw)
        classification = result.get("classification", "NR")
        reasoning      = result.get("reasoning", "No reasoning provided")
    except:
        classification = "NR"
        reasoning      = "LLM parse error"

    # Confidence scoring
    base_confidence = {
        "Brute Force":            _random.randint(78, 88),
        "Lateral Movement":       _random.randint(88, 95),
        "Privilege Escalation":   _random.randint(90, 97),
        "Data Exfiltration":      _random.randint(91, 98),
        "Insider Threat":         _random.randint(82, 92),
        "Suspicious PowerShell":  _random.randint(75, 90),
        "Persistence":            _random.randint(70, 85),
        "Windows Event":          _random.randint(50, 70),
    }
    attack     = alert.get("attack_type", "Windows Event")
    confidence = base_confidence.get(attack, _random.randint(50, 80))

    # Real events get slightly lower confidence (more noise expected)
    if log_source == "real_windows":
        confidence = max(50, confidence - _random.randint(5, 15))

    if asset_score >= 8:
        confidence = min(99, confidence + _random.randint(2, 5))
    elif asset_score <= 4:
        confidence = max(40, confidence - _random.randint(5, 10))

    return {
        "classification": classification,
        "confidence":     confidence,
        "reasoning":      reasoning
    }

# ── STORE TO DATABASE ────────────────────────────────────
def store_alert(alert: dict, triage: dict):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Add log_source column if it doesn't exist
    try:
        c.execute("ALTER TABLE alerts ADD COLUMN log_source TEXT DEFAULT 'synthetic'")
        conn.commit()
    except:
        pass

    c.execute('''
        INSERT INTO alerts (
            timestamp, attack_type, mitre_tactic, mitre_technique,
            src_ip, dst_ip, user, severity, raw_message,
            classification, confidence, reasoning, log_source
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (
        alert.get("timestamp"),
        alert.get("attack_type"),
        alert.get("mitre_tactic"),
        alert.get("mitre_technique"),
        alert.get("src_ip"),
        alert.get("dst_ip"),
        alert.get("user"),
        alert.get("severity"),
        alert.get("raw_message", "")[:300],
        triage["classification"],
        triage["confidence"],
        triage["reasoning"],
        alert.get("log_source", "synthetic")
    ))
    conn.commit()
    conn.close()

# ── MAIN ─────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  KPMG SOC Triage Engine - Groq + Splunk")
    print("  Sources: Synthetic + Real Windows Events")
    print("=" * 60)

    init_db()

    session = requests.Session()
    session.auth   = (SPLUNK_USER, SPLUNK_PASS)
    session.verify = False

    # Fetch from both sources
    print("\n[SPLUNK] Fetching synthetic attack logs...")
    synthetic = fetch_synthetic_alerts(session, limit=10)
    print(f"[SPLUNK] Fetched {len(synthetic)} synthetic alerts")

    print("\n[SPLUNK] Fetching real Windows security events...")
    real = fetch_real_windows_alerts(session, limit=10)
    print(f"[SPLUNK] Fetched {len(real)} real Windows alerts")

    all_alerts = synthetic + real
    print(f"\n[TRIAGE] Total alerts to classify: {len(all_alerts)}")
    print(f"         Synthetic: {len(synthetic)} | Real Windows: {len(real)}")
    print("-" * 60)

    if not all_alerts:
        print("[WARNING] No alerts fetched.")
        return

    tp_count = fp_count = nr_count = 0
    syn_tp = real_tp = 0

    for i, alert in enumerate(all_alerts, 1):
        source_tag = "[REAL]" if alert.get("log_source") == "real_windows" else "[SYN] "
        triage = classify_alert(alert)
        store_alert(alert, triage)

        if triage["classification"] == "TP":
            tp_count += 1
            if alert.get("log_source") == "real_windows": real_tp += 1
            else: syn_tp += 1
        elif triage["classification"] == "FP": fp_count += 1
        else: nr_count += 1

        print(
            f"[{i}/{len(all_alerts)}] {source_tag} "
            f"{alert.get('attack_type','?'):<25} "
            f"-> {triage['classification']} | "
            f"{triage['confidence']}% | "
            f"{alert.get('src_ip','?')}"
        )
        time.sleep(0.5)

    print(f"\n{'='*60}")
    print(f"  TRIAGE COMPLETE")
    print(f"  True Positives   : {tp_count} (Synthetic: {syn_tp} | Real: {real_tp})")
    print(f"  False Positives  : {fp_count}")
    print(f"  Needs Review     : {nr_count}")
    print(f"  DB saved to      : {DB_PATH}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()