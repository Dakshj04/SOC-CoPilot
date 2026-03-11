import requests
import sqlite3
import json
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

# ── CONFIG ──────────────────────────────────────────────
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")
DB_PATH       = r"D:\Capstone Soc Project\soc_alerts.db"
# ────────────────────────────────────────────────────────

# ── SLACK NOTIFICATION ───────────────────────────────────
def send_slack(message: str, color: str = "#ff4444"):
    payload = {
        "attachments": [{
            "color":  color,
            "blocks": [{
                "type": "section",
                "text": {"type": "mrkdwn", "text": message}
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"KPMG MDR SOC Copilot | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC"}]
            }]
        }]
    }
    try:
        r = requests.post(SLACK_WEBHOOK, json=payload, timeout=5)
        return r.status_code == 200
    except Exception as e:
        print(f"[SLACK ERROR] {e}")
        return False

# ── UPDATE CASE STATUS IN DB ─────────────────────────────
def update_case_status(alert_id: int, status: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE alerts SET playbook_status = ? WHERE id = ?",
        (status, alert_id)
    )
    conn.commit()
    conn.close()

# ── PLAYBOOK 1: BRUTE FORCE CONTAINMENT ─────────────────
def playbook_brute_force(alert: dict) -> dict:
    alert_id = alert.get("id")
    src_ip   = alert.get("src_ip", "unknown")
    user     = alert.get("user", "unknown")
    conf     = alert.get("confidence", 0)

    log = []
    log.append(f"[P1] Brute Force Containment initiated for alert {alert_id}")
    log.append(f"[P1] Source IP: {src_ip} | User: {user} | Confidence: {conf}%")

    # Step 1 - Block IP (simulated)
    log.append(f"[P1] ACTION: Blocking IP {src_ip} at perimeter firewall [SIMULATED]")

    # Step 2 - Lock account (simulated)
    log.append(f"[P1] ACTION: Locking user account '{user}' pending investigation [SIMULATED]")

    # Step 3 - Update case
    update_case_status(alert_id, "contained")
    log.append(f"[P1] Case {alert_id} status updated to: CONTAINED")

    # Step 4 - Notify Slack
    msg = (
        f":rotating_light: *BRUTE FORCE CONTAINED*\n"
        f">*Alert ID:* {alert_id}\n"
        f">*Source IP:* `{src_ip}` — blocked at perimeter\n"
        f">*User:* `{user}` — account locked\n"
        f">*Confidence:* {conf}%\n"
        f">*MITRE:* T1110 — Credential Access\n"
        f">*Status:* CONTAINED"
    )
    slack_ok = send_slack(msg, color="#ff4444")
    log.append(f"[P1] Slack notification: {'sent' if slack_ok else 'failed'}")

    return {"playbook": "Brute Force Containment", "status": "contained", "log": log}

# ── PLAYBOOK 2: LATERAL MOVEMENT BLOCK ──────────────────
def playbook_lateral_movement(alert: dict) -> dict:
    alert_id = alert.get("id")
    src_ip   = alert.get("src_ip", "unknown")
    dst_ip   = alert.get("dst_ip", "unknown")
    conf     = alert.get("confidence", 0)

    log = []
    log.append(f"[P2] Lateral Movement Block initiated for alert {alert_id}")
    log.append(f"[P2] {src_ip} -> {dst_ip} | Confidence: {conf}%")

    # Step 1 - Block SMB traffic (simulated)
    log.append(f"[P2] ACTION: Blocking SMB (port 445) from {src_ip} to {dst_ip} [SIMULATED]")

    # Step 2 - Isolate source host (simulated)
    log.append(f"[P2] ACTION: Isolating host {src_ip} from network segment [SIMULATED]")

    # Step 3 - Update case
    update_case_status(alert_id, "escalated")
    log.append(f"[P2] Case {alert_id} status updated to: ESCALATED")

    # Step 4 - Notify Slack
    msg = (
        f":warning: *LATERAL MOVEMENT BLOCKED*\n"
        f">*Alert ID:* {alert_id}\n"
        f">*Movement:* `{src_ip}` → `{dst_ip}`\n"
        f">*Action:* SMB blocked, source host isolated\n"
        f">*Confidence:* {conf}%\n"
        f">*MITRE:* T1021 — Lateral Movement\n"
        f">*Status:* ESCALATED"
    )
    slack_ok = send_slack(msg, color="#ff8800")
    log.append(f"[P2] Slack notification: {'sent' if slack_ok else 'failed'}")

    return {"playbook": "Lateral Movement Block", "status": "escalated", "log": log}

# ── PLAYBOOK 3: PRIVILEGE ESCALATION / INSIDER THREAT ───
def playbook_privilege_escalation(alert: dict) -> dict:
    alert_id = alert.get("id")
    user     = alert.get("user", "unknown")
    src_ip   = alert.get("src_ip", "unknown")
    conf     = alert.get("confidence", 0)
    attack   = alert.get("attack_type", "unknown")

    log = []
    log.append(f"[P3] Privilege Escalation Response initiated for alert {alert_id}")
    log.append(f"[P3] User: {user} | IP: {src_ip} | Type: {attack} | Confidence: {conf}%")

    # Step 1 - Revoke privileges (simulated)
    log.append(f"[P3] ACTION: Revoking elevated privileges for '{user}' [SIMULATED]")

    # Step 2 - Force session termination (simulated)
    log.append(f"[P3] ACTION: Terminating active sessions for '{user}' [SIMULATED]")

    # Step 3 - Flag for HR/Legal (simulated)
    log.append(f"[P3] ACTION: Flagging incident for HR and Legal review [SIMULATED]")

    # Step 4 - Update case
    update_case_status(alert_id, "under_review")
    log.append(f"[P3] Case {alert_id} status updated to: UNDER REVIEW")

    # Step 5 - Notify Slack
    msg = (
        f":shield: *PRIVILEGE ESCALATION / INSIDER THREAT DETECTED*\n"
        f">*Alert ID:* {alert_id}\n"
        f">*User:* `{user}` — privileges revoked, sessions terminated\n"
        f">*Source IP:* `{src_ip}`\n"
        f">*Attack Type:* {attack}\n"
        f">*Confidence:* {conf}%\n"
        f">*Action:* Flagged for HR/Legal review\n"
        f">*Status:* UNDER REVIEW"
    )
    slack_ok = send_slack(msg, color="#9d4dff")
    log.append(f"[P3] Slack notification: {'sent' if slack_ok else 'failed'}")

    return {"playbook": "Privilege Escalation Response", "status": "under_review", "log": log}

# ── PLAYBOOK ROUTER ──────────────────────────────────────
def run_playbook(alert: dict) -> dict:
    attack_type = alert.get("attack_type", "").lower()

    if "brute" in attack_type:
        return playbook_brute_force(alert)
    elif "lateral" in attack_type:
        return playbook_lateral_movement(alert)
    elif "privilege" in attack_type or "insider" in attack_type or "exfil" in attack_type:
        return playbook_privilege_escalation(alert)
    else:
        return playbook_brute_force(alert)  # default

# ── FETCH ALERT FROM DB ──────────────────────────────────
def get_alert_by_id(alert_id: int) -> dict:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return {}
    cols = ["id","timestamp","attack_type","mitre_tactic","mitre_technique",
            "src_ip","dst_ip","user","severity","raw_message",
            "classification","confidence","reasoning","playbook_status","created_at"]
    return dict(zip(cols, row))

# ── TEST RUN (standalone) ────────────────────────────────
if __name__ == "__main__":
    print("Testing playbooks...")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM alerts WHERE classification='TP' LIMIT 3")
    rows = c.fetchall()
    conn.close()

    cols = ["id","timestamp","attack_type","mitre_tactic","mitre_technique",
            "src_ip","dst_ip","user","severity","raw_message",
            "classification","confidence","reasoning","playbook_status","created_at"]

    for row in rows:
        alert = dict(zip(cols, row))
        print(f"\nRunning playbook for: {alert['attack_type']} (ID: {alert['id']})")
        result = run_playbook(alert)
        print(f"Status: {result['status']}")
        for line in result['log']:
            print(f"  {line}")