import requests
import random
import time
from datetime import datetime, timezone

# ── CONFIG ──────────────────────────────────────────────
SPLUNK_HEC_URL = "http://localhost:8088/services/collector"
SPLUNK_TOKEN   = "0d786ff1-f4db-49c3-a958-86cdc4b034aa"  # replace with your token
INDEX          = "main"
SOURCETYPE     = "synthetic_attack"
DRY_RUN        = False  # set True to print without sending
# ────────────────────────────────────────────────────────

HEADERS = {"Authorization": f"Splunk {SPLUNK_TOKEN}"}

USERS      = ["admin", "root", "svc_account", "jsmith", "chen.wei"]
SRC_IPS    = ["192.168.10.45", "192.168.18.34", "10.0.0.22", "185.220.101.5"]
DST_IPS    = ["192.168.20.5", "192.168.20.6", "192.168.1.100"]
WORKSTATIONS = ["WKSTN-JOHNSON-01", "WKSTN-CHEN-02", "SRV-APP-07"]

def send(event: dict):
    payload = {
        "time":       datetime.now(timezone.utc).timestamp(),
        "host":       random.choice(WORKSTATIONS),
        "index":      INDEX,
        "sourcetype": SOURCETYPE,
        "event":      event
    }
    if DRY_RUN:
        print(f"[DRY RUN] {payload}")
        return
    try:
        r = requests.post(SPLUNK_HEC_URL, headers=HEADERS, json=payload, timeout=5)
        print(f"[{event['attack_type']}] sent → {r.status_code} | src={event.get('src_ip')} user={event.get('user','N/A')}")
    except Exception as e:
        print(f"[ERROR] {e}")

def brute_force():
    user = random.choice(USERS)
    ip   = random.choice(SRC_IPS)
    send({
        "attack_type":   "Brute Force",
        "mitre_tactic":  "Credential Access",
        "mitre_technique": "T1110",
        "src_ip":        ip,
        "dst_ip":        random.choice(DST_IPS),
        "user":          user,
        "action":        "failed_login",
        "failure_count": random.randint(5, 20),
        "severity":      "high",
        "message":       f"Multiple failed login attempts for {user} from {ip}"
    })

def lateral_movement():
    src = random.choice(SRC_IPS)
    dst = random.choice(DST_IPS)
    send({
        "attack_type":     "Lateral Movement",
        "mitre_tactic":    "Lateral Movement",
        "mitre_technique": "T1021",
        "src_ip":          src,
        "dst_ip":          dst,
        "user":            random.choice(USERS),
        "action":          "smb_connection",
        "port":            445,
        "severity":        "critical",
        "message":         f"SMB lateral movement detected from {src} to {dst}"
    })

def privilege_escalation():
    user = random.choice(USERS)
    send({
        "attack_type":     "Privilege Escalation",
        "mitre_tactic":    "Privilege Escalation",
        "mitre_technique": "T1068",
        "src_ip":          random.choice(SRC_IPS),
        "dst_ip":          random.choice(DST_IPS),
        "user":            user,
        "action":          "privilege_granted",
        "severity":        "critical",
        "message":         f"Privilege escalation attempt by {user} — admin rights granted"
    })

def insider_threat():
    user = random.choice(USERS)
    send({
        "attack_type":     "Insider Threat",
        "mitre_tactic":    "Collection",
        "mitre_technique": "T1074",
        "src_ip":          random.choice(SRC_IPS),
        "dst_ip":          random.choice(DST_IPS),
        "user":            user,
        "action":          "large_data_transfer",
        "bytes_transferred": random.randint(500000000, 3000000000),
        "severity":        "critical",
        "message":         f"Off-hours large data transfer by {user} — possible exfiltration"
    })

def data_exfiltration():
    send({
        "attack_type":     "Data Exfiltration",
        "mitre_tactic":    "Exfiltration",
        "mitre_technique": "T1041",
        "src_ip":          random.choice(SRC_IPS),
        "dst_ip":          "203.0.113.99",  # external IP
        "user":            random.choice(USERS),
        "action":          "outbound_transfer",
        "bytes_transferred": random.randint(100000000, 2500000000),
        "severity":        "critical",
        "message":         "Sensitive data exfiltration to external IP detected"
    })

# ── ATTACK WEIGHTS (brute force most common) ────────────
ATTACKS = [
    brute_force,        # 40%
    brute_force,
    lateral_movement,   # 20%
    privilege_escalation, # 20%
    insider_threat,     # 10%
    data_exfiltration   # 10%
]

print("=" * 50)
print("  SOC Attack Simulator — Splunk HEC")
print("  Press Ctrl+C to stop")
print("=" * 50)

count = 0
try:
    while True:
        attack = random.choice(ATTACKS)
        attack()
        count += 1
        print(f"  Total events sent: {count}", end="\r")
        time.sleep(random.uniform(1, 3))
except KeyboardInterrupt:
    print(f"\n  Stopped. Total events sent: {count}")