import sqlite3
import json
import requests
from datetime import datetime
from fpdf import FPDF
from dotenv import load_dotenv
import os

load_dotenv()
# ── CONFIG ──────────────────────────────────────────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY")  # replace with your key
DB_PATH      = r"D:\Capstone Soc Project\soc_alerts.db"
# ────────────────────────────────────────────────────────

# ── FETCH ALERTS FOR INCIDENT ────────────────────────────
def fetch_incident_alerts(src_ip: str = None, limit: int = 10) -> list:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if src_ip:
        c.execute("""
            SELECT id, timestamp, attack_type, mitre_tactic, mitre_technique,
                   src_ip, dst_ip, user, severity, raw_message, classification,
                   confidence, reasoning, playbook_status, created_at
            FROM alerts
            WHERE src_ip = ? AND classification = 'TP'
            ORDER BY created_at ASC
            LIMIT ?
        """, (src_ip, limit))
    else:
        c.execute("""
            SELECT id, timestamp, attack_type, mitre_tactic, mitre_technique,
                   src_ip, dst_ip, user, severity, raw_message, classification,
                   confidence, reasoning, playbook_status, created_at
            FROM alerts
            WHERE classification = 'TP'
            ORDER BY created_at ASC
            LIMIT ?
        """, (limit,))
    rows = c.fetchall()
    conn.close()

    cols = ["id","timestamp","attack_type","mitre_tactic","mitre_technique",
            "src_ip","dst_ip","user","severity","raw_message","classification",
            "confidence","reasoning","playbook_status","created_at"]
    return [dict(zip(cols, r)) for r in rows]

# ── GENERATE TIMELINE VIA GROQ ───────────────────────────
def generate_timeline(alerts: list) -> str:
    from groq import Groq
    client = Groq(api_key=GROQ_API_KEY)

    events_text = ""
    for i, a in enumerate(alerts, 1):
        events_text += (
            f"{i}. [{a.get('created_at','N/A')}] "
            f"{a.get('attack_type')} | "
            f"Src: {a.get('src_ip')} -> Dst: {a.get('dst_ip')} | "
            f"User: {a.get('user')} | "
            f"MITRE: {a.get('mitre_tactic')} ({a.get('mitre_technique')}) | "
            f"Severity: {a.get('severity')}\n"
        )

    prompt = f"""You are a forensic analyst. Given the following sequence of security events, 
construct a concise attack timeline narrative.

Events:
{events_text}

Output format - write exactly this structure:
ATTACK TIMELINE
1. [TIME] What happened - Source: event X
2. [TIME] What happened - Source: event X
...

ATTACK CHAIN SUMMARY
2-3 sentences describing the full attack chain from initial access to final impact.

Only reference events explicitly listed above. Do not hallucinate."""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=600
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Timeline generation failed: {e}"

# ── GENERATE EXECUTIVE SUMMARY VIA GROQ ─────────────────
def generate_executive_summary(alerts: list, timeline: str) -> dict:
    from groq import Groq
    client = Groq(api_key=GROQ_API_KEY)

    attack_types  = list(set([a.get("attack_type") for a in alerts]))
    affected_ips  = list(set([a.get("src_ip") for a in alerts]))
    affected_users = list(set([a.get("user") for a in alerts]))
    avg_conf      = int(sum([a.get("confidence", 0) for a in alerts]) / len(alerts))
    severities    = [a.get("severity") for a in alerts]
    risk_score    = 9 if "critical" in severities else 7 if "high" in severities else 5

    prompt = f"""You are a cybersecurity consultant writing for a non-technical CISO audience at KPMG.

Incident data:
- Attack types observed: {', '.join(attack_types)}
- Systems/IPs affected: {', '.join(affected_ips)}
- User accounts involved: {', '.join(affected_users)}
- Total alerts: {len(alerts)}
- Average confidence: {avg_conf}%
- Risk score: {risk_score}/10
- Timeline summary: {timeline[:300]}

Write a professional executive summary with exactly these sections:
WHAT HAPPENED
2-3 plain language sentences. No jargon.

BUSINESS IMPACT  
2-3 sentences on potential business risk.

RECOMMENDED ACTIONS
- Action 1
- Action 2
- Action 3
- Action 4
- Action 5

Keep it under 250 words total. State risk score {risk_score}/10 prominently.
Do not use technical jargon. Only reference facts from the data above."""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=500
        )
        summary_text = response.choices[0].message.content.strip()
    except Exception as e:
        summary_text = f"Summary generation failed: {e}"

    return {
        "summary":     summary_text,
        "risk_score":  risk_score,
        "attack_types": attack_types,
        "affected_ips": affected_ips,
        "affected_users": affected_users,
        "avg_confidence": avg_conf,
        "total_alerts": len(alerts),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

# ── GENERATE PDF ─────────────────────────────────────────
def generate_pdf(timeline: str, summary: dict) -> str:
    pdf = FPDF()
    pdf.add_page()

    # Header
    pdf.set_fill_color(13, 27, 46)
    pdf.rect(0, 0, 210, 40, 'F')
    pdf.set_text_color(126, 179, 232)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_y(10)
    pdf.cell(0, 10, "KPMG MDR - SOC Incident Report", align="C", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(77, 122, 168)
    pdf.cell(0, 8, f"Generated: {summary['generated_at']} | Confidential", align="C", ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(15)

    # Risk Score Banner
    pdf.set_fill_color(255, 68, 68)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 12, f"  RISK SCORE: {summary['risk_score']}/10  |  TOTAL ALERTS: {summary['total_alerts']}  |  AVG CONFIDENCE: {summary['avg_confidence']}%", fill=True, ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(5)

    # Incident Summary Box
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_fill_color(230, 240, 255)
    pdf.cell(0, 8, "INCIDENT SUMMARY", fill=True, ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.ln(2)
    pdf.cell(60, 7, f"Attack Types:", ln=False)
    pdf.cell(0, 7, ", ".join(summary["attack_types"]), ln=True)
    pdf.cell(60, 7, f"Affected IPs:", ln=False)
    pdf.cell(0, 7, ", ".join(summary["affected_ips"]), ln=True)
    pdf.cell(60, 7, f"Affected Users:", ln=False)
    pdf.cell(0, 7, ", ".join(summary["affected_users"]), ln=True)
    pdf.ln(5)

    # Executive Summary
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_fill_color(230, 240, 255)
    pdf.cell(0, 8, "EXECUTIVE SUMMARY", fill=True, ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.ln(2)
    # Clean text for PDF
    clean_summary = summary["summary"].encode('latin-1', 'replace').decode('latin-1')
    pdf.multi_cell(0, 6, clean_summary)
    pdf.ln(5)

    # Attack Timeline
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_fill_color(230, 240, 255)
    pdf.cell(0, 8, "ATTACK TIMELINE", fill=True, ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.ln(2)
    clean_timeline = timeline.encode('latin-1', 'replace').decode('latin-1')
    pdf.multi_cell(0, 5, clean_timeline)
    pdf.ln(5)

    # Footer
    pdf.set_y(-20)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(128, 128, 128)
    pdf.cell(0, 5, "CONFIDENTIAL - KPMG MDR Security Operations Center - For Internal Use Only", align="C", ln=True)

    # Save
    output_path = r"D:\Capstone Soc Project\incident_report.pdf"
    pdf.output(output_path)
    return output_path

# ── MAIN ─────────────────────────────────────────────────
if __name__ == "__main__":
    print("Testing incident report generation...")
    alerts = fetch_incident_alerts(limit=10)
    print(f"Fetched {len(alerts)} alerts")
    timeline = generate_timeline(alerts)
    print("\nTIMELINE:")
    print(timeline)
    summary = generate_executive_summary(alerts, timeline)
    print("\nEXECUTIVE SUMMARY:")
    print(summary["summary"])
    path = generate_pdf(timeline, summary)
    print(f"\nPDF saved to: {path}")