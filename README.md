# 🛡️ KPMG MDR — SOC Copilot
### AI-Powered Security Operations Center | Capstone Project 2026

![Python](https://img.shields.io/badge/Python-3.9-blue?style=for-the-badge&logo=python)
![Splunk](https://img.shields.io/badge/SIEM-Splunk_Enterprise-orange?style=for-the-badge)
![Groq](https://img.shields.io/badge/LLM-Groq_Llama_3.3_70B-green?style=for-the-badge)
![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red?style=for-the-badge)
![Slack](https://img.shields.io/badge/Alerts-Slack-purple?style=for-the-badge)
![Ngrok](https://img.shields.io/badge/Tunnel-Ngrok-blue?style=for-the-badge)

---

## What Is This?

A fully functional AI-powered SOC (Security Operations Center) Copilot that replicates KPMG's Managed Detection & Response (MDR) practice. The system ingests real Windows endpoint logs and simulated MITRE ATT&CK attack scenarios into Splunk, classifies every alert using Groq's Llama 3.3 70B LLM, executes automated containment playbooks with Slack notifications, generates professional incident reports, and provides analysts with a context-aware AI chatbot — all accessible live via a public URL.

> Built as a capstone project demonstrating enterprise SOC pipeline architecture on a single machine using entirely free tools.

---

## Live Demo

```
https://trippingly-multiradial-michel.ngrok-free.dev
```
*(Accessible when demo laptop is running)*

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     LAYER 1 — DATA INGESTION                    │
│                                                                 │
│   Real Windows Logs              Synthetic Attack Simulator     │
│   ──────────────────             ────────────────────────────   │
│   Event ID 4625  Brute Force     Brute Force      T1110         │
│   Event ID 4648  Lateral Move    Lateral Movement T1021         │
│   Event ID 4672  Priv Esc        Privilege Esc    T1068         │
│   Event ID 4720  New Account     Insider Threat   T1074         │
│   Event ID 4698  Sched Task      Data Exfiltration T1041        │
│   Event ID 4104  PowerShell                                     │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HEC port 8088
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     LAYER 2 — SPLUNK SIEM                       │
│              140,000+ real Windows logs ingested                │
│         sourcetype=WinEventLog + synthetic_attack               │
└──────────────────────────┬──────────────────────────────────────┘
                           │ REST API every 2 minutes
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                   LAYER 3 — AI TRIAGE ENGINE                    │
│   Groq Llama 3.3 70B → TP / FP / NR + confidence + reasoning   │
│   Deduplication layer — skips already-triaged events            │
│   Noise filter — suppresses SYSTEM/Splunkd 4672 events          │
└───────────────┬─────────────────────────────┬───────────────────┘
                │                             │
                ▼                             ▼
┌─────────────────────────┐    ┌──────────────────────────────────┐
│  SQLite Database        │    │  Playbook Engine                 │
│  soc_alerts.db          │    │  P1: Brute Force Containment     │
│  Full audit trail       │    │  P2: Lateral Movement Block      │
│  TP/FP/NR + reasoning   │    │  P3: Privilege Escalation        │
│  log_source tagging     │    │       └→ Slack #soc-alerts       │
└─────────────────────────┘    └──────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────────────┐
│           LAYER 5 — STREAMLIT DASHBOARD  port 8501              │
│  Tab 1: Alert Queue      Tab 2: SOC Metrics   Tab 3: Detail     │
│  Tab 4: Playbook Console Tab 5: Incident PDF  Tab 6: Chatbot    │
└──────────────────────────────────┬──────────────────────────────┘
                                   │ Ngrok tunnel
                                   ▼
              https://trippingly-multiradial-michel.ngrok-free.dev
```

---

## Features

| Feature | Description | File |
|---|---|---|
| **Dual Log Ingestion** | Real Windows events + synthetic MITRE ATT&CK | `attack_generator.py` |
| **AI Triage** | Llama 3.3 70B classifies TP/FP/NR with reasoning | `triage_engine.py` |
| **Deduplication** | Prevents re-triaging same events across cycles | `triage_engine.py` |
| **Noise Filtering** | Suppresses benign SYSTEM/Splunkd events | `triage_engine.py` |
| **MITRE Mapping** | Every alert mapped to ATT&CK tactic + technique | `triage_engine.py` |
| **Confidence Scoring** | Per-attack scoring adjusted by asset criticality | `triage_engine.py` |
| **Automated Playbooks** | 3 containment procedures with simulated actions | `playbooks.py` |
| **Slack Notifications** | Structured alerts on every playbook execution | `playbooks.py` |
| **6-Tab Dashboard** | Dark Streamlit UI with 6 Plotly charts + 7 KPIs | `dashboard.py` |
| **AI Incident Report** | Groq-generated timeline + executive summary | `incident_report.py` |
| **PDF Export** | One-click professional incident report download | `incident_report.py` |
| **SOC Chatbot** | Context-stuffed AI with live DB awareness | `dashboard.py` |
| **Public URL** | Ngrok permanent domain for remote demo | ngrok |

---

## Project Structure

```
D:\Capstone Soc Project\
│
├── attack_generator.py    # Synthetic MITRE ATT&CK log generator
├── triage_engine.py       # Splunk poller + Groq LLM + deduplication
├── playbooks.py           # 3 containment playbooks + Slack
├── incident_report.py     # AI timeline + exec summary + PDF
├── dashboard.py           # Streamlit 6-tab SOC dashboard
├── soc_alerts.db          # SQLite database (auto-created)
├── launch_demo.ps1        # One-click demo launcher
└── README.md              # This file
```

---

## Installation

**Install dependencies:**
```bash
pip install requests groq streamlit==1.12.0 plotly pandas altair==4.2.2 fpdf2
```

**Update these config values across the files:**

| File | Variable | Source |
|---|---|---|
| `attack_generator.py` | `SPLUNK_TOKEN` | Splunk HEC settings |
| `triage_engine.py` | `SPLUNK_PASS` | Your Splunk password |
| `triage_engine.py` | `GROQ_API_KEY` | console.groq.com |
| `incident_report.py` | `GROQ_API_KEY` | console.groq.com |
| `playbooks.py` | `SLACK_WEBHOOK` | Slack app settings |
| `dashboard.py` Tab 6 | `GROQ_API_KEY` | console.groq.com |

---

## Running the Project

Open 4 PowerShell windows:

**Window 1 — Attack Generator:**
```powershell
$env:PYTHONIOENCODING = "utf-8"
while ($true) { python "D:\Capstone Soc Project\attack_generator.py"; Start-Sleep 3 }
```

**Window 2 — Triage Engine:**
```powershell
$env:PYTHONIOENCODING = "utf-8"
while ($true) { python "D:\Capstone Soc Project\triage_engine.py"; Start-Sleep 120 }
```

**Window 3 — Dashboard:**
```powershell
$env:PYTHONIOENCODING = "utf-8"
streamlit run "D:\Capstone Soc Project\dashboard.py" --server.headless true
```

**Window 4 — Ngrok:**
```powershell
ngrok http --url=trippingly-multiradial-michel.ngrok-free.dev 8501
```

---

## Demo Script (2-3 Minutes)

| Time | Action |
|---|---|
| 0:00 | Open ngrok URL — show it's live |
| 0:20 | Alert Queue — show colour-coded TP/FP classification |
| 0:40 | SOC Metrics — MITRE chart + real vs synthetic split |
| 1:00 | Playbook Console — run containment, show Slack notification |
| 1:30 | Incident Report — generate AI report, download PDF |
| 2:00 | SOC Chatbot — ask "what should I escalate right now?" |
| 2:30 | Run PowerShell brute force script — show live real detection |

**Live brute force demo:**
```powershell
1..10 | ForEach-Object {
    try {
        $c = New-Object System.Management.Automation.PSCredential("admin$_",(ConvertTo-SecureString "wrong$_" -AsPlainText -Force))
        Start-Process cmd -Credential $c -ErrorAction Stop
    } catch {}
    Start-Sleep -Milliseconds 300
}
```

---

## MITRE ATT&CK Coverage

| Attack | Tactic | Technique | Log Source |
|---|---|---|---|
| Brute Force | Credential Access | T1110 | Real 4625 + Synthetic |
| Lateral Movement | Lateral Movement | T1021 | Synthetic |
| Privilege Escalation | Privilege Escalation | T1068 | Real 4672 + Synthetic |
| Insider Threat | Collection | T1074 | Synthetic |
| Data Exfiltration | Exfiltration | T1041 | Synthetic |
| Persistence | Persistence | T1053 | Real 4698 |
| Suspicious PowerShell | Execution | T1059.001 | Real 4104 |
| Account Creation | Persistence | T1136 | Real 4720 |

---

## Chatbot Architecture — Why Not RAG?

| | RAG | Our Approach (Context-Stuffing) |
|---|---|---|
| Infrastructure needed | Vector DB + embeddings | None |
| Response latency | Retrieval + generation | Generation only |
| Data freshness | Index sync dependent | 100% real-time |
| Token usage | ~200 tokens | ~1,200 / 128,000 tokens |
| Best for | 50,000+ alerts | Under 10,000 alerts |

We use under 1% of Llama 3.3's context window. RAG adds complexity with zero benefit at this scale.

---

## Tech Stack

| Component | Technology |
|---|---|
| SIEM | Splunk Enterprise 10.2.1 |
| LLM | Groq — Llama 3.3 70B Versatile |
| Database | SQLite |
| Dashboard | Streamlit 1.12.0 + Plotly |
| Notifications | Slack Incoming Webhooks |
| PDF | fpdf2 |
| Tunnel | Ngrok |
| Language | Python 3.9 |

---

## Author

**Isha Jain** — KPMG Cybersecurity Capstone 2026

*All IPs and usernames are fictional. Playbook actions are simulated. Never commit API keys to public repos.*
