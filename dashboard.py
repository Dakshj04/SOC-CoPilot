import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dotenv import load_dotenv
import os

load_dotenv()

DB_PATH = r"D:\Capstone Soc Project\soc_alerts.db"

st.set_page_config(page_title="KPMG MDR - SOC Copilot", page_icon="Shield", layout="wide")

st.markdown("""
<style>
    .stApp { background-color: #0a0e1a; color: #e0e0e0; }
    section[data-testid="stSidebar"] { background-color: #0d1117; border-right: 1px solid #1e3a5f; }
    div[data-testid="metric-container"] {
        background: linear-gradient(135deg, #0d1b2e, #1a2744);
        border: 1px solid #1e3a5f;
        border-radius: 10px;
        padding: 15px;
    }
    div[data-testid="metric-container"] label { color: #7eb3e8 !important; font-size: 0.75rem !important; text-transform: uppercase; letter-spacing: 1px; }
    div[data-testid="metric-container"] div[data-testid="metric-value"] { color: #ffffff !important; font-size: 2rem !important; font-weight: 700 !important; }
    h1, h2, h3 { color: #7eb3e8 !important; }
    .stTabs [data-baseweb="tab-list"] { background-color: #0d1117; border-bottom: 2px solid #1e3a5f; }
    .stTabs [data-baseweb="tab"] { background-color: #0d1b2e; color: #7eb3e8; border-radius: 6px 6px 0 0; border: 1px solid #1e3a5f; padding: 8px 20px; }
    .stTabs [aria-selected="true"] { background-color: #1e3a5f !important; color: #ffffff !important; }
    .stButton button { background: linear-gradient(135deg, #1e3a5f, #2d5a9e); color: white; border: 1px solid #4d9fff; border-radius: 6px; }
</style>
""", unsafe_allow_html=True)

# ── HEADER ───────────────────────────────────────────────
st.markdown("""
<div style="background:linear-gradient(90deg,#0d1b2e,#1a2744);border-bottom:2px solid #1e3a5f;padding:15px 20px;margin-bottom:20px;border-radius:10px;display:flex;align-items:center;justify-content:space-between;">
    <div style="display:flex;align-items:center;gap:15px;">
        <div style="font-size:2rem;">🛡️</div>
        <div>
            <div style="font-size:1.4rem;font-weight:800;color:#7eb3e8;letter-spacing:2px;">KPMG MDR</div>
            <div style="font-size:0.7rem;color:#4d7aa8;letter-spacing:3px;">SOC COPILOT</div>
        </div>
    </div>
    <div style="text-align:center;">
        <div style="font-size:1.1rem;color:#e0e0e0;font-weight:600;">Security Operations Center</div>
        <div style="font-size:0.75rem;color:#4d7aa8;">Powered by Groq LLM + Splunk SIEM</div>
    </div>
    <div style="text-align:right;">
        <div style="background:#00ff8840;border:1px solid #00ff88;color:#00ff88;padding:4px 12px;border-radius:20px;font-size:0.75rem;font-weight:700;letter-spacing:2px;">⬤ LIVE</div>
        <div style="font-size:0.75rem;color:#7eb3e8;margin-top:5px;">Analyst: SOC L1</div>
        <div style="font-size:0.7rem;color:#4d7aa8;">Shift 08:00-20:00 UTC</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── LOAD DATA ────────────────────────────────────────────
def load_alerts():
    try:
        conn = sqlite3.connect(DB_PATH)
        alerts_df = pd.read_sql_query("SELECT * FROM alerts ORDER BY created_at DESC", conn)
        conn.close()
        alerts_df["confidence"]   = pd.to_numeric(alerts_df["confidence"], errors="coerce").fillna(0).astype(int)
        alerts_df["severity"]     = alerts_df["severity"].str.strip().str.lower()
        alerts_df["attack_type"]  = alerts_df["attack_type"].str.strip()
        alerts_df["mitre_tactic"] = alerts_df["mitre_tactic"].str.strip()
        alerts_df["src_ip"]       = alerts_df["src_ip"].str.strip()
        # Handle log_source column
        if "log_source" not in alerts_df.columns:
            alerts_df["log_source"] = "synthetic"
        alerts_df["log_source"] = alerts_df["log_source"].fillna("synthetic")
        # Make it readable
        alerts_df["log_source"] = alerts_df["log_source"].map({
            "synthetic":    "Synthetic",
            "real_windows": "Real Windows"
        }).fillna("Synthetic")
        return alerts_df
    except Exception as e:
        st.error(f"Database error: {e}")
        return pd.DataFrame()

alerts_df = load_alerts()

if alerts_df.empty:
    st.warning("No alerts found. Run triage_engine.py first.")
    st.stop()

# ── KPI METRICS ──────────────────────────────────────────
total      = len(alerts_df)
critical   = len(alerts_df[alerts_df["severity"] == "critical"])
high       = len(alerts_df[alerts_df["severity"] == "high"])
tp_count   = len(alerts_df[alerts_df["classification"] == "TP"])
fp_count   = len(alerts_df[alerts_df["classification"] == "FP"])
avg_conf   = int(alerts_df["confidence"].mean())
tp_rate    = round((tp_count / total) * 100, 1) if total > 0 else 0
real_count = len(alerts_df[alerts_df["log_source"] == "Real Windows"])
syn_count  = len(alerts_df[alerts_df["log_source"] == "Synthetic"])

m1, m2, m3, m4, m5, m6, m7 = st.columns(7)
m1.metric("Total Alerts",    total)
m2.metric("Critical",        critical, delta=f"{round(critical/total*100)}%")
m3.metric("High",            high)
m4.metric("True Positives",  tp_count, delta=f"{tp_rate}% TP rate")
m5.metric("False Positives", fp_count)
m6.metric("Avg Confidence",  f"{avg_conf}%")
m7.metric("Real Win Logs",   real_count, delta=f"{syn_count} synthetic")

st.markdown("---")

# ── TABS ─────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "Alert Queue", "SOC Metrics", "Alert Detail", "Playbook Console", "Incident Report", "SOC Chatbot"
])

# ════════════════════════════════════════════════════════
# TAB 1 — ALERT QUEUE
# ════════════════════════════════════════════════════════
with tab1:
    f1, f2, f3, f4 = st.columns(4)
    with f1:
        sev_filter = st.multiselect(
            "Severity",
            options=alerts_df["severity"].unique().tolist(),
            default=alerts_df["severity"].unique().tolist()
        )
    with f2:
        class_filter = st.multiselect(
            "Classification",
            options=["TP", "FP", "NR"],
            default=["TP", "FP", "NR"]
        )
    with f3:
        attack_filter = st.multiselect(
            "Attack Type",
            options=alerts_df["attack_type"].unique().tolist(),
            default=alerts_df["attack_type"].unique().tolist()
        )
    with f4:
        source_filter = st.multiselect(
            "Log Source",
            options=alerts_df["log_source"].unique().tolist(),
            default=alerts_df["log_source"].unique().tolist()
        )

    filtered = alerts_df[
        alerts_df["severity"].isin(sev_filter) &
        alerts_df["classification"].isin(class_filter) &
        alerts_df["attack_type"].isin(attack_filter) &
        alerts_df["log_source"].isin(source_filter)
    ]

    st.markdown(f"**Showing {len(filtered)} of {total} alerts**")

    def color_severity(val):
        colors = {
            "critical": "background-color:#ff4444;color:white;font-weight:bold",
            "high":     "background-color:#ff8800;color:white",
            "medium":   "background-color:#ffcc00;color:black",
            "low":      "background-color:#44bb44;color:white"
        }
        return colors.get(str(val).lower(), "")

    def color_classification(val):
        colors = {
            "TP": "background-color:#ff4444;color:white;font-weight:bold",
            "FP": "background-color:#44bb44;color:white",
            "NR": "background-color:#888888;color:white"
        }
        return colors.get(val, "")

    def color_confidence(val):
        if val >= 90:   return "color:#ff4444;font-weight:bold"
        elif val >= 75: return "color:#ff8800"
        else:           return "color:#aaaaaa"

    def color_logsource(val):
        if val == "Real Windows": return "background-color:#00ff8830;color:#00ff88;font-weight:bold"
        return "background-color:#4d9fff30;color:#4d9fff"

    # Only include columns that exist
    display_cols = [
        "id", "log_source", "timestamp", "attack_type", "mitre_tactic",
        "mitre_technique", "src_ip", "dst_ip", "user",
        "severity", "classification", "confidence", "reasoning", "playbook_status"
    ]
    display_cols = [c for c in display_cols if c in filtered.columns]
    display_df = filtered[display_cols].copy()
    display_df.columns = [
        "ID", "Source", "Time", "Attack Type", "MITRE Tactic",
        "Technique", "Src IP", "Dst IP", "User",
        "Severity", "Class", "Conf %", "LLM Reasoning", "Status"
    ][:len(display_cols)]

    styled = (
        display_df.style
        .applymap(color_severity,       subset=["Severity"])
        .applymap(color_classification, subset=["Class"])
        .applymap(color_confidence,     subset=["Conf %"])
        .applymap(color_logsource,      subset=["Source"])
    )
    st.dataframe(styled, height=500)

# ════════════════════════════════════════════════════════
# TAB 2 — SOC METRICS
# ════════════════════════════════════════════════════════
with tab2:
    c1, c2 = st.columns(2)

    with c1:
        st.markdown("#### Attack Type Distribution")
        attack_counts = alerts_df["attack_type"].value_counts().reset_index()
        attack_counts.columns = ["Attack Type", "Count"]
        fig1 = px.bar(
            attack_counts, x="Attack Type", y="Count", color="Count",
            color_continuous_scale=["#1e3a5f", "#4d9fff", "#ff4444"],
            template="plotly_dark"
        )
        fig1.update_layout(
            paper_bgcolor="#0d1b2e", plot_bgcolor="#0d1b2e",
            font_color="#7eb3e8", showlegend=False, margin=dict(t=20, b=20)
        )
        st.plotly_chart(fig1, use_container_width=True)

    with c2:
        st.markdown("#### MITRE ATT&CK Tactics")
        tactic_counts = alerts_df["mitre_tactic"].value_counts().reset_index()
        tactic_counts.columns = ["Tactic", "Count"]
        fig2 = px.pie(
            tactic_counts, names="Tactic", values="Count", hole=0.5,
            color_discrete_sequence=["#4d9fff", "#ff4444", "#ff8800", "#00ff88", "#9d4dff"],
            template="plotly_dark"
        )
        fig2.update_layout(
            paper_bgcolor="#0d1b2e", plot_bgcolor="#0d1b2e",
            font_color="#7eb3e8", margin=dict(t=20, b=20)
        )
        st.plotly_chart(fig2, use_container_width=True)

    c3, c4 = st.columns(2)

    with c3:
        st.markdown("#### Confidence Score Distribution")
        fig3 = go.Figure(data=[go.Histogram(
            x=alerts_df["confidence"].tolist(),
            nbinsx=15,
            marker_color="#4d9fff",
            opacity=0.9
        )])
        fig3.update_layout(
            paper_bgcolor="#0d1b2e", plot_bgcolor="#0d1b2e",
            font_color="#7eb3e8", xaxis_title="Confidence %",
            yaxis_title="Alert Count", margin=dict(t=20, b=20)
        )
        st.plotly_chart(fig3, use_container_width=True)

    with c4:
        st.markdown("#### Severity Breakdown")
        sev_counts = alerts_df["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Count"]
        color_map  = {"critical": "#ff4444", "high": "#ff8800", "medium": "#ffcc00", "low": "#44bb44"}
        bar_colors = [color_map.get(s, "#4d9fff") for s in sev_counts["Severity"].tolist()]
        fig4 = go.Figure(data=[go.Bar(
            x=sev_counts["Severity"].tolist(),
            y=sev_counts["Count"].tolist(),
            marker_color=bar_colors,
            opacity=0.9
        )])
        fig4.update_layout(
            paper_bgcolor="#0d1b2e", plot_bgcolor="#0d1b2e",
            font_color="#7eb3e8", margin=dict(t=20, b=20)
        )
        st.plotly_chart(fig4, use_container_width=True)

    c5, c6 = st.columns(2)

    with c5:
        st.markdown("#### Top Attacking Source IPs")
        ip_counts = alerts_df["src_ip"].value_counts().head(10).reset_index()
        ip_counts.columns = ["Source IP", "Alert Count"]
        fig5 = px.bar(
            ip_counts, x="Alert Count", y="Source IP", orientation="h",
            color="Alert Count", color_continuous_scale=["#1e3a5f", "#ff4444"],
            template="plotly_dark"
        )
        fig5.update_layout(
            paper_bgcolor="#0d1b2e", plot_bgcolor="#0d1b2e",
            font_color="#7eb3e8", margin=dict(t=20, b=20)
        )
        st.plotly_chart(fig5, use_container_width=True)

    with c6:
        st.markdown("#### Log Source Distribution")
        source_counts = alerts_df["log_source"].value_counts().reset_index()
        source_counts.columns = ["Source", "Count"]
        fig6 = px.pie(
            source_counts, names="Source", values="Count", hole=0.4,
            color="Source",
            color_discrete_map={
                "Synthetic":    "#4d9fff",
                "Real Windows": "#00ff88"
            },
            template="plotly_dark"
        )
        fig6.update_layout(
            paper_bgcolor="#0d1b2e", plot_bgcolor="#0d1b2e",
            font_color="#7eb3e8", margin=dict(t=20, b=20)
        )
        st.plotly_chart(fig6, use_container_width=True)

# ════════════════════════════════════════════════════════
# TAB 3 — ALERT DETAIL
# ════════════════════════════════════════════════════════
with tab3:
    selected_id = st.selectbox("Select Alert ID to inspect", options=alerts_df["id"].tolist())

    if selected_id:
        row = alerts_df[alerts_df["id"] == selected_id].iloc[0]
        d1, d2 = st.columns(2)

        with d1:
            st.markdown("**Alert Information**")
            st.markdown(f"- **Attack Type:** {row['attack_type']}")
            st.markdown(f"- **MITRE Tactic:** {row['mitre_tactic']}")
            st.markdown(f"- **Technique:** {row['mitre_technique']}")
            st.markdown(f"- **Severity:** {row['severity'].upper()}")
            st.markdown(f"- **Source IP:** {row['src_ip']}")
            st.markdown(f"- **Dest IP:** {row['dst_ip']}")
            st.markdown(f"- **User:** {row['user']}")
            st.markdown(f"- **Log Source:** {row['log_source']}")
            st.markdown(f"- **Created:** {row['created_at']}")

        with d2:
            st.markdown("**Triage Result**")
            classification = row['classification']
            color = "🔴" if classification == "TP" else "🟢" if classification == "FP" else "🟡"
            st.markdown(f"- **Classification:** {color} {classification}")
            st.markdown(f"- **Confidence:** {row['confidence']}%")
            st.markdown(f"- **Playbook Status:** `{row['playbook_status'].upper()}`")
            st.markdown("---")
            st.markdown("**LLM Reasoning:**")
            st.info(row['reasoning'])
            st.markdown("**Raw Message:**")
            st.code(row['raw_message'])

# ════════════════════════════════════════════════════════
# TAB 4 — PLAYBOOK CONSOLE
# ════════════════════════════════════════════════════════
with tab4:
    from playbooks import run_playbook, get_alert_by_id

    st.markdown("### Playbook Console")
    st.markdown("Select a True Positive alert and run the appropriate containment playbook.")
    st.markdown("---")

    tp_alerts = alerts_df[alerts_df["classification"] == "TP"]

    if tp_alerts.empty:
        st.warning("No True Positive alerts found.")
    else:
        col1, col2 = st.columns([2, 1])

        with col1:
            selected_alert_id = st.selectbox(
                "Select Alert to action",
                options=tp_alerts["id"].tolist(),
                format_func=lambda x: (
                    f"ID:{x} | "
                    f"{tp_alerts[tp_alerts['id']==x]['attack_type'].values[0]} | "
                    f"{tp_alerts[tp_alerts['id']==x]['src_ip'].values[0]} | "
                    f"{tp_alerts[tp_alerts['id']==x]['confidence'].values[0]}% conf | "
                    f"[{tp_alerts[tp_alerts['id']==x]['log_source'].values[0]}]"
                )
            )

        with col2:
            current_status = tp_alerts[tp_alerts["id"] == selected_alert_id]["playbook_status"].values[0]
            status_colors  = {
                "pending":      "🟡 PENDING",
                "contained":    "🔴 CONTAINED",
                "escalated":    "🟠 ESCALATED",
                "under_review": "🟣 UNDER REVIEW"
            }
            st.markdown("**Current Status:**")
            st.markdown(f"### {status_colors.get(current_status, current_status.upper())}")

        if selected_alert_id:
            row = tp_alerts[tp_alerts["id"] == selected_alert_id].iloc[0]
            st.markdown("---")
            p1, p2, p3, p4, p5 = st.columns(5)
            p1.metric("Attack Type",  row["attack_type"])
            p2.metric("Source IP",    row["src_ip"])
            p3.metric("Confidence",   f"{row['confidence']}%")
            p4.metric("Severity",     row["severity"].upper())
            p5.metric("Log Source",   row["log_source"])

            st.markdown("---")
            st.markdown("**Select Playbook to Run:**")
            b1, b2, b3 = st.columns(3)

            with b1:
                run_bf = st.button("🔴 Brute Force Containment",    key="bf")
            with b2:
                run_lm = st.button("🟠 Lateral Movement Block",     key="lm")
            with b3:
                run_pe = st.button("🟣 Privilege Escalation Response", key="pe")

            if run_bf or run_lm or run_pe:
                alert_data = get_alert_by_id(selected_alert_id)
                if run_bf:
                    alert_data["attack_type"] = "Brute Force"
                elif run_lm:
                    alert_data["attack_type"] = "Lateral Movement"
                elif run_pe:
                    alert_data["attack_type"] = "Privilege Escalation"

                with st.spinner("Running playbook..."):
                    result = run_playbook(alert_data)

                st.success(f"Playbook '{result['playbook']}' completed — Status: {result['status'].upper()}")
                st.markdown("**Execution Log:**")
                st.code("\n".join(result["log"]), language="bash")
                st.info("Slack notification sent to #soc-alerts channel")
                st.markdown("*Reload page to see updated case status*")

# ════════════════════════════════════════════════════════
# TAB 5 — INCIDENT REPORT
# ════════════════════════════════════════════════════════
with tab5:
    from incident_report import (
        fetch_incident_alerts,
        generate_timeline,
        generate_executive_summary,
        generate_pdf
    )

    st.markdown("### Incident Report Generator")
    st.markdown("Generate an AI-powered incident timeline and executive summary with one click.")
    st.markdown("---")

    c1, c2 = st.columns(2)
    with c1:
        filter_ip = st.selectbox(
            "Filter by Source IP (optional)",
            options=["All IPs"] + sorted(alerts_df["src_ip"].unique().tolist())
        )
    with c2:
        alert_limit = st.slider("Number of alerts to analyse", min_value=5, max_value=20, value=10)

    st.markdown("---")

    if st.button("Generate Incident Report"):
        src_ip = None if filter_ip == "All IPs" else filter_ip

        with st.spinner("Fetching alerts..."):
            inc_alerts = fetch_incident_alerts(src_ip=src_ip, limit=alert_limit)

        if not inc_alerts:
            st.warning("No TP alerts found for selected filter.")
        else:
            st.success(f"Analysing {len(inc_alerts)} alerts...")

            with st.spinner("Generating attack timeline via Groq LLM..."):
                timeline = generate_timeline(inc_alerts)

            with st.spinner("Generating executive summary..."):
                summary = generate_executive_summary(inc_alerts, timeline)

            risk       = summary["risk_score"]
            risk_color = "#ff4444" if risk >= 8 else "#ff8800" if risk >= 5 else "#44bb44"
            st.markdown(f"""
            <div style="background:{risk_color};padding:15px;border-radius:8px;margin:10px 0;">
                <span style="color:white;font-size:1.5rem;font-weight:800;">RISK SCORE: {risk}/10</span>
                <span style="color:white;font-size:1rem;margin-left:20px;">
                    {len(inc_alerts)} alerts | Avg confidence: {summary['avg_confidence']}%
                </span>
            </div>
            """, unsafe_allow_html=True)

            s1, s2, s3 = st.columns(3)
            s1.metric("Attack Types",   len(summary["attack_types"]))
            s2.metric("Affected IPs",   len(summary["affected_ips"]))
            s3.metric("Affected Users", len(summary["affected_users"]))

            st.markdown("---")
            t1, t2 = st.columns(2)

            with t1:
                st.markdown("#### Attack Timeline")
                st.code(timeline, language="")

            with t2:
                st.markdown("#### Executive Summary")
                st.info(summary["summary"])

            st.markdown("---")

            with st.spinner("Generating PDF..."):
                pdf_path = generate_pdf(timeline, summary)

            with open(pdf_path, "rb") as f:
                pdf_bytes = f.read()

            st.download_button(
                label="Download Incident Report PDF",
                data=pdf_bytes,
                file_name=f"KPMG_SOC_Incident_Report_{summary['generated_at'][:10]}.pdf",
                mime="application/pdf"
            )
            st.success("Report ready! Click above to download.")

# ════════════════════════════════════════════════════════
# TAB 6 — SOC CHATBOT
# ════════════════════════════════════════════════════════
with tab6:
    from groq import Groq
    import json

    GROQ_API_KEY = os.getenv("GROQ_API_KEY")   # replace with your key
    groq_client  = Groq(api_key=GROQ_API_KEY)

    st.markdown("### SOC Analyst Chatbot")
    st.markdown("Ask anything about your alerts, threats, or get analyst recommendations.")
    st.markdown("---")

    # Build context snapshot from DB
    def build_alert_context(df):
        total_alerts   = len(df)
        tp             = len(df[df["classification"] == "TP"])
        fp             = len(df[df["classification"] == "FP"])
        avg_confidence = int(df["confidence"].mean())
        critical_count = len(df[df["severity"] == "critical"])
        real_count     = len(df[df["log_source"] == "Real Windows"]) if "log_source" in df.columns else 0

        top_ips = df["src_ip"].value_counts().head(5).to_dict()
        attack_dist = df["attack_type"].value_counts().to_dict()
        mitre_dist  = df["mitre_tactic"].value_counts().to_dict()

        # Recent 10 alerts as structured summary
        recent = df.head(10)[["id","attack_type","src_ip","user","severity","classification","confidence","reasoning","log_source"]].to_dict(orient="records")

        context = f"""
You are an expert SOC analyst assistant at KPMG MDR (Managed Detection & Response).
You have real-time access to the current SOC alert database.

=== CURRENT SOC STATUS ===
Total Alerts: {total_alerts}
True Positives: {tp} ({round(tp/total_alerts*100,1) if total_alerts else 0}% TP rate)
False Positives: {fp}
Critical Alerts: {critical_count}
Average Confidence: {avg_confidence}%
Real Windows Events: {real_count}
Synthetic Simulated: {total_alerts - real_count}

=== ATTACK DISTRIBUTION ===
{json.dumps(attack_dist, indent=2)}

=== MITRE ATT&CK TACTICS ===
{json.dumps(mitre_dist, indent=2)}

=== TOP SOURCE IPs ===
{json.dumps(top_ips, indent=2)}

=== RECENT 10 ALERTS ===
{json.dumps(recent, indent=2)}

=== YOUR ROLE ===
- Answer analyst questions about the alerts above
- Give specific, actionable recommendations
- Reference actual alert IDs, IPs, users from the data
- Flag high-risk patterns you notice
- Suggest playbooks when appropriate
- Be concise but thorough — this is a live SOC environment
- If asked about something not in the data, say so clearly
"""
        return context

    # Initialize chat history
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

    # Suggested questions
    st.markdown("**Quick questions:**")
    q1, q2, q3, q4 = st.columns(4)
    with q1:
        if st.button("Which IPs are most dangerous?", key="sq1"):
            st.session_state.pending_question = "Which source IPs have the most alerts and are most dangerous? Give me specific recommendations."
    with q2:
        if st.button("Summarise today's threats", key="sq2"):
            st.session_state.pending_question = "Give me an executive summary of today's security incidents and overall risk posture."
    with q3:
        if st.button("What should I escalate?", key="sq3"):
            st.session_state.pending_question = "Which alerts should I escalate immediately and why? Prioritise by risk."
    with q4:
        if st.button("Any patterns I should know?", key="sq4"):
            st.session_state.pending_question = "Are there any attack patterns or correlations in the current alerts I should be aware of?"

    st.markdown("---")

    # Display chat history
    for msg in st.session_state.chat_history:
        if msg["role"] == "user":
            st.markdown(f"""
            <div style="background:#1a2744;border:1px solid #1e3a5f;border-radius:10px;padding:12px 16px;margin:8px 0;text-align:right;">
                <span style="color:#7eb3e8;font-size:0.8rem;">YOU</span><br>
                <span style="color:#e0e0e0;">{msg["content"]}</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="background:#0d1b2e;border:1px solid #00ff8840;border-left:3px solid #00ff88;border-radius:10px;padding:12px 16px;margin:8px 0;">
                <span style="color:#00ff88;font-size:0.8rem;">🛡️ SOC COPILOT</span><br>
                <span style="color:#e0e0e0;">{msg["content"]}</span>
            </div>
            """, unsafe_allow_html=True)

    # Input box
    user_input = st.text_input(
        "Ask your SOC Copilot...",
        value=st.session_state.get("pending_question", ""),
        placeholder="e.g. Which alerts should I escalate? What's the biggest threat right now?",
        key="chat_input"
    )

    # Clear pending question after use
    if "pending_question" in st.session_state:
        del st.session_state["pending_question"]

    col_send, col_clear = st.columns([1, 5])
    with col_send:
        send = st.button("Send", key="send_btn")
    with col_clear:
        if st.button("Clear Chat", key="clear_btn"):
            st.session_state.chat_history = []

    if send and user_input.strip():
        # Show user message immediately
        st.markdown(f"""
        <div style="background:#1a2744;border:1px solid #1e3a5f;border-radius:10px;padding:12px 16px;margin:8px 0;text-align:right;">
            <span style="color:#7eb3e8;font-size:0.8rem;">YOU</span><br>
            <span style="color:#e0e0e0;">{user_input}</span>
        </div>
        """, unsafe_allow_html=True)

        alert_context = build_alert_context(alerts_df)
        messages = [{"role": "system", "content": alert_context}]
        for h in st.session_state.chat_history[-6:]:
            messages.append({"role": h["role"], "content": h["content"]})
        messages.append({"role": "user", "content": user_input})

        with st.spinner("SOC Copilot is analysing..."):
            try:
                response = groq_client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=messages,
                    temperature=0.3,
                    max_tokens=600
                )
                bot_reply = response.choices[0].message.content.strip()
            except Exception as e:
                bot_reply = f"Error: {e}"

        # Show response immediately
        st.markdown(f"""
        <div style="background:#0d1b2e;border:1px solid #00ff8840;border-left:3px solid #00ff88;border-radius:10px;padding:12px 16px;margin:8px 0;">
            <span style="color:#00ff88;font-size:0.8rem;">SOC COPILOT</span><br>
            <span style="color:#e0e0e0;">{bot_reply}</span>
        </div>
        """, unsafe_allow_html=True)

        # Save to history
        st.session_state.chat_history.append({"role": "user", "content": user_input})
        st.session_state.chat_history.append({"role": "assistant", "content": bot_reply})

    # Empty state
    if not st.session_state.chat_history:
        st.markdown("""
        <div style="text-align:center;padding:40px;color:#4d7aa8;">
            <div style="font-size:3rem;">🛡️</div>
            <div style="font-size:1rem;margin-top:10px;">SOC Copilot ready. Ask me anything about your alerts.</div>
            <div style="font-size:0.8rem;margin-top:5px;">I have full context of all current alerts, threat patterns and MITRE ATT&CK mappings.</div>
        </div>
        """, unsafe_allow_html=True)

# ── FOOTER ───────────────────────────────────────────────
st.markdown("---")
col1, col2, col3 = st.columns(3)
with col1:
    st.caption("Reload page to refresh alerts")
with col2:
    st.caption(f"Total alerts in DB: {total} | Real: {real_count} | Synthetic: {syn_count}")
with col3:
    st.caption("KPMG MDR SOC Copilot | Groq LLM + Splunk")