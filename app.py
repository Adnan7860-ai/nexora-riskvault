import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import sqlite3
from io import BytesIO
from datetime import datetime

# ------------------------------
# 🎨 PAGE CONFIGURATION
# ------------------------------
st.set_page_config(
    page_title="Nexora RiskVault – SOC Risk Management",
    layout="wide",
    page_icon="🛡️"
)

# ------------------------------
# 🎨 DARK THEME CUSTOMIZATION
# ------------------------------
st.markdown("""
    <style>
        body {
            background-color: #0E1117;
            color: #E0E0E0;
        }
        .stApp {
            background-color: #0E1117;
        }
        .css-18e3th9 {
            padding-top: 1rem;
        }
        .stSidebar {
            background-color: #111827;
            color: #E0E0E0;
        }
        .st-bw {
            background-color: #1F2937;
        }
        .css-1v0mbdj {
            color: #9CA3AF;
        }
        .stButton>button {
            background-color: #2563EB;
            color: white;
            border-radius: 10px;
            height: 3em;
            font-weight: 600;
        }
        .stDownloadButton>button {
            background-color: #059669;
            color: white;
            border-radius: 10px;
            height: 3em;
            font-weight: 600;
        }
    </style>
""", unsafe_allow_html=True)

# ------------------------------
# 🧠 SIDEBAR WITH BRANDING
# ------------------------------
st.sidebar.image("assets/nexora_logo.png", width=180)
st.sidebar.title("🧩 Nexora RiskVault Controls")

# ------------------------------
# PAGE NAVIGATION
# ------------------------------
page = st.sidebar.radio(
    "📄 Select Page",
    ["Dashboard", "Attack Intelligence", "Database View", "About"],
)

# ------------------------------
# FILE UPLOAD & SETTINGS
# ------------------------------
st.sidebar.subheader("📁 Data Source")
uploaded_file = st.sidebar.file_uploader("Upload SOC Log CSV", type=["csv"])
use_demo = st.sidebar.checkbox("Use demo data (if no upload)", value=True)

st.sidebar.subheader("🧠 Risk Parameters")
detectability = st.sidebar.slider("Default Detectability (1–10)", 1, 10, 5)
critical_rpn = st.sidebar.number_input("Critical RPN threshold (🔴)", 50, 1000, 200, step=10)

st.sidebar.subheader("🛡️ Attack Detection")
brute_window = st.sidebar.number_input("Brute-force window (sec)", 10, 300, 60)
brute_attempts = st.sidebar.number_input("Brute-force attempts threshold", 2, 10, 3)

# ------------------------------
# LOAD DATA
# ------------------------------
if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.sidebar.success(f"✅ Loaded {len(df)} events from uploaded file")
elif use_demo:
    df = pd.read_csv("sample_logs.csv")
    st.sidebar.info("ℹ️ Using demo dataset")
else:
    st.warning("Please upload a CSV or use demo data to proceed.")
    st.stop()

df["timestamp"] = pd.to_datetime(df["timestamp"])
df = df.sort_values("timestamp")

# ------------------------------
# RISK CALCULATIONS
# ------------------------------
def risk_factors(event):
    if "failed" in event:
        return 8, 5, detectability
    elif "conn" in event:
        return 8, 5, detectability
    elif "process" in event:
        return 9, 3, detectability
    else:
        return 2, 3, detectability

df[["Severity", "Probability", "Detectability"]] = df["event_type"].apply(lambda x: pd.Series(risk_factors(x)))
df["RPN"] = df["Severity"] * df["Probability"] * df["Detectability"]
df["Risk_Level"] = pd.cut(df["RPN"], bins=[0, 100, critical_rpn, np.inf], labels=["Low", "Moderate", "Critical"])

# ------------------------------
# PAGE 1: DASHBOARD
# ------------------------------
if page == "Dashboard":
    st.title("🛡️ Nexora RiskVault – SOC Risk Management Dashboard")
    st.caption("Powered by Nexora Technologies © 2025 | AMDEC + Threat Intelligence")

    total_events = len(df)
    critical_events = len(df[df["RPN"] > critical_rpn])
    unique_sources = df["source_ip"].nunique()
    avg_rpn = df["RPN"].mean().round(1)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", total_events)
    col2.metric("Critical Events (RPN > 200)", critical_events)
    col3.metric("Unique Sources", unique_sources)
    col4.metric("Average RPN", avg_rpn)

    amdec_summary = (
        df.groupby("event_type")
        .agg({
            "Severity": "mean",
            "Probability": "mean",
            "Detectability": "mean",
            "RPN": "mean",
            "source_ip": "nunique",
            "event_type": "count"
        })
        .rename(columns={"event_type": "occurrences", "source_ip": "unique_sources"})
        .reset_index()
    )

    st.subheader("📊 Risk Distribution")
    fig1 = px.bar(
        amdec_summary,
        x="RPN", y="event_type",
        color="Risk_Level",
        orientation="h",
        color_discrete_map={"Low": "#10B981", "Moderate": "#F59E0B", "Critical": "#EF4444"}
    )
    st.plotly_chart(fig1, use_container_width=True)

    fig2 = px.pie(
        amdec_summary,
        names="Risk_Level",
        hole=0.4,
        color_discrete_map={"Low": "#10B981", "Moderate": "#F59E0B", "Critical": "#EF4444"}
    )
    st.plotly_chart(fig2, use_container_width=True)

    st.subheader("AMDEC Summary")
    st.dataframe(amdec_summary, use_container_width=True)

    st.subheader("Event Logs (Filtered)")
    risk_filter = st.multiselect("Select Risk Levels", options=df["Risk_Level"].unique(), default=list(df["Risk_Level"].unique()))
    st.dataframe(df[df["Risk_Level"].isin(risk_filter)], use_container_width=True)

    # Export Button
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine="xlsxwriter") as writer:
        df.to_excel(writer, sheet_name="Logs", index=False)
        amdec_summary.to_excel(writer, sheet_name="AMDEC Summary", index=False)
    st.download_button("📥 Download Excel Report", data=buffer.getvalue(), file_name="nexora_riskvault_report.xlsx")

# ------------------------------
# PAGE 2: ATTACK INTELLIGENCE
# ------------------------------
elif page == "Attack Intelligence":
    st.title("🧠 Threat & Attack Intelligence")
    st.caption("Live brute-force and anomaly detection view")

    df["is_failed"] = df["event_type"].str.contains("fail", case=False)
    df["timestamp_diff"] = df["timestamp"].diff().dt.total_seconds().fillna(9999)

    suspicious_ips = []
    for ip, group in df[df["is_failed"]].groupby("source_ip"):
        bursts = (group["timestamp_diff"] < brute_window).sum()
        if bursts >= brute_attempts:
            suspicious_ips.append(ip)

    if suspicious_ips:
        st.warning(f"⚠️ Brute-force Detected: {', '.join(suspicious_ips)}")
    else:
        st.success("✅ No brute-force activity detected.")

    st.subheader("Recent Failed Logins")
    st.dataframe(df[df["is_failed"]].sort_values("timestamp", ascending=False), use_container_width=True)

# ------------------------------
# PAGE 3: DATABASE LOGGING
# ------------------------------
elif page == "Database View":
    st.title("🗄️ RiskVault Database Integration")
    conn = sqlite3.connect("riskvault.db")
    df.to_sql("logs", conn, if_exists="append", index=False)
    st.success("✅ Logs saved to SQLite (riskvault.db)")

    db_data = pd.read_sql("SELECT * FROM logs LIMIT 50", conn)
    st.subheader("Last 50 Stored Entries")
    st.dataframe(db_data, use_container_width=True)
    conn.close()

# ------------------------------
# PAGE 4: ABOUT
# ------------------------------
else:
    st.title("ℹ️ About Nexora RiskVault")
    st.markdown("""
    **Nexora RiskVault** is a real-time risk intelligence system  
    combining **AMDEC (FMEA)** + **Threat Analytics** to detect, score, and prioritize cyber incidents.

    **Key Features:**
    - 🔍 Upload & analyze real SOC logs (CSV)
    - ⚙️ AMDEC-based RPN scoring
    - 🧠 Brute-force & telnet attack detection
    - 📊 Visual dashboards (RPN charts, Risk Mix)
    - 🗄️ SQLite database integration
    - 🖤 Dark, modern SOC UI

    **Developed by:** *Nexora Technologies (2025)*  
    **Lead Risk Analyst:** Adnan7860-ai
    """)
