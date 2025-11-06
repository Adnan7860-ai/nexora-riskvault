import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import sqlite3
from io import BytesIO
from datetime import datetime

# ------------------------------
# ⚙️ PAGE CONFIGURATION
# ------------------------------
st.set_page_config(
    page_title="Nexora RiskVault – SOC Risk Dashboard",
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
        .stSidebar {
            background-color: #111827;
            color: #E0E0E0;
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
        h1, h2, h3 {
            color: #60A5FA;
        }
    </style>
""", unsafe_allow_html=True)

# ------------------------------
# 🧠 SIDEBAR CONTROLS
# ------------------------------
st.sidebar.title("🧩 Nexora RiskVault Controls")

page = st.sidebar.radio(
    "📄 Select Page",
    ["Dashboard", "Attack Intelligence", "Database View", "About"],
)

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
# 🧾 LOAD DATA
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

# ✅ Verify essential columns exist
required_cols = {"timestamp", "source_ip", "event_type"}
missing = required_cols - set(df.columns)
if missing:
    st.error(f"❌ Missing required columns in uploaded data: {', '.join(missing)}")
    st.stop()

df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df = df.dropna(subset=["timestamp"])
df = df.sort_values("timestamp")

# ------------------------------
# 🧮 RISK CALCULATION
# ------------------------------
def risk_factors(event):
    if "fail" in str(event).lower():
        return 8, 5, detectability
    elif "conn" in str(event).lower():
        return 8, 5, detectability
    elif "process" in str(event).lower():
        return 9, 3, detectability
    else:
        return 2, 3, detectability

df[["Severity", "Probability", "Detectability"]] = df["event_type"].apply(lambda x: pd.Series(risk_factors(x)))
df["RPN"] = df["Severity"] * df["Probability"] * df["Detectability"]
df["Risk_Level"] = pd.cut(df["RPN"], bins=[0, 100, critical_rpn, np.inf], labels=["Low", "Moderate", "Critical"])

# ------------------------------
# 📊 PAGE 1: DASHBOARD
# ------------------------------
if page == "Dashboard":
    st.title("🛡️ Nexora RiskVault – SOC Risk Management Dashboard")
    st.caption("AMDEC + Attack Detection | Nexora Technologies © 2025")

    total_events = len(df)
    critical_events = len(df[df["RPN"] > critical_rpn])
    unique_sources = df["source_ip"].nunique()
    avg_rpn = df["RPN"].mean().round(1)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", total_events)
    col2.metric("Critical Events (RPN > 200)", critical_events)
    col3.metric("Unique Sources", unique_sources)
    col4.metric("Average RPN", avg_rpn)

    # 🔧 Aggregate AMDEC summary
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

    # ✅ FIX: Add Risk_Level back to summary
    amdec_summary["Risk_Level"] = pd.cut(
        amdec_summary["RPN"],
        bins=[0, 100, critical_rpn, np.inf],
        labels=["Low", "Moderate", "Critical"]
    )

    # 📊 Charts
    st.subheader("📊 Risk Distribution by Event Type")
    fig1 = px.bar(
        amdec_summary,
        x="RPN", y="event_type",
        color="Risk_Level",
        orientation="h",
        color_discrete_map={"Low": "#10B981", "Moderate": "#F59E0B", "Critical": "#EF4444"}
    )
    st.plotly_chart(fig1, use_container_width=True)

    st.subheader("🎯 Risk Composition")
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

    # 💾 Export
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine="xlsxwriter") as writer:
        df.to_excel(writer, sheet_name="Logs", index=False)
        amdec_summary.to_excel(writer, sheet_name="AMDEC Summary", index=False)
    st.download_button("📥 Download Excel Report", data=buffer.getvalue(), file_name="nexora_riskvault_report.xlsx")

# ------------------------------
# 📈 PAGE 2: ATTACK INTELLIGENCE
# ------------------------------
elif page == "Attack Intelligence":
    st.title("🧠 Threat & Attack Intelligence")
    st.caption("Live brute-force and anomaly detection")

    df["is_failed"] = df["event_type"].str.contains("fail", case=False)
    df["timestamp_diff"] = df["timestamp"].diff().dt.total_seconds().fillna(9999)

    suspicious_ips = []
    for ip, group in df[df["is_failed"]].groupby("source_ip"):
        bursts = (group["timestamp_diff"] < brute_window).sum()
        if bursts >= brute_attempts:
            suspicious_ips.append(ip)

    if suspicious_ips:
        st.warning(f"⚠️ Brute-force activity detected from: {', '.join(suspicious_ips)}")
    else:
        st.success("✅ No brute-force activity detected.")

    st.subheader("Recent Failed Logins")
    st.dataframe(df[df["is_failed"]].sort_values("timestamp", ascending=False), use_container_width=True)

# ------------------------------
# 🗄️ PAGE 3: DATABASE VIEW
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
# ℹ️ PAGE 4: ABOUT
# ------------------------------
else:
    st.title("ℹ️ About Nexora RiskVault")
    st.markdown("""
    **Nexora RiskVault** provides a low-cost, intelligent SOC dashboard  
    for monitoring, analyzing, and mitigating cybersecurity risks.

    **Features:**
    - AMDEC-based RPN scoring
    - Real-time attack intelligence
    - Visualization of risks and event trends
    - SQLite database integration
    - Excel report export

    **Developed by:** Nexora Technologies (2025)  
    **Lead Risk Analyst:** Adnan7860-ai
    """)
