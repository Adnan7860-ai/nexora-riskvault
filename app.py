import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from io import BytesIO

# ------------------------------
# ⚙️ App Configuration
# ------------------------------
st.set_page_config(
    page_title="Nexora RiskVault – Risk Management Dashboard",
    layout="wide",
    page_icon="🛡️"
)

# ------------------------------
# 🧩 Sidebar – Control Panel
# ------------------------------
st.sidebar.title("⚙️ Control Panel")

st.sidebar.subheader("📁 Data Source")
uploaded_file = st.sidebar.file_uploader("Upload your SOC log (CSV)", type=["csv"])
use_demo = st.sidebar.checkbox("Use demo data (if no upload)", value=True)

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.sidebar.success(f"Loaded {len(df)} events from uploaded file")
elif use_demo:
    df = pd.read_csv("sample_logs.csv")
    st.sidebar.info("Using demo dataset (sample_logs.csv)")
else:
    st.warning("Please upload a CSV or use demo data to continue.")
    st.stop()

# ------------------------------
# 🧮 Risk Parameters
# ------------------------------
st.sidebar.subheader("🧠 Risk Scoring Parameters")
detectability = st.sidebar.slider("Default Detectability (1-10)", 1, 10, 5)
critical_rpn = st.sidebar.number_input("Critical RPN threshold (🔴)", 50, 1000, 200, step=10)

# ------------------------------
# 🧠 Attack Detection Settings
# ------------------------------
st.sidebar.subheader("🛡️ Attack Detection Settings")
brute_window = st.sidebar.number_input("Brute-force window (seconds)", 10, 300, 60)
brute_attempts = st.sidebar.number_input("Brute-force attempts threshold", 2, 10, 3)

# ------------------------------
# 🔍 Data Preprocessing
# ------------------------------
df["timestamp"] = pd.to_datetime(df["timestamp"])
df = df.sort_values("timestamp")

# Detect brute-force attempts
df["is_failed"] = df["event_type"].str.contains("fail", case=False)
brute_force_ips = []
for ip, group in df[df["is_failed"]].groupby("source_ip"):
    times = group["timestamp"].diff().dt.total_seconds().fillna(9999)
    bursts = (times < brute_window).sum()
    if bursts >= brute_attempts:
        brute_force_ips.append(ip)

# ------------------------------
# 🧮 AMDEC RPN Calculation
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

df[["Severity", "Probability", "Detectability"]] = df["event_type"].apply(
    lambda x: pd.Series(risk_factors(x))
)
df["RPN"] = df["Severity"] * df["Probability"] * df["Detectability"]

df["Risk_Level"] = pd.cut(
    df["RPN"],
    bins=[0, 100, critical_rpn, np.inf],
    labels=["Low", "Moderate", "Critical"],
)

# ------------------------------
# 🧮 AMDEC Summary (aggregated)
# ------------------------------
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
amdec_summary["RPN"] = amdec_summary["RPN"].round(1)
amdec_summary["Suggested_Action"] = [
    "Lock account / Investigate IP / Increase monitoring" if "fail" in e else
    "Block IP / Firewall rule / Threat intel" if "conn" in e else
    "Investigate service / Patch / Restore" if "process" in e else
    "Monitor / Investigate"
    for e in amdec_summary["event_type"]
]

# ------------------------------
# 🧠 Dashboard Header
# ------------------------------
st.title("🛡️ Nexora RiskVault – Risk Management Dashboard")
st.caption("AMDEC + Attack Detection | Nexora Technologies © 2025")

st.info("📊 Upload your log CSV or use the demo data to perform live AMDEC-based risk analysis.")

# ------------------------------
# 🔢 KPIs
# ------------------------------
total_events = len(df)
critical_events = len(df[df["RPN"] > critical_rpn])
unique_sources = df["source_ip"].nunique()
avg_rpn = df["RPN"].mean().round(1)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", total_events)
col2.metric("Critical Events (RPN > 200)", critical_events)
col3.metric("Unique Sources", unique_sources)
col4.metric("Avg RPN", avg_rpn)

# ------------------------------
# 📊 Risk Charts
# ------------------------------
st.subheader("Top Risks (by RPN)")
fig1 = px.bar(
    amdec_summary,
    x="RPN",
    y="event_type",
    color="Risk_Level",
    orientation="h",
    color_discrete_map={"Low": "green", "Moderate": "orange", "Critical": "red"},
)
st.plotly_chart(fig1, use_container_width=True)

st.subheader("Risk Mix")
fig2 = px.pie(
    amdec_summary,
    names="Risk_Level",
    hole=0.4,
    color_discrete_map={"Low": "green", "Moderate": "orange", "Critical": "red"},
)
st.plotly_chart(fig2, use_container_width=True)

# ------------------------------
# 🧮 AMDEC Table
# ------------------------------
st.subheader("AMDEC Summary (Aggregated Incidents)")
st.dataframe(amdec_summary, use_container_width=True)

# ------------------------------
# 🔎 Filtered Logs
# ------------------------------
st.subheader("Event Logs (Filter by Risk Level)")
risk_filter = st.multiselect("Select Risk Levels", options=df["Risk_Level"].unique(), default=list(df["Risk_Level"].unique()))
filtered_df = df[df["Risk_Level"].isin(risk_filter)]
st.dataframe(filtered_df, use_container_width=True)

# ------------------------------
# ⚠️ Attack Detection Report
# ------------------------------
if brute_force_ips:
    st.warning(f"⚠️ Detected Brute-force Activity from {len(brute_force_ips)} IP(s): {', '.join(brute_force_ips)}")
else:
    st.success("✅ No brute-force activity detected within the configured window.")

# ------------------------------
# 💾 Export Data
# ------------------------------
st.subheader("Export Processed Data")
to_excel = BytesIO()
with pd.ExcelWriter(to_excel, engine='xlsxwriter') as writer:
    df.to_excel(writer, sheet_name="Logs", index=False)
    amdec_summary.to_excel(writer, sheet_name="AMDEC Summary", index=False)
st.download_button("📥 Download Excel Report", data=to_excel.getvalue(), file_name="nexora_riskvault_report.xlsx")
