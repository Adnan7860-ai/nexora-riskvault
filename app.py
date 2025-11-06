# app.py
import io
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st
from datetime import datetime

# ---------- CONFIG ----------
st.set_page_config(page_title="Nexora RiskVault Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ Nexora RiskVault – Risk Management Dashboard")
st.caption("Low-Cost SOC Prototype — AMDEC + Attack Detection | © Nexora Technologies 2025")

# ---------- SIDEBAR: Upload + Settings ----------
st.sidebar.header("1) Upload & Settings")
uploaded_file = st.sidebar.file_uploader("Upload log CSV (timestamp,event_type,source_ip,...)", type=["csv"])
use_demo = st.sidebar.checkbox("Use demo data (if no upload)", value=True)

st.sidebar.markdown("**Scoring / thresholds**")
detect_default = st.sidebar.slider("Default Detectability (1-10)", 1, 10, 5)
critical_rpn = st.sidebar.number_input("Critical RPN threshold (🔴)", min_value=50, max_value=500, value=200, step=10)
bruteforce_window = st.sidebar.number_input("Brute-force window (seconds)", min_value=10, max_value=300, value=60)
bruteforce_attempts = st.sidebar.number_input("Brute-force attempts threshold", min_value=2, max_value=50, value=3)

st.sidebar.markdown("---")
st.sidebar.caption("Tip: upload sanitized logs with timestamp, event_type, source_ip, dst_port, message")

# ---------- DEMO DATA ----------
def demo_df():
    rows = [
        {"timestamp":"2025-11-01 09:01:00","event_type":"failed_login","source_ip":"10.0.0.10","destination_ip":"192.168.1.10","src_port":55512,"dst_port":22,"username":"alice","message":"Invalid password"},
        {"timestamp":"2025-11-01 09:01:10","event_type":"failed_login","source_ip":"10.0.0.10","destination_ip":"192.168.1.10","src_port":55513,"dst_port":22,"username":"alice","message":"Invalid password"},
        {"timestamp":"2025-11-01 09:01:20","event_type":"failed_login","source_ip":"10.0.0.10","destination_ip":"192.168.1.10","src_port":55514,"dst_port":22,"username":"alice","message":"Invalid password"},
        {"timestamp":"2025-11-02 12:10:00","event_type":"process_crash","source_ip":"185.22.33.44","destination_ip":"192.168.1.20","src_port":0,"dst_port":0,"username":"system","message":"Service crash"},
        {"timestamp":"2025-11-03 10:00:00","event_type":"conn_attempt","source_ip":"203.0.113.9","destination_ip":"192.168.1.30","src_port":40000,"dst_port":23,"username":"","message":"telnet"},
        {"timestamp":"2025-11-03 10:00:05","event_type":"conn_attempt","source_ip":"203.0.113.9","destination_ip":"192.168.1.31","src_port":40001,"dst_port":23,"username":"","message":"telnet"},
        {"timestamp":"2025-11-03 10:00:10","event_type":"conn_attempt","source_ip":"203.0.113.9","destination_ip":"192.168.1.32","src_port":40002,"dst_port":23,"username":"","message":"telnet"},
        {"timestamp":"2025-11-04 11:00:00","event_type":"success","source_ip":"10.0.0.3","destination_ip":"192.168.1.40","src_port":60000,"dst_port":443,"username":"bob","message":"OK"},
    ]
    return pd.DataFrame(rows)

# ---------- LOAD DATA ----------
if uploaded_file:
    df = pd.read_csv(uploaded_file, parse_dates=["timestamp"], infer_datetime_format=True)
    st.success("✅ CSV uploaded")
elif use_demo:
    df = demo_df()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    st.info("Using demo dataset (use your CSV to analyze real logs)")
else:
    st.warning("Please upload a CSV file or enable demo data in the sidebar.")
    st.stop()

# standardize columns
for c in ["timestamp","event_type","source_ip","destination_ip","src_port","dst_port","username","message"]:
    if c not in df.columns:
        df[c] = np.nan

df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df.sort_values("timestamp", inplace=True)

# ---------- SIMPLE ATTACK DETECTION RULES ----------
# 1) Brute-force / failed-login bursts: count failed_login per source in sliding window
df["is_failed_login"] = df["event_type"].str.contains("failed_login|failed_auth|login_failed", case=False, na=False)

# mark brute force events:
bf_events = []
for src, g in df[df["is_failed_login"]].groupby("source_ip"):
    times = g["timestamp"].dropna().sort_values()
    # sliding window approach: for simplicity, compute counts in each row's window
    counts = []
    for t in times:
        lower = t - pd.Timedelta(seconds=bruteforce_window)
        c = times[(times >= lower) & (times <= t)].count()
        counts.append((t, c))
    # store back
    for t, c in counts:
        idx = df[(df["source_ip"] == src) & (df["timestamp"] == t)].index
        if len(idx):
            df.loc[idx, "bf_count"] = c

df["bf_count"] = df["bf_count"].fillna(0).astype(int)
df["bruteforce_flag"] = df["bf_count"] >= int(bruteforce_attempts)

# 2) Port-scan / multi-destination attempt in short time => conn_attempt with many dst_ips
scan_flags = []
for src, g in df[df["event_type"].str.contains("conn_attempt|conn|portscan|scan", case=False, na=False)].groupby("source_ip"):
    times = g["timestamp"].dropna().sort_values()
    dest_counts = g.groupby("timestamp")["destination_ip"].nunique()  # approximation
    # mark sources with >2 distinct destinations total in short time window
    unique_dests = g["destination_ip"].nunique()
    flag = unique_dests >= 3
    df.loc[df["source_ip"] == src, "scan_flag"] = flag

df["scan_flag"] = df["scan_flag"].fillna(False)

# 3) Suspicious IP list (example)
suspicious_ips = {"203.0.113.9", "185.22.33.44"}
df["suspicious_ip_flag"] = df["source_ip"].isin(suspicious_ips)

# ---------- MAP TO AMDEC / RPN SCORES ----------
# Severity mapping by event_type and flags (base severity)
sev_map = {
    "critical": 9, "process_crash": 9, "error": 8, "failed_login": 7,
    "conn_attempt": 6, "warning": 6, "info": 3, "success": 2
}
df["Severity"] = df["event_type"].str.lower().map(sev_map).fillna(5).astype(int)

# Increase severity if flags present
df.loc[df["bruteforce_flag"], "Severity"] = df.loc[df["bruteforce_flag"], "Severity"].apply(lambda x: min(9, max(x, 8)))
df.loc[df["scan_flag"], "Severity"] = df.loc[df["scan_flag"], "Severity"].apply(lambda x: min(9, max(x, 7)))
df.loc[df["suspicious_ip_flag"], "Severity"] = df.loc[df["suspicious_ip_flag"], "Severity"].apply(lambda x: min(9, max(x, 8)))

# Probability: derived from frequency of event types per source and historical counts
freq = df.groupby("source_ip").size().to_dict()
df["Probability"] = df["source_ip"].map(lambda s: freq.get(s, 0))
# bucket probabilities to scores 3/5/8
df["Probability"] = df["Probability"].apply(lambda x: 8 if x >= 10 else (5 if x >= 3 else 3))

# Detectability: default slider unless specific detection difficulty in logs
df["Detectability"] = detect_default

# RPN
df["RPN"] = (df["Severity"] * df["Probability"] * df["Detectability"]).astype(int)

# Risk level
def classify(r):
    if r > critical_rpn: return "🔴 Critical"
    if r >= 100: return "🟡 Moderate"
    return "🟢 Low"
df["Risk_Level"] = df["RPN"].apply(classify)

# ---------- AGGREGATE AMDEC-LIKE TABLE (group by incident type) ----------
amdec = df.groupby(["event_type"]).agg({
    "Severity":"max",
    "Probability":"max",
    "Detectability":"max",
    "RPN":"max",
    "source_ip":"nunique",
    "message":"count"
}).rename(columns={"source_ip":"unique_sources","message":"occurrences"}).reset_index()

# Add suggested action column (basic mapping)
def suggest_action(evt):
    if "failed_login" in str(evt): return "Lock account / Investigate IP / Increase MFA"
    if "conn_attempt" in str(evt) or "scan" in str(evt): return "Block IP / Firewall rule / Threat intel"
    if "process_crash" in str(evt) or "critical" in str(evt): return "Investigate service / Patch / Restore"
    return "Monitor / Investigate"

amdec["Suggested_Action"] = amdec["event_type"].apply(suggest_action)

# ---------- KPI / DASH ----------
c1, c2, c3, c4 = st.columns([1.5,1,1,1])
c1.metric("Total Events", f"{len(df):,}")
c2.metric("Critical Events (RPN > {})".format(critical_rpn), int((df["RPN"] > critical_rpn).sum()))
c3.metric("Unique Sources", int(df["source_ip"].nunique()))
c4.metric("Avg RPN", round(df["RPN"].mean(),1))

st.markdown("---")

# Top risks
st.subheader("Top Risks (by RPN)")
topn = df.sort_values("RPN", ascending=False).head(12)
fig = px.bar(topn, x="RPN", y="event_type", color="Risk_Level", orientation="h",
             color_discrete_map={"🔴 Critical":"#dc2626","🟡 Moderate":"#f59e0b","🟢 Low":"#22c55e"})
st.plotly_chart(fig, use_container_width=True)

# Risk mix donut
st.subheader("Risk Mix")
rct = df["Risk_Level"].value_counts().reset_index()
rct.columns = ["Risk_Level","count"]
fig2 = px.pie(rct, values="count", names="Risk_Level", hole=0.5,
              color="Risk_Level", color_discrete_map={"🔴 Critical":"#dc2626","🟡 Moderate":"#f59e0b","🟢 Low":"#22c55e"})
st.plotly_chart(fig2, use_container_width=True)

# Criticality heatmap
st.subheader("Criticality Matrix (Severity × Probability)")
heat = df.pivot_table(index="Severity", columns="Probability", values="RPN", aggfunc="mean")
fig3 = px.imshow(heat.fillna(0), text_auto=True, color_continuous_scale=["#C8E6C9","#FFF59D","#FFCC80","#EF5350"])
st.plotly_chart(fig3, use_container_width=True)

st.markdown("---")

# Show AMDEC aggregated table
st.subheader("AMDEC Summary (aggregated incidents)")
st.dataframe(amdec.sort_values("RPN", ascending=False), use_container_width=True)

# Show raw events filtered by risk
st.subheader("Events (filterable)")
risk_filter = st.multiselect("Filter by Risk Level", options=df["Risk_Level"].unique(), default=df["Risk_Level"].unique())
st.dataframe(df[df["Risk_Level"].isin(risk_filter)].sort_values("RPN", ascending=False), use_container_width=True)

# ---------- EXPORTS ----------
st.markdown("---")
st.subheader("Export processed data")

# CSV processed
csv_bytes = df.to_csv(index=False).encode("utf-8")
st.download_button("Download Processed CSV", csv_bytes, "processed_logs.csv", "text/csv")

# Excel: AMDEC + raw + heatmap sheet
def to_excel_bytes(raw_df, amdec_df, heat_df):
    out = io.BytesIO()
    with pd.ExcelWriter(out, engine="xlsxwriter") as writer:
        raw_df.to_excel(writer, sheet_name="RawEvents", index=False)
        amdec_df.to_excel(writer, sheet_name="AMDEC_Summary", index=False)
        heat_df.fillna(0).to_excel(writer, sheet_name="Criticality", index=True)
    return out.getvalue()

excel_bytes = to_excel_bytes(df, amdec, heat)
st.download_button("Download Excel (AMDEC + Raw + Criticality)", excel_bytes,
                   "nexora_riskvault_report.xlsx",
                   "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

st.caption("RPN = Severity × Probability × Detectability. Adjust scoring in sidebar. Rules: brute-force (failed_login bursts), scan detection (conn_attempt multi-dest), suspicious IP list.")
