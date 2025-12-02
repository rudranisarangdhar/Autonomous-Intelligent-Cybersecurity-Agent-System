import streamlit as st
import pandas as pd
import os
import time
import feedparser
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import numpy as np
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Multi-agent imports
from agents import (
    ThreatDetectionAgent,
    ThreatIntelAgent,
    AutoResponseAgent,
    SelfEvolvingAgent,
    SystemMonitorAgent
)

# ================================================================
# MUST BE FIRST STREAMLIT COMMAND
# ================================================================
st.set_page_config(
    page_title="AI Cybersecurity Multi-Agent System",
    layout="wide",
)

# ================================================================
# CUSTOM CSS (SAFE)
# ================================================================
cyber_css = """
<style>

/* PAGE BACKGROUND */
.main, .block-container {
    background-color: #0d1117 !important;
    color: white !important;
}

/* SIDEBAR */
[data-testid="stSidebar"] {
    background: #111827 !important;
    color: #ffffff !important;
}

/* TITLES */
h1, h2, h3, h4, h5 {
    color: #38bdf8 !important;
    font-weight: 700;
}

/* SUBHEADERS */
.block-container h2 {
    border-left: 5px solid #38bdf8;
    padding-left: 10px;
}

/* BUTTONS */
div.stButton > button {
    background-color: #1f6feb !important;
    color: white !important;
    border-radius: 8px !important;
}
div.stButton > button:hover {
    background-color: #388bfd !important;
}

/* CARDS */
.report-card {
    background: rgba(255,255,255,0.1) !important;
    padding: 18px !important;
    border-radius: 12px !important;
    border: 1px solid #1f2937 !important;
}

/* DATATABLE */
.dataframe th {
    background-color: #1f2937 !important;
    color: white !important;
}
.dataframe td {
    color: white !important;
}

/* BACKGROUND IMAGE */
body {
    background-image: url('background.jpg');
    background-size: cover;
    background-attachment: fixed;
}

/* NEON BOX */
.neon-box {
    padding: 15px;
    border-radius: 10px;
    background:#0e7490;
    color:white;
    box-shadow: 0 0 15px #38bdf8;
    margin-bottom: 20px;
}

</style>
"""
st.markdown(cyber_css, unsafe_allow_html=True)

# Neon box
st.markdown(
    '<div class="neon-box">Cybersecurity Multi-Agent System Active</div>',
    unsafe_allow_html=True
)

# ================================================================
# PAGE TITLE
# ================================================================
st.title("🛡 AI Cybersecurity Intelligence System")
st.write("Universal Dataset Support • Multi-Agent Defense • Auto-Response • Threat Intel • CVEs • Timeline • PDF Reports")

# ================================================================
# UNIVERSAL DATASET CONVERTER
# ================================================================
def convert_to_required(df):
    """Auto-convert ANY dataset to required 8 ML features."""

    required = {
        "duration": ["duration", "flow_duration", "flow time", "connection_time"],
        "src_bytes": ["src_bytes", "total_fwd_bytes", "fwd_bytes"],
        "dst_bytes": ["dst_bytes", "total_bwd_bytes", "bwd_bytes"],
        "flag": ["flag", "flags", "tcp_flags"],
        "failed_logins": ["failed_logins", "login_fails", "auth_failures"],
        "hot": ["hot", "num_hot", "hot_count"],
        "same_srv_rate": ["same_srv_rate", "srv_rate", "service_rate"],
        "packets": ["packets", "total_packets", "pkt_count", "fwd_pkt_count", "bwd_pkt_count"]
    }

    new_df = pd.DataFrame()

    for target, aliases in required.items():
        found = False

        for col in df.columns:
            if col.lower().replace(" ", "_") in aliases:
                new_df[target] = df[col]
                found = True
                break

        if not found:
            if target in ["duration", "src_bytes", "dst_bytes", "packets"]:
                new_df[target] = df.select_dtypes(include=[np.number]).mean(axis=1).fillna(1)
            elif target == "flag":
                new_df[target] = 0
            elif target == "failed_logins":
                new_df[target] = 0
            elif target == "hot":
                new_df[target] = np.random.randint(0, 5, len(df))
            elif target == "same_srv_rate":
                new_df[target] = np.random.uniform(0.2, 0.8, len(df))

    for col in new_df.columns:
        new_df[col] = pd.to_numeric(new_df[col], errors="coerce").fillna(0)

    return new_df

# ================================================================
# RSS FEED SYSTEM
# ================================================================
st.sidebar.title("📰 Cybersecurity News & CVEs")

def show_rss_feed(title, url):
    st.sidebar.subheader(title)
    try:
        feed = feedparser.parse(url)
        for entry in feed.entries[:5]:
            st.sidebar.markdown(f"**{entry.title}**")
            if hasattr(entry, "summary"):
                st.sidebar.write(entry.summary[:160] + "...")
            st.sidebar.markdown(f"[Read more]({entry.link})")
            st.sidebar.write("---")
    except:
        st.sidebar.write("Unable to load feed.")

show_rss_feed("🟠 Latest Cybersecurity News", "https://feeds.feedburner.com/TheHackersNews")
show_rss_feed("🔴 Latest CVEs", "https://www.cvedetails.com/vulnerability-feed.php")

# ================================================================
# PDF Export Function
# ================================================================
def export_pdf(filename, summary_text, df):
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    y = height - 50

    c.setFont("Helvetica-Bold", 20)
    c.drawString(40, y, "Cybersecurity Threat Intelligence Report")
    y -= 40

    c.setFont("Helvetica", 12)
    c.drawString(40, y, "Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    y -= 30

    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "Summary")
    y -= 20

    c.setFont("Helvetica", 10)
    for line in summary_text.split("\n"):
        if y < 50:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 10)
        c.drawString(40, y, line)
        y -= 15

    c.save()

# ================================================================
# TIMELINE FUNCTIONS
# ================================================================
def build_attack_timeseries(df):
    df2 = df.copy()

    df2["timestamp"] = pd.to_datetime(df2.get("timestamp"), errors="coerce")
    if df2["timestamp"].isna().any():
        df2["timestamp"] = pd.date_range(
            end=datetime.now(), periods=len(df2), freq="min"
        )

    df2["attack_type"] = (
        df2.get("attack_type", df2["pred"].map({1: "unknown_attack", 0: "benign"}))
        .astype(str)
        .str.replace(r"[\[\]\']", "", regex=True)
        .str.split(",")
        .str[0]
        .str.strip()
    )

    df2["date"] = df2["timestamp"].dt.floor("D")
    daily = df2.groupby("date").size()

    try:
        pivot = df2.pivot_table(
            index="date",
            columns="attack_type",
            values="attack_type",
            aggfunc="count",
            fill_value=0,
        )
    except:
        pivot = None

    return daily, pivot


def plot_daily_attacks(daily, pivot, container):
    fig1, ax1 = plt.subplots()
    ax1.plot(daily.index, daily.values, marker="o")
    ax1.set_title("Daily Total Events")
    container.pyplot(fig1)

    if pivot is not None:
        fig2, ax2 = plt.subplots()
        ax2.stackplot(
            pivot.index,
            [pivot[c].values for c in pivot.columns],
            labels=pivot.columns,
        )
        ax2.legend(loc="upper left")
        ax2.set_title("Daily Attack Types")
        container.pyplot(fig2)

# ================================================================
# INIT AGENTS
# ================================================================
if not os.path.exists("model.joblib"):
    st.warning("⚠ No model found, run train.py first.")

det = ThreatDetectionAgent() if os.path.exists("model.joblib") else None
intel = ThreatIntelAgent()
resp = AutoResponseAgent()
evo = SelfEvolvingAgent()
monitor = SystemMonitorAgent()

# ================================================================
# FILE UPLOAD + UNIVERSAL CONVERSION
# ================================================================
st.header("📤 Upload Network Dataset")

uploaded = st.file_uploader("Upload ANY CSV Network Log:", type=["csv"])

if uploaded and det is not None:
    df = pd.read_csv(uploaded)

    # Auto-map any dataset → required ML fields
    clean = convert_to_required(df)

    df["pred"], df["prob"] = det.detect(clean)
    df = intel.analyze(df)
    df = resp.respond(df)

    st.subheader("🔍 Converted & Analyzed Data")
    st.dataframe(df)

    # Self-evolving model
    accuracy = 1 - abs(df["pred"] - df.get("label", df["pred"])).mean()
    _, msg = evo.check_and_retrain(accuracy)
    st.subheader("🧠 Self-Evolving Model")
    st.write(msg)

    # Timeline
    st.header("📈 Daily Attack Timeline")
    daily, pivot = build_attack_timeseries(df)
    plot_daily_attacks(daily, pivot, st)

    # Summary
    st.header("📝 Threat Summary")
    summary_text = f"""
Total records: {len(df)}
Detected attacks: {df['pred'].sum()}
Top attack types: {df['pred'].value_counts().to_dict()}
"""
    st.markdown(summary_text)

    # PDF Export
    if st.button("📄 Export PDF Report"):
        fname = "threat_report.pdf"
        export_pdf(fname, summary_text, df)
        with open(fname, "rb") as f:
            st.download_button("Download PDF", f, file_name=fname, mime="application/pdf")

# ================================================================
# REAL-TIME SYSTEM MONITOR
# ================================================================
st.header("🖥 Real-Time System Monitor")

start = st.button("Start Monitoring")
stop_area = st.empty()

if start:
    stop_btn = stop_area.button("Stop")

    live = st.empty()
    st.info("Monitoring every 2 seconds...")

    while True:
        d = monitor.monitor()

        live.markdown(f"""
### Live Status
**CPU:** {d['cpu']}%  
**Free RAM:** {d['free_ram_mb']} MB  
**SYN Count:** {d['syn_count']}  
**Top IP:** {d['top_ip']}  
""")

        if d["cpu"] > 80:
            st.error("⚠ HIGH CPU USAGE")
        if d["free_ram_mb"] < 500:
            st.error("⚠ LOW MEMORY")
        if d["syn_count"] > 20:
            st.warning("⚠ SYN FLOOD DETECTED")

        time.sleep(2)
        if stop_btn:
            st.success("🛑 Monitoring stopped.")
            break
