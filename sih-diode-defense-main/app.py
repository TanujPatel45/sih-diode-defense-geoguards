import streamlit as st
import pandas as pd
import numpy as np
import requests
import json
import os
import time

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="Diode Defense Streamlit Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .stApp { background-color: #030712; color: #f3f4f6; }
    .metric-card {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 16px;
        text-align: center;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    .metric-value { font-size: 2rem; font-weight: 700; color: #38bdf8; }
    .metric-label { font-size: 0.875rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }
    .status-badge {
        display: inline-block; padding: 4px 12px; border-radius: 9999px; font-weight: 600; font-size: 0.8rem;
    }
    .status-ok { background-color: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid #22c55e; }
    .status-alert { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
</style>
""", unsafe_allow_html=True)

# Sidebar Configuration
API_BASE_URL = st.sidebar.text_input("Backend API URL", value="http://127.0.0.1:8000")
st.sidebar.divider()
st.sidebar.title("🛡️ SIH 26145 Engine")
st.sidebar.caption("Unidirectional IP Cyber Threat Intelligence Enclave")

auto_refresh = st.sidebar.checkbox("🔄 Auto-Refresh Dashboard (5s)", value=False)

# Header
col_head1, col_head2 = st.columns([3, 1])
with col_head1:
    st.title("🛡️ DIODE DEFENSE // STREAMLIT MONITOR")
    st.caption("AI-Based Unidirectional Passive Threat Classifier & Risk Fusion Platform")

with col_head2:
    # Backend Health Check
    try:
        r = requests.get(f"{API_BASE_URL}/api/v1/health", timeout=3)
        if r.status_code == 200:
            health = r.json()
            st.markdown('<div style="text-align: right; padding-top: 15px;"><span class="status-badge status-ok">● BACKEND ONLINE</span></div>', unsafe_allow_html=True)
        else:
            st.markdown('<div style="text-align: right; padding-top: 15px;"><span class="status-badge status-alert">● BACKEND ERROR</span></div>', unsafe_allow_html=True)
    except Exception:
        st.markdown('<div style="text-align: right; padding-top: 15px;"><span class="status-badge status-alert">● BACKEND OFFLINE</span></div>', unsafe_allow_html=True)

st.divider()

# Tabs
tab_overview, tab_pcap, tab_simulator, tab_replay = st.tabs(["📊 Live Telemetry", "📁 PCAP Analyzer", "⚡ Traffic Simulator", "🎯 Guided Attack Replay"])

# --- TAB 1: OVERVIEW & TELEMETRY ---
with tab_overview:
    try:
        stats_resp = requests.get(f"{API_BASE_URL}/api/v1/stats", timeout=3)
        stats = stats_resp.json() if stats_resp.status_code == 200 else {}
    except Exception:
        stats = {}

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.metric("Total Flows", stats.get("total_flows_processed", 0))
    with m2:
        st.metric("Total Alerts", stats.get("total_alerts_generated", 0))
    with m3:
        st.metric("Anomalies Flagged", stats.get("anomalies_flagged", 0))
    with m4:
        st.metric("DNS Tunnels Detected", stats.get("dns_tunnels_detected", 0))
    with m5:
        st.metric("C2 Beacons Detected", stats.get("c2_beacons_detected", 0))

    st.divider()

    c_left, c_right = st.columns([1, 1])

    with c_left:
        st.subheader("📊 Threat Class Distribution")
        dist = stats.get("class_distribution", {})
        if dist:
            df_dist = pd.DataFrame(list(dist.items()), columns=["Classification", "Count"]).set_index("Classification")
            st.bar_chart(df_dist)
        else:
            st.info("No classification data recorded yet.")

    with c_right:
        st.subheader("🚨 Severity Breakdown")
        sev = stats.get("severity_breakdown", {})
        if sev:
            df_sev = pd.DataFrame(list(sev.items()), columns=["Severity", "Count"]).set_index("Severity")
            st.bar_chart(df_sev)
        else:
            st.info("No severity data recorded yet.")

    st.subheader("📜 Recent High-Risk Alerts")
    try:
        alerts_resp = requests.get(f"{API_BASE_URL}/api/v1/alerts?limit=15", timeout=3)
        if alerts_resp.status_code == 200:
            alerts = alerts_resp.json()
            if alerts:
                df_alerts = pd.DataFrame(alerts)
                cols_to_show = [c for c in ["timestamp", "src_ip", "dst_ip", "predicted_class", "confidence", "anomaly_score", "risk_score", "severity"] if c in df_alerts.columns]
                st.dataframe(df_alerts[cols_to_show], use_container_width=True)
            else:
                st.info("No alerts in MongoDB log.")
        else:
            st.error("Failed to fetch alerts from backend API.")
    except Exception as e:
        st.warning(f"Could not connect to alert log: {e}")

# --- TAB 2: PCAP ANALYZER ---
with tab_pcap:
    st.subheader("📁 Upload PCAP File for Passive Analysis")
    uploaded_pcap = st.file_uploader("Select a `.pcap` or `.pcapng` file", type=["pcap", "pcapng"])

    if uploaded_pcap is not None:
        if st.button("🔍 Analyze PCAP File", type="primary"):
            with st.spinner("Extracting unidirectional IP flows and classifying threats..."):
                try:
                    files = {"file": (uploaded_pcap.name, uploaded_pcap.getvalue(), "application/octet-stream")}
                    res = requests.post(f"{API_BASE_URL}/api/v1/analyze_pcap", files=files, timeout=30)
                    if res.status_code == 200:
                        data = res.json()
                        st.success(f"✅ Analyzed {data.get('flows_extracted', 0)} flows from {data.get('packets_processed', 0)} packets in {data.get('filename')}")
                        results = data.get("results", [])
                        if results:
                            df_pcap = pd.DataFrame(results)
                            st.dataframe(df_pcap, use_container_width=True)
                        else:
                            st.info("No active IP flows identified in PCAP.")
                    else:
                        st.error(f"Error analyzing PCAP: {res.text}")
                except Exception as ex:
                    st.error(f"Failed to submit PCAP to backend: {ex}")

# --- TAB 3: TRAFFIC SIMULATOR ---
with tab_simulator:
    st.subheader("⚡ Inject Demo Traffic Stream")
    sim_mode = st.selectbox("Select Traffic Profile", options=["mixed", "normal", "syn_flood", "dns_tunnel", "c2_beacon"])
    sim_count = st.slider("Number of Flows", min_value=1, max_value=50, value=10)
    sim_delay = st.slider("Delay per flow (seconds)", min_value=0.0, max_value=1.0, value=0.2, step=0.1)

    if st.button("🚀 Run Traffic Simulation", type="primary"):
        with st.spinner("Generating and classifying traffic flows..."):
            try:
                # Direct API calls for fast demo simulation
                sim_url = f"{API_BASE_URL}/api/v1/ingest_flow"
                # Sample templates
                samples = {
                    "normal": {"iat_mean": 0.05, "iat_std": 0.01, "pkt_len_mean": 512, "pkt_len_std": 80, "payload_entropy": 4.5, "syn_ratio": 0.05, "src_ip": "10.0.1.15", "dst_ip": "10.0.0.1", "src_port": 5000, "dst_port": 80},
                    "syn_flood": {"iat_mean": 0.0001, "iat_std": 0.00005, "pkt_len_mean": 60, "pkt_len_std": 2, "payload_entropy": 1.2, "syn_ratio": 0.99, "src_ip": "10.0.4.182", "dst_ip": "10.0.0.1", "src_port": 4000, "dst_port": 80},
                    "dns_tunnel": {"iat_mean": 0.02, "iat_std": 0.005, "pkt_len_mean": 850, "pkt_len_std": 120, "payload_entropy": 7.85, "syn_ratio": 0.01, "src_ip": "192.168.10.45", "dst_ip": "8.8.8.8", "src_port": 1200, "dst_port": 53},
                    "c2_beacon": {"iat_mean": 5.0, "iat_std": 0.01, "pkt_len_mean": 210, "pkt_len_std": 5, "payload_entropy": 6.8, "syn_ratio": 0.0, "src_ip": "172.16.0.88", "dst_ip": "91.195.240.117", "src_port": 50000, "dst_port": 443}
                }
                
                success_count = 0
                for i in range(sim_count):
                    mode = sim_mode if sim_mode != "mixed" else np.random.choice(["normal", "syn_flood", "dns_tunnel", "c2_beacon"])
                    payload = samples[mode].copy()
                    payload["src_port"] = int(np.random.randint(1024, 65535))
                    res = requests.post(sim_url, json=payload, timeout=5)
                    if res.status_code == 200:
                        success_count += 1
                    time.sleep(sim_delay)
                
                st.success(f"🎉 Injected and processed {success_count}/{sim_count} flow samples into Diode Defense pipeline!")
                st.rerun()
            except Exception as e:
                st.error(f"Simulation failed: {e}")

# --- TAB 4: GUIDED ATTACK REPLAY & CORRELATION ---
with tab_replay:
    st.subheader("🎯 Guided Multi-Stage Attack Replay & Correlation")
    st.caption("Replays actual PCAP traffic through ML model, Anomaly detector, Specialized engines, Risk Fusion, and Cross-Flow Correlation.")

    # Control buttons
    col_c1, col_c2, col_c3, col_c4 = st.columns(4)
    with col_c1:
        if st.button("🚀 Start Guided Replay", type="primary"):
            try:
                r = requests.post(f"{API_BASE_URL}/api/v1/attack-replay/start", json={"scenario_name": "Multi-Stage Exfiltration", "speed": 0.0}, timeout=5)
                st.info(r.json().get("message", "Replay started"))
                st.rerun()
            except Exception as ex:
                st.error(f"Failed to start replay: {ex}")
    with col_c2:
        if st.button("⏸️ Pause Replay"):
            try:
                r = requests.post(f"{API_BASE_URL}/api/v1/attack-replay/pause", timeout=5)
                st.info(r.json().get("message", "Replay paused"))
                st.rerun()
            except Exception as ex:
                st.error(f"Failed to pause replay: {ex}")
    with col_c3:
        if st.button("▶️ Resume Replay"):
            try:
                r = requests.post(f"{API_BASE_URL}/api/v1/attack-replay/resume", timeout=5)
                st.info(r.json().get("message", "Replay resumed"))
                st.rerun()
            except Exception as ex:
                st.error(f"Failed to resume replay: {ex}")
    with col_c4:
        if st.button("🔄 Reset Replay"):
            try:
                r = requests.post(f"{API_BASE_URL}/api/v1/attack-replay/reset", timeout=5)
                st.success(r.json().get("message", "Replay reset"))
                st.rerun()
            except Exception as ex:
                st.error(f"Failed to reset replay: {ex}")

    st.divider()

    # Query Status
    try:
        status_r = requests.get(f"{API_BASE_URL}/api/v1/attack-replay/status", timeout=3)
        status_data = status_r.json() if status_r.status_code == 200 else {}
    except Exception:
        status_data = {}

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Replay State", status_data.get("state", "IDLE"))
    with m2:
        st.metric("Active Stage", status_data.get("current_stage", "Not Started"))
    with m3:
        st.metric("Flows Processed", status_data.get("flows_processed", 0))
    with m4:
        st.metric("Alerts Generated", status_data.get("alerts_emitted", 0))

    st.divider()

    # Correlated Incident Card
    st.subheader("🔥 Correlated Multi-Stage Incident")
    try:
        inc_r = requests.get(f"{API_BASE_URL}/api/v1/attack-replay/incident", timeout=3)
        if inc_r.status_code == 200:
            inc_data = inc_r.json()
            if inc_data.get("cluster_id"):
                st.error(f"🚨 **CORRELATED MULTI-STAGE INCIDENT DETECTED** [{inc_data.get('cluster_id')}]")
                st.markdown(f"**Target Attacker Host**: `{inc_data.get('src_ip')}`")
                st.markdown(f"**Attack Progression Story**: `{inc_data.get('attack_story')}`")
                st.markdown(f"**Fused Correlation Risk Score**: `{inc_data.get('correlated_score', 0.0):.2f}` / 1.00")
                st.info(f"**Analyst Narrative**: {inc_data.get('narrative')}")
            else:
                st.info("No correlated multi-stage incident active yet. Click 'Start Guided Replay' above to trigger.")
    except Exception as ex:
        st.warning(f"Could not fetch incident status: {ex}")

    st.divider()

    # Chronological Timeline
    st.subheader("📜 Chronological Forensic Attack Timeline")
    try:
        tl_r = requests.get(f"{API_BASE_URL}/api/v1/attack-replay/timeline", timeout=3)
        if tl_r.status_code == 200:
            timeline_list = tl_r.json()
            if timeline_list:
                df_tl = pd.DataFrame(timeline_list)
                show_cols = [c for c in ["timestamp", "stage", "threat_category", "source_ip", "destination_ip", "destination_port", "risk_score", "severity"] if c in df_tl.columns]
                st.dataframe(df_tl[show_cols], use_container_width=True)
            else:
                st.info("No events in replay timeline yet.")
    except Exception as ex:
        st.warning(f"Could not fetch timeline: {ex}")

if auto_refresh:
    time.sleep(5)
    st.rerun()