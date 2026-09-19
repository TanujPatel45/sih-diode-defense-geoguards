<<<<<<< HEAD
# GeoGuards — Passive Cyber Intelligence for Unidirectional Networks

**Smart India Hackathon 2026 · Problem Statement 26145**  
**Theme: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**  
**Team: GeoGuards**

---

## 🛡️ Executive Summary

GeoGuards is an AI-assisted passive cyber threat intelligence command center engineered specifically for **unidirectional network environments (data diodes)**. It ingests mirror traffic copies, extracts 5-tuple flow telemetry, and executes a multi-pillar detection consensus across all six Problem Statement threat categories without ever sending return traffic or actively probing the protected network.

```
Unidirectional Traffic Copy (PCAP or Streaming Ingestion)
                         ↓
               5-Tuple Flow Extraction
          (src_ip, dst_ip, src_port, dst_port, proto)
                         ↓
             Canonical Flow Metadata (V1: 6 / V2: 25 features)
                         ↓
  ┌─────────────────────────────────────────────────────────┐
  │              PARALLEL MULTI-SIGNAL DETECTION            │
  │                                                         │
  │  ① Supervised Classifier                                │
  │     DiodeThreatNet (PyTorch MLP, V1 Baseline & V2)      │
  │     Classes: Benign, SYN/UDP Flood,                     │
  │     DNS Tunneling, C2 Beaconing                         │
  │                                                         │
  │  ② Real-Benign Anomaly Detection                        │
  │     Isolation Forest (fitted on clean Monday benign)    │
  │     Flags outlier deviations from benign baseline       │
  │                                                         │
  │  ③ Specialized Threat Detectors                         │
  │     DDoS, C2 Beaconing, DGA / DNS Tunnel,               │
  │     Reconnaissance, Data Exfiltration, Encrypted TLS    │
  └─────────────────────────────────────────────────────────┘
                         ↓
                 Risk Fusion Engine
     (Multi-Signal Bayesian / Linear Consensus Formulation)
                         ↓
       Cross-Flow Host & Temporal Correlation Engine
                         ↓
                 Explainable Alert
         (Evidence-backed JSON schema with forensic items)
                         ↓
          FastAPI Backend → Next.js SOC Dashboard
```

> [!IMPORTANT]
> **Strict Passive Monitoring**: GeoGuards is designed to operate behind a hardware-enforced unidirectional boundary. The GeoGuards software layer itself is passive/read-only and performs no outbound probing, reciprocal communication, or inline mitigation.

---

## 🔬 Rigorous Scientific Validation Summary

To eliminate data leakage, GeoGuards models were evaluated under **strict day and capture isolation** (training on Monday Benign & Wednesday DoS; testing on unseen Friday Benign & Friday DDoS):

| Metric / Benchmark | Model V1 Baseline (6 Feat) | Model V2 Expanded (25 Feat) | Model V2 Pure Telemetry (21 Feat) |
|---|---|---|---|
| **Day-Isolated Accuracy** | **80.51%** | **81.89%** | **82.02%** |
| **Macro F1 Score** | **0.6445** | **0.8621** | **0.8864** |
| **Benign False Alarm Rate (FPR)** | **1.04%** | **4.21%** | **1.80%** |
| **Model Inference Latency** | **0.142 ms** | **0.202 ms** | **0.194 ms** |
| **End-to-End Pipeline Latency** | **6.833 ms avg** (P95: 10.723 ms) — well within the < 2.0s SLA | | |
| **Held-out Zero-Day DNS Generalization** | **95.06% threat detection rate** on unseen Cobalt Strike / tcp-over-dns | | |

---

## 🚀 5-Minute SIH Demo Sequence

1. **Overview Dashboard (`/`)**:
   - Inspect the **One-Way Network Topology** card showing 0 return packets.
   - Verify **System Operational** and **One-Way Ingestion** status pills in the TopBar.
2. **Instant Attack Simulator (`/` or `/demo`)**:
   - Click **"🔴 SYN Flood"** in the Overview quick bar: Watch the real-time risk chart spike and new alert appear.
   - Click **"🔵 DNS Tunnel"**: Observe high payload entropy detection on UDP port 53.
   - Click **"🟠 C2 Beacon"**: Observe periodic interval jitter analysis flagging beacon behavior.
3. **Alert Investigation Drawer (`/threats`)**:
   - Click any alert row to slide open the **Investigation Drawer**.
   - Inspect the multi-pillar breakdown (Classifier confidence %, Anomaly score %, Behaviour score %).
   - Review the structured forensic evidence items and probabilistic analyst explanation.
4. **Detection Engine Architecture (`/detection`)**:
   - Review the mathematical consensus formula and specialized detector status.
5. **PCAP Analysis & Streaming Replay (`/pcap`)**:
   - Upload any `.pcap` capture file to execute passive flow reconstruction, or click **"Start Streaming Replay"** to stream packets with real-time bounded latency SLA badges.

---

## 🛠️ Quick Start

### Backend (FastAPI)

```bash
cd backend
pip install -r ../requirements.txt

# Start backend daemon
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
- API Endpoint: `http://localhost:8000`
- Swagger Docs: `http://localhost:8000/docs`

### Frontend (Next.js 16)

```bash
cd frontend
npm install
npm run dev
```
- Dashboard: `http://localhost:3000`

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Backend status, model version, and storage mode |
| `GET` | `/api/v1/stats` | Real operational telemetry counters |
| `GET` | `/api/v1/alerts` | Paginated threat alerts stream |
| `GET` | `/api/v1/flows` | Ingested flows including benign baseline |
| `POST` | `/api/v1/analyze-flow` | Process 5-tuple flow through multi-signal pipeline |
| `POST` | `/api/v1/analyze-pcap` | Upload `.pcap` for offline flow extraction |
| `POST` | `/api/v1/stream-pcap` | Start bounded-latency streaming PCAP replay |
| `GET` | `/api/v1/correlation/clusters` | Host-level cross-flow correlated attack campaigns |
| `POST` | `/api/v1/attack-replay/start` | Start guided multi-stage attack replay |
| `POST` | `/api/v1/attack-replay/pause` | Pause active attack replay |
| `POST` | `/api/v1/attack-replay/resume` | Resume paused attack replay |
| `POST` | `/api/v1/attack-replay/reset` | Reset replay state and correlation history |
| `GET` | `/api/v1/attack-replay/status` | Get guided replay status & active stage |
| `GET` | `/api/v1/attack-replay/timeline` | Get chronological forensic attack timeline |
| `GET` | `/api/v1/attack-replay/incident` | Get resulting correlated multi-stage attack story |

---

## 🎯 Guided Multi-Stage Attack Replay & Correlation

Demonstrates a complete 4-stage cyber attack lifecycle (**Multi-Stage Exfiltration**):

```text
Reconnaissance → C2 Beaconing → DNS Tunnelling → Data Exfiltration
                               ↓
           ONE CORRELATED MULTI-STAGE INCIDENT
```

- **Reuses Existing Architecture**: Passes traffic through `StreamingReplaySession`, `DiodeThreatNet`, `IsolationForestDetector`, `UnifiedSpecializedDetectorRegistry`, `RiskFusionEngine`, and `ThreatCorrelationEngine`.
- **Zero Frontend UI Modifications**: Backend REST API driven; clean separation of concerns.
- **Passively Safe**: Analysis-only execution without network probing or outbound packet generation.

**Run Guided Replay Test Suite**:
```bash
python -m pytest backend/tests/test_specialized_and_safety.py backend/tests/test_guided_replay.py
```

---

## 📁 Repository Structure

```
sih-diode-defense-main/
├── backend/
│   ├── main.py                  # FastAPI application & endpoints
│   ├── anomaly_detector.py      # Real-Benign Isolation Forest anomaly engine
│   ├── behaviour_analytics.py   # Statistical heuristic engine
│   ├── specialized_detectors.py # Specialized detectors for 6 PS threat classes
│   ├── correlation.py           # Cross-flow threat correlation engine
│   ├── streaming_engine.py      # Streaming PCAP replay engine
│   ├── benchmark.py             # Latency & throughput benchmark suite
│   ├── risk_fusion.py           # Multi-pillar risk consensus fusion
│   ├── pcap_analyzer.py         # Scapy flow extraction & PCAP processor
│   ├── schemas.py               # Pydantic standardized alert schemas
│   ├── diode_threat_model.pth   # PyTorch DiodeThreatNet weights
│   └── scaler.pkl               # Standard feature scaler
├── ml/
│   ├── reports/                 # Rigorous validation reports, curves, and audits
│   └── scripts/                 # Preprocessing, training, and validation scripts
├── frontend/
│   ├── app/
│   │   ├── page.tsx             # Overview SOC Dashboard
│   │   ├── threats/             # Threats Feed with severity filter
│   │   ├── flows/               # Flow Explorer with 25 metadata features
│   │   ├── detection/           # Detection Engine & Consensus weights
│   │   ├── analytics/           # Risk distribution & telemetry
│   │   ├── pcap/                # PCAP upload & streaming replay suite
│   │   ├── demo/                # Controlled Synthetic Attack Lab
│   │   ├── monitor/             # Real-time passive stream monitor
│   │   └── components/          # Reusable glassmorphic SOC components
│   └── package.json
├── ML_README.md                 # Complete ML subsystem documentation
├── MODEL_CARD.md                # Standardized AI model card
└── README.md
```
=======
# sih-diode-defense-geoguards
>>>>>>> 8cdfe85fabcc775dffae087c7f33d81462e14eab
