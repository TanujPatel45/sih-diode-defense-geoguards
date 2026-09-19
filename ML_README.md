# GeoGuards Machine Learning & Detection Subsystem

This document provides a comprehensive technical guide to the machine learning pipelines, feature engineering schemas, specialized detector modules, rigorous leakage validation, and benchmarking suites within **GeoGuards** (Smart India Hackathon 2026, Problem Statement 26145: *AI-Based Detection of Cyber Threats in Unidirectional IP Traffic*).

---

## 1. Directory Structure

```
ml/
├── artifacts/              # Preprocessed data splits (.npz, .json)
├── reports/                # Rigorous validation, leakage, ablation & multi-seed reports
│   ├── overfitting_audit_initial.md
│   ├── duplicate_leakage_audit.json
│   ├── feature_leakage_audit.md
│   ├── ablation_results.json
│   ├── learning_curves.png
│   ├── learning_curve_analysis.md
│   ├── multi_seed_results.json
│   └── FINAL_VALIDATION_REPORT.md
├── scripts/
│   ├── audit_datasets.py        # Dataset auditing and manifest generation
│   ├── feature_schema.py        # Canonical feature definitions (V1 & V2)
│   ├── preprocess_data.py       # Data parsing and scaler generation
│   ├── train_models.py          # Multi-model training & baseline evaluation
│   └── rigorous_validation.py   # Day-isolated leakage audit & ablation suite
backend/
├── specialized_detectors.py# Detectors for 6 PS threat classes
├── correlation.py          # Cross-flow correlation & timeline tracker
├── streaming_engine.py     # Streaming PCAP replay engine
├── benchmark.py            # Latency and throughput benchmark suite
├── anomaly_detector.py     # Real-benign Isolation Forest
├── behaviour_analytics.py  # Statistical heuristic engine
├── risk_fusion.py          # Multi-signal risk fusion engine
├── schemas.py              # Pydantic standardized alert schemas
└── main.py                 # FastAPI application
```

---

## 2. Canonical Feature Schemas

### Baseline Feature Schema (V1 - 6 Attributes)
Lightweight representation optimized for sub-millisecond wire-speed processing:
1. `iat_mean`: Mean inter-arrival time between packets (seconds).
2. `iat_std`: Standard deviation of inter-arrival time (seconds).
3. `pkt_len_mean`: Mean packet length (bytes).
4. `pkt_len_std`: Standard deviation of packet length (bytes).
5. `payload_entropy`: Shannon entropy of concatenated flow payloads (0–8 bits).
6. `syn_ratio`: Ratio of TCP SYN packets to total flow packet count ($[0, 1]$).

### Expanded Metadata Schema (V2 - 25 Attributes)
Enhanced flow and protocol metadata for deeper representation:
- Temporal: `flow_duration`, `iat_mean`, `iat_std`, `iat_min`, `iat_max`
- Volume: `packet_count`, `byte_count`, `packets_per_second`, `bytes_per_second`
- Directional: `forward_packet_count`, `backward_packet_count`, `forward_bytes`, `backward_bytes`
- Packet Sizes: `pkt_len_mean`, `pkt_len_std`, `pkt_len_min`, `pkt_len_max`
- Protocol & State: `syn_count`, `rst_count`, `fin_count`, `syn_ratio`, `payload_entropy`, `src_port`, `dst_port`, `protocol`

---

## 3. Specialized Detection Ensembles

GeoGuards deploys dedicated detection engines for the **6 Problem Statement Threat Classes**:

1. **Volumetric / Protocol DDoS (`DDoSDetector`):**
   - High SYN ratio ($>0.80$), burst packet rate, small uniform packet sizes, high UDP PPS.
2. **Botnet C2 Beaconing (`C2BeaconDetector`):**
   - Inter-arrival time coefficient of variation ($CV < 0.25$), low jitter, periodic interval window, small keepalive packets.
3. **DGA Domains & DNS Tunnelling (`DNSTunnelDetector`):**
   - Subdomain Shannon entropy ($>3.6$ bits), query length ($>30$ chars), high query rate, character n-gram TF-IDF logistic regression classifier.
4. **Malware in Encrypted Sessions (`EncryptedTrafficDetector`):**
   - Metadata-only inspection of TLS/QUIC channels: packet size sequence variance, SNI entropy, handshake timing patterns without payload decryption.
5. **Reconnaissance & Port Scanning (`ReconScanDetector`):**
   - Short probe flows ($1-4$ packets), high SYN-to-data ratio, elevated TCP RST rates, fan-out host/port indexing.
6. **Data Exfiltration (`DataExfiltrationDetector`):**
   - Severe unilateral byte asymmetry (outbound/inbound ratio $>4.0$), sustained outbound volume ($>500$ KB), high payload entropy on bulk flow.

---

## 4. Rigorous Scientific Validation & Day-Isolated Evaluation

To ensure evaluation integrity, GeoGuards was subjected to a rigorous scientific audit eliminating all session and file-level overlap:

| Model Configuration | Feature Count | Day-Isolated Accuracy | Macro F1 | Benign FPR (False Alarms) | Avg Model Latency |
|---|---|---|---|---|---|
| **DiodeThreatNet V1 Baseline** | 6 | **80.51%** | **0.6445** | **1.040%** | **0.142 ms** |
| **DiodeThreatNet V2 Expanded** | 25 | **81.89%** | **0.8621** | **4.210%** | **0.202 ms** |
| **V2 Port-Agnostic (No Ports/Proto)** | 22 | **80.87%** | **0.8573** | **4.310%** | **0.195 ms** |
| **V2 Pure Telemetry (No Shortcuts)** | 21 | **82.02%** | **0.8864** | **1.800%** | **0.194 ms** |

### Additional Benchmark Components:
- **Zero-Day Unknown DNS Threat Detection Rate:** **95.06%** (Held-out Cobalt Strike, tcp-over-dns, ozymandns)
- **Multi-Seed Stability (5 Seeds):** `77.15% ± 2.62%` Accuracy | `0.5366 ± 0.1206` Macro F1
- **Isolation Forest Anomaly Baseline:** Fitted exclusively on clean Monday benign network flows.
- **End-to-End Pipeline Latency:** **6.833 ms avg** (P95: **10.723 ms**, well within the < 2.0s bounded SLA).
- **System Throughput:** **146.33 flows/second** sustained pipeline throughput.

---

## 5. One-Way Architecture & Passive Guarantees

- **Hardware Diode Enforced:** GeoGuards is designed to operate behind a hardware-enforced unidirectional boundary. The GeoGuards software layer itself is passive/read-only and performs no outbound probing, reciprocal communication, or inline mitigation.
- **Explainability First:** Every alert emitted contains a structured `evidence` array containing measurable forensic observations and interpretations.
