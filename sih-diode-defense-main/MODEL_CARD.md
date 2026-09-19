# GeoGuards Model Card

**Model Name:** DiodeThreatNet & Specialized Metadata Threat Ensemble  
**Version:** v2.0-rc1 (SIH 2026 PS ID: 26145)  
**Task:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Organization / Team:** GeoGuards  

---

## 1. Model Purpose & Intended Use
GeoGuards is designed for **passive, non-intrusive threat monitoring** in high-security unidirectional network architectures (e.g., physical optical data diodes). The system monitors one-way tapped IP traffic streams to detect cyber threats across six core problem statement categories without requiring payload decryption, active probing, or reciprocal packet transmission.

> [!IMPORTANT]
> **Operational Boundary:** GeoGuards is designed to operate behind a hardware-enforced unidirectional boundary. The GeoGuards software layer itself is passive/read-only and performs no outbound probing, reciprocal communication, or inline mitigation.

### Intended Use Cases
- High-assurance air-gapped or diode-isolated operational technology (OT/ICS) networks.
- Passive network tap monitoring on egress/ingress enterprise perimeters.
- Real-time flow classification and multi-signal risk prioritization for SOC analysts.

### Out-of-Scope / Prohibited Uses
- Active inline prevention (IPS) or bidirectional TCP reset injection across the diode ingest path.
- Deep payload decryption of end-to-end encrypted TLS/QUIC sessions.
- Reliance on active ICMP pings or port scanning towards the monitored network.

---

## 2. Architecture & Pipeline Overview
The GeoGuards system adopts a **multi-signal ensemble architecture**:

```
UNIDIRECTIONAL IP INGEST (Hardware Diode Tapped)
               │
               ▼
   5-Tuple Session Aggregator
               │
               ▼
    Canonical Feature Pipeline
   (iat_mean, iat_std, pkt_len_mean, pkt_len_std, entropy, syn_ratio + 25 extended metadata)
               │
       ┌───────┼───────────────────────┬────────────────────────┐
       ▼       ▼                       ▼                        ▼
DiodeThreatNet  Real-Benign        Behaviour Heuristics   Specialized Detectors
 (6/25 MLP)   Isolation Forest    (C2 Jitter, DNS Rate)  (DDoS, DGA, Exfil, Recon, TLS)
       │       │                       │                        │
       └───────┼───────────────────────┴────────────────────────┘
               │
               ▼
       Risk Fusion Engine (Configurable Bayesian/Linear Weights)
               │
               ▼
     Cross-Flow Threat Correlation Engine (Multi-stage Kill Chain Tracker)
               │
               ▼
   Standardized Forensic Alert (Evidence-Backed JSON Schema)
```

---

## 3. Training & Validation Datasets

| Dataset | Modality | Samples Used | Role in Pipeline |
|---|---|---|---|
| **CIC-IDS2017** | CSV (ISCX Flow Features) | 80,000 Benign, 80,000 DDoS/DoS, 1,966 Botnet, 10,000 PortScan | Supervised Classifier, Real Benign Isolation Forest Baseline |
| **DNS-Tunnel-Datasets** | PCAP (Raw Captures) | 2,898 Known Tunnels, 2,267 Zero-Day Unknown Tunnels | Supervised Training (Known) & Held-Out Robustness (Unknown) |
| **DGA Domains Dataset** | CSV (Domain Strings) | 50,000 Domains (25k Alexa + 25k across 25 Malware Families) | Domain-Level DGA Intelligence Component (Char n-gram TF-IDF) |
| **USTC-TFC2016** | PCAP / Archives | 20 Classes (10 Benign / 10 Malware) | External Malware Generalization Reference |

---

## 4. Leakage Prevention & Scientific Validation Methodology

1. **Strict Day & Capture Isolation:** Models are trained on Monday Benign & Wednesday DoS captures and tested against completely unseen Friday Benign and Friday DDoS captures. No session or capture occurs in both train and test.
2. **Feature Shortcut Ablation:** Tested with and without `dst_port` and `protocol` to ensure detection is driven by physical flow dynamics (rates, inter-arrival time variance, packet length distribution) rather than port lookups.
3. **Pure Real-Benign Baseline:** The `IsolationForest` anomaly detector is fit exclusively on clean Monday benign traffic, with 0% attack exposure during fitting.
4. **Zero-Day Quarantine:** Unknown DNS tunnels (`unkownTunnel`: Cobalt Strike, tcp-over-dns, ozymandns) were strictly quarantined from model training, scaling, and threshold tuning.

---

## 5. Quantitative Evaluation Metrics (Day-Isolated)

### Day & Capture-Isolated Benchmark (21,620 flows)
- **Model V1 Baseline (6 features):**
  - Accuracy: **80.51%**
  - Macro F1: **0.6445**
  - Weighted F1: **0.7928**
  - Benign False Alarm Rate (FPR): **1.04%**
  - Model Inference Latency: **0.142 ms** (P95: 0.241 ms)

- **Model V2 Expanded (25 features):**
  - Accuracy: **81.89%**
  - Macro F1: **0.8621**
  - Weighted F1: **0.8153**
  - Benign FPR: **4.21%**
  - Model Inference Latency: **0.202 ms** (P95: 0.364 ms)

- **Model V2 Port-Agnostic (22 features without ports/protocols):**
  - Accuracy: **80.87%**
  - Macro F1: **0.8573**

- **Model V2 Pure Telemetry (21 features, no shortcuts):**
  - Accuracy: **82.02%**
  - Macro F1: **0.8864**

- **Zero-Day Held-Out DNS Threat Generalization (Cobalt Strike / tcp-over-dns):**
  - Detection Rate: **95.06%**

---

## 6. System Latency & Performance Latencies (Measured)

| Latency / Benchmark Metric | Measured Value | Standard / SLA | Status |
|---|---|---|---|
| Model V1 Forward Pass | **0.142 ms avg** / **0.241 ms P95** | < 1.0 ms | **PASSED** |
| Model V2 Forward Pass | **0.202 ms avg** / **0.364 ms P95** | < 1.0 ms | **PASSED** |
| Full End-to-End Pipeline Latency | **6.833 ms avg** / **10.723 ms P95** | < 2.0 s Bounded SLA | **PASSED** |
| Sustained Pipeline Throughput | **146.33 flows/sec** | Sustained Line Ingest | **PASSED** |
| Streaming PCAP Replay Rate | **670 packets/sec** | Real-time Emulation | **PASSED** |

---

## 7. Limitations
- **Encrypted Session Constraints:** GeoGuards inspects unencrypted metadata and transport timing only. Fully encrypted sessions with standard burst and packet-size distribution require cross-flow correlation and domain intelligence.
