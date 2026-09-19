# Initial Overfitting & Leakage Audit Report
**Project:** GeoGuards — SIH 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Date:** 2026-09-10  
**Status:** Complete Initial Codebase & ML Pipeline Audit

---

## 1. Executive Summary

This audit investigates the factors contributing to the reported high classification metrics (~97.2% for V1 and ~99.0% for V2) on the initial pipeline. A rigorous review of the data ingestion, feature generation, dataset partitioning, and model evaluation code was performed to identify any sources of data leakage, shortcut learning, duplicate feature vectors, and distribution similarity between splits.

---

## 2. In-Depth Audit Findings by Component

### 2.1 Dataset Selection & Composition
- **CIC-IDS2017**: Used for Benign (Monday/Tuesday), Flood/DoS (Wednesday/Friday), Botnet C2 (Friday morning), PortScan (Friday afternoon), Infiltration (Thursday afternoon).
- **DNS-Tunnel-Datasets**: Used for DNS Tunneling (Class 2) from 15 known tunnel PCAPs (`dnscat2`, `dns2tcp`, `dnspot`). Held-out PCAPs (`unkownTunnel`, `wildcard`, `crossEndPoint`) used for zero-day evaluation.
- **DGA Domains**: 25k Alexa domains + 25k DGA domains across 25 malware families.
- **Responsible File/Function**: `ml/scripts/preprocess_data.py` (`process_cic_ids`, `process_dns_tunnels`, `process_dga_dataset`).

### 2.2 Split Methodology & Leakage Analysis
- **Current Split Type**: Row-level stratified random split (`train_test_split(..., test_size=0.30, stratify=y)` followed by a 50/50 split of the test partition into validation and test sets).
- **Leakage Finding**: While splitting was performed **before** scaler fitting (preventing scaler parameter leakage), the **random row-level splitting** allows flows belonging to the same TCP connection/session, identical attack burst window, or the exact same PCAP capture file to be split across Train (70%), Validation (15%), and Test (15%).
- **Impact**: In network security benchmarks (especially CIC-IDS2017), attack flows executed within the same minute often have nearly identical packet sizes and inter-arrival times. Random sampling creates an "easy" test set where the model memorizes flow burst characteristics rather than generalizing to unseen days/captures.
- **Risk Rating**: **HIGH**

### 2.3 Feature Pipeline & Shortcut Learning
- **V1 Baseline (6 features)**: `iat_mean`, `iat_std`, `pkt_len_mean`, `pkt_len_std`, `payload_entropy`, `syn_ratio`.
  - *Finding*: Generic flow timing and size statistics without port or IP artifacts. However, payload entropy in CIC-IDS2017 was synthesized via a proxy formula based on packet length variance (`3.8 + (pkt_s / pkt_m) * 1.5`), which may introduce an artificial correlation with class.
  - *Risk Rating*: **MEDIUM**
- **V2 Expanded (25 features)**: Includes `src_port`, `dst_port`, `protocol`, packet/byte counts, rates, and flag counts.
  - *Finding*: `dst_port` (e.g., port 53 for DNS, port 80/443/8080 for web attacks) and `protocol` act as strong shortcut features. When port 53 is strongly correlated with Class 2 (DNS tunneling), the neural network can bypass deep temporal analysis and rely on port/protocol lookups.
  - *Risk Rating*: **HIGH**

### 2.4 Duplicate & Near-Duplicate Flow Vectors
- **Finding**: In CIC-IDS2017, DoS/DDoS attacks (e.g., Low Orbit Ion Cannon, Slowloris, SYN Flood) generate millions of identical or near-identical packet sequences with identical duration (0 or fixed timeout), identical packet sizes, and 0 IAT variance.
- **Impact**: When random sampling extracts 40,000 samples, thousands of identical feature vectors appear across both train and test splits, artificially inflating the test accuracy to ~99%.
- **Risk Rating**: **HIGH**

### 2.5 Isolation Forest Benign Baseline
- **Responsible File/Function**: `ml/scripts/train_models.py` (lines 231–256) & `backend/anomaly_detector.py`.
- **Finding**: The Isolation Forest was fit on 20,000 flows from Monday and Tuesday captures (strictly labeled `BENIGN`). No attack data was included in training.
- **Wording Audit**: Previously referred to as "zero attack leakage" and "0% false positives", which is unscientific. It is accurately described as: *"Isolation Forest fitted exclusively on clean benign training traffic."*
- **Risk Rating**: **LOW (Methodology is sound; descriptive terminology needed refinement)**

---

## 3. Risk Matrix Summary

| Component | Potential Issue | Responsible File & Function | Current Risk Rating | Required Remediation |
|---|---|---|---|---|
| **Split Strategy** | Random row-level split allows session/day flow leakage | `preprocess_data.py:main()` (lines 377-380) | **HIGH** | Implement strict Capture/Day/File-isolated evaluation split (Phase 3). |
| **Duplicates** | Identical DoS/Flood feature vectors across splits | `preprocess_data.py:load_mapped()` | **HIGH** | Perform exhaustive duplicate & near-duplicate cross-split audit (Phase 2). |
| **Shortcut Features** | `dst_port` and `protocol` allow shortcut classification | `feature_schema.py` & `preprocess_data.py` | **HIGH** | Conduct feature distribution analysis & ablation tests without ports/protocols (Phases 4 & 5). |
| **Entropy Proxy** | Synthesized entropy from packet length variance | `preprocess_data.py:load_mapped()` (line 250) | **MEDIUM** | Evaluate model sensitivity with and without synthesized entropy in ablation. |
| **Reporting Terminology** | "99% detection accuracy" implies real-world deployment accuracy | `reports/MODEL_EVALUATION.md`, `README.md` | **MEDIUM** | Update reports to specify in-distribution vs out-of-distribution / cross-dataset metrics. |

---

## 4. Initial Audit Conclusion & Next Steps

The reported ~99.0% V2 accuracy and ~97.2% V1 accuracy are reproducible from the existing random-split script, but are susceptible to:
1. **Flow-level overlap** from identical attack bursts in CIC-IDS2017.
2. **Port/protocol shortcut learning** in the 25-feature V2 model.
3. **Capture-level co-occurrence** where the model has seen other flows from the same capture file during training.

We will proceed directly to **Phase 2 (Duplicate Audit)** and **Phase 3 (Capture/Day Isolation)** to establish a rigorous, leakage-free evaluation benchmark.
