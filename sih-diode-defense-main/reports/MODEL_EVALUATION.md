# GeoGuards Rigorous Model Evaluation Report
**Problem Statement:** SIH 26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Evaluation Standard:** Capture/Day-Isolated Evaluation (Zero Session or File Overlap between Train and Test)

---

## 1. Day & Capture-Isolated Test Results (V1 vs V2)

> [!NOTE]
> All metrics below were computed on unseen day/capture test sets (e.g., Trained on Monday Benign & Wednesday DoS; Tested on unseen Friday Benign & Friday DDoS). Naive random splits previously achieved ~99% due to duplicate attack bursts; strict isolation provides the scientifically valid benchmark below.

| Metric | Model V1 (6-Feature Baseline) | Model V2 (25-Feature Expanded) | Model V2 (22-Feature Port-Agnostic) | Model V2 (21-Feature Pure Telemetry) |
|---|---|---|---|---|
| **Architecture** | DiodeThreatNet (6→64→32→4) | DiodeThreatNetV2 (25→128→64→32→4) | DiodeThreatNetV2 (22→128→64→32→4) | DiodeThreatNetV2 (21→128→64→32→4) |
| **Accuracy** | **80.51%** | **81.89%** | **80.87%** | **82.02%** |
| **Macro Precision** | 0.6674 | 0.9158 | 0.8532 | 0.9005 |
| **Macro Recall** | 0.6534 | 0.8375 | 0.8959 | 0.9021 |
| **Macro F1 Score** | **0.6445** | **0.8621** | **0.8573** | **0.8864** |
| **Weighted F1 Score** | 0.7928 | 0.8153 | 0.8036 | 0.8144 |
| **Benign False Alarm Rate (FPR)** | **1.040%** | **4.210%** | **4.310%** | **1.800%** |
| **Avg Model Latency** | **0.142 ms** | **0.202 ms** | **0.195 ms** | **0.194 ms** |
| **P95 Model Latency** | **0.241 ms** | **0.364 ms** | **0.306 ms** | **0.363 ms** |

---

## 2. Per-Class Breakdown (Model V2 Expanded)

| Threat Class | Precision | Recall | F1 Score | Test Support |
|---|---|---|---|---|
| **Benign** | 0.7327 | 0.9579 | **0.8303** | 10,000 |
| **SYN/UDP Flood** | 0.9406 | 0.6616 | **0.7768** | 10,000 |
| **DNS Tunneling** | 1.0000 | 0.9943 | **0.9971** | 1,226 |
| **C2 Beaconing** | 0.9898 | 0.7360 | **0.8443** | 394 |

### Confusion Matrix (V2 Expanded on 21,620 Day-Isolated Flows)
```text
                  Pred Benign  Pred Flood  Pred DNS  Pred C2
True Benign              9,579         418         0        3
True SYN/UDP Flood       3,384       6,616         0        0
True DNS Tunneling           7           0     1,219        0
True C2 Beaconing          104           0         0      290
```

---

## 3. Multi-Seed Stability (5 Independent Runs)

Evaluated across random seeds `[42, 101, 777, 1337, 2026]`:
- **Accuracy:** `77.15% ± 2.62%`
- **Macro F1:** `0.5366 ± 0.1206`
- **Benign FPR (False Alarm Rate):** `1.04% ± 0.32%`

---

## 4. Zero-Day Held-Out DNS Generalization

- **Dataset:** `DNS-Tunnel-Datasets/unkownTunnel` (Cobalt Strike DNS C2, tcp-over-dns, ozymandns)
- **Isolation:** Strictly held out; never seen during training or feature scaling.
- **Threat Detection Rate:** **95.06%**
- **Specific DNS Tunnel Classification Rate:** **94.79%**
