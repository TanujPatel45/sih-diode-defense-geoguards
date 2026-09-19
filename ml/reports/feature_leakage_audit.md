# Feature Leakage & Shortcut Learning Audit

**Problem Statement:** SIH 26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
**Audit Focus:** Evaluating whether high model accuracy is driven by legitimate temporal/size telemetry or dataset artifacts.

## 1. Feature Importance & Mutual Information (Fit on Training Data Only)

| Feature Name | RF Importance | Mutual Info | Benign Mean | Flood Mean | DNS Mean | C2 Mean | Shortcut Assessment |
|---|---|---|---|---|---|---|---|
| `pkt_len_mean` | **13.71%** | 0.6614 | 100.87 | 585.99 | 141.99 | 68.43 | ✅ Valid - Legitimate flow telemetry |
| `pkt_len_std` | **13.09%** | 0.5366 | 132.76 | 1213.33 | 1.05 | 129.88 | ✅ Valid - Legitimate flow telemetry |
| `pkt_len_max` | **10.21%** | 0.6467 | 438.53 | 3992.16 | 143.16 | 556.31 | ✅ Valid - Legitimate flow telemetry |
| `byte_count` | **9.93%** | 0.6534 | 4960.64 | 7984.1 | 5413.94 | 3695.72 | ✅ Valid - Legitimate flow telemetry |
| `dst_port` | **9.48%** | 0.6992 | 10518.23 | 80.0 | 59756.23 | 21214.71 | ⚠️ **SHORTCUT CANDIDATE** - Dataset port artifact (e.g. port 53 / 80 shortcut) |
| `backward_bytes` | **5.93%** | 0.6483 | 4482.17 | 7697.99 | 2990.33 | 79.18 | ✅ Valid - Legitimate flow telemetry |
| `backward_packet_count` | **4.77%** | 0.4130 | 5.55 | 4.17 | 10.52 | 3.49 | ✅ Valid - Legitimate flow telemetry |
| `packets_per_second` | **4.13%** | 0.5400 | 67131.02 | 177065.09 | 20.5 | 63814.76 | ✅ Valid - Legitimate flow telemetry |
| `bytes_per_second` | **4.07%** | 0.5188 | 1531727.25 | 28654.51 | 2902.4 | 418726.84 | ✅ Valid - Legitimate flow telemetry |
| `pkt_len_min` | **3.44%** | 0.3847 | 19.89 | 0.0 | 140.58 | 2.99 | ✅ Valid - Legitimate flow telemetry |
| `iat_max` | **3.29%** | 0.5740 | 4.13 | 55.11 | 6.15 | 0.06 | ✅ Valid - Legitimate flow telemetry |
| `forward_bytes` | **2.94%** | 0.5832 | 478.47 | 286.11 | 2423.6 | 3616.54 | ✅ Valid - Legitimate flow telemetry |
| `src_port` | **2.77%** | 0.0803 | 33004.68 | 33044.26 | 197.25 | 33243.11 | ✅ Valid - Legitimate flow telemetry |
| `iat_mean` | **2.56%** | 0.5414 | 1.01 | 5.18 | 2.2 | 0.01 | ✅ Valid - Legitimate flow telemetry |
| `forward_packet_count` | **2.39%** | 0.3093 | 5.86 | 5.31 | 10.61 | 3.26 | ✅ Valid - Legitimate flow telemetry |
| `iat_min` | **1.69%** | 0.2677 | 0.28 | 0.49 | 0.22 | 0.0 | ✅ Valid - Legitimate flow telemetry |
| `iat_std` | **1.61%** | 0.3894 | 1.45 | 15.82 | 2.78 | 0.02 | ✅ Valid - Legitimate flow telemetry |
| `flow_duration` | **1.42%** | 0.5520 | 10.09 | 55.63 | 8.93 | 0.1 | ✅ Valid - Legitimate flow telemetry |
| `packet_count` | **0.99%** | 0.3153 | 11.41 | 9.48 | 21.13 | 6.75 | ✅ Valid - Legitimate flow telemetry |
| `fin_count` | **0.75%** | 0.0581 | 0.02 | 0.24 | 0.0 | 0.0 | ✅ Valid - Legitimate flow telemetry |
| `payload_entropy` | **0.58%** | 0.4134 | 4.98 | 5.94 | 4.14 | 5.18 | ✅ Valid - Legitimate observable in PCAP; proxy in CSV |
| `protocol` | **0.21%** | 0.2066 | 10.54 | 6.0 | 17.0 | 6.0 | ⚠️ **SHORTCUT CANDIDATE** - Dataset port artifact (e.g. port 53 / 80 shortcut) |
| `syn_ratio` | **0.02%** | 0.0157 | 0.02 | 0.0 | 0.0 | 0.0 | ✅ Valid - Legitimate flow telemetry |
| `syn_count` | **0.01%** | 0.0197 | 0.06 | 0.0 | 0.0 | 0.0 | ✅ Valid - Legitimate flow telemetry |
| `rst_count` | **0.00%** | 0.0082 | 0.0 | 0.0 | 0.0 | 0.0 | ✅ Valid - Legitimate flow telemetry |

## 2. Key Findings & Shortcut Recommendations
1. **`dst_port` and `protocol`:** Ports are fixed in benchmark captures (DNS=53, HTTP DoS=80). Models relying on `dst_port` can achieve superficial 99% accuracy on known ports but fail when attacks occur over non-standard ports (e.g., DNS-over-HTTPS or C2 on port 8443).
2. **Timing & Size Telemetry (`iat_mean`, `pkt_len_std`, `pps`, `bytes_per_second`):** These represent invariant physical traffic behaviors that remain robust across different ports and sessions.
3. **Entropy Proxy:** In CSVs, entropy is estimated from packet length variance. In live PCAPs, Shannon entropy is directly computed on raw frame payloads.
