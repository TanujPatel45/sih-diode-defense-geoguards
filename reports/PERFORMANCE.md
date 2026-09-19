# GeoGuards Performance & Throughput Benchmark Report

**Benchmark Timestamp:** 2026-09-10T07:37:50.235202+00:00

## 1. Execution Environment

- **CPU:** 12 Logical Cores (6 Physical Cores)
- **RAM:** 15.27 GB Total (0.65 GB Available)
- **Inference Device:** CPU (Unidirectional Monitoring Node)
- **Software:** Python 3.14.6, PyTorch 2.14.0+cpu

## 2. Measured Processing Rates & Latencies

| Component | Metric | Measured Value | Operational SLA / Target |
|---|---|---|---|
| **Model V1 Forward Pass** | Average Latency | **0.1056 ms** | < 1.0 ms |
| **Model V1 Forward Pass** | P95 Latency | **0.2237 ms** | < 2.0 ms |
| **Full End-to-End Pipeline** | Throughput | **146.33 flows/sec** | Sustained Live Ingest |
| **Full End-to-End Pipeline** | Average Latency | **6.833 ms** | < 50.0 ms |
| **Full End-to-End Pipeline** | P95 Latency | **10.723 ms** | < 100.0 ms |
| **Streaming PCAP Replay** | Replay Throughput | **0.214 Mbps** (670.2 pkts/s) | Real-Time Line Rate |
| **Streaming PCAP Replay** | P95 Alert Latency | **6.447 ms** | < 2.0 s Target SLA |

## 3. SLA Compliance & Bounded Latency

- **Target Alert Latency:** < 2.000 seconds
- **Measured P95 Alert Latency:** **0.01072 seconds**
- **Verdict:** **PASSED (Well within bounded real-time processing SLA)**

