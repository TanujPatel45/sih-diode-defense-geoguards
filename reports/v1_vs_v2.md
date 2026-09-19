# Model Comparison: Baseline V1 vs Expanded V2 (Leakage-Isolated Benchmark)

### Summary of Model Architectures
- **Model V1 Baseline (6 features):** Uses lightweight statistical flow metrics (`iat_mean`, `iat_std`, `pkt_len_mean`, `pkt_len_std`, `payload_entropy`, `syn_ratio`). Evaluates in **0.142 ms** with a **1.04% false alarm rate**.
- **Model V2 Expanded (25 features):** Deep metadata model incorporating bi-directional flow metrics, byte rates, packet counts, and TCP flag distribution. Achieves **81.89% day-isolated accuracy** and **0.8621 Macro F1**.
- **Model V2 Port-Agnostic (22 features):** Strips `src_port`, `dst_port`, and `protocol` to prevent port shortcut learning, maintaining **80.87% accuracy** and **0.8573 Macro F1**.

### Day-Isolated Performance Comparison:
- **V1 Baseline:** Accuracy: **80.51%** | Macro F1: **0.6445** | FPR: **1.04%** | Avg Latency: **0.142 ms**
- **V2 Expanded:** Accuracy: **81.89%** | Macro F1: **0.8621** | FPR: **4.21%** | Avg Latency: **0.202 ms**
- **V2 Pure Telemetry:** Accuracy: **82.02%** | Macro F1: **0.8864** | FPR: **1.80%** | Avg Latency: **0.194 ms**
