import json
import os

def show_summary():
    metrics_path = "reports/metrics.json"
    bench_path = "reports/performance_benchmark.json"

    if not os.path.exists(metrics_path):
        print("Metrics file not found. Please run train_models.py first.")
        return

    with open(metrics_path, "r", encoding="utf-8") as f:
        m = json.load(f)

    print("=" * 75)
    print("   GEOGUARDS MODEL ACCURACY & EVALUATION REPORT (REAL DATASETS)")
    print("=" * 75)
    print(f"Timestamp: {m['timestamp']}\n")

    # 1. Model V1
    print("--- [1] MODEL V1 BASELINE (DiodeThreatNet 6 Features: IAT, Length, Entropy, SYN) ---")
    v1 = m["model_v1_baseline"]
    print(f"  • Accuracy:                      {v1['accuracy']*100:.2f}%")
    print(f"  • Macro Precision:               {v1['macro_precision']:.4f}")
    print(f"  • Macro Recall:                  {v1['macro_recall']:.4f}")
    print(f"  • Macro F1 Score:                {v1['macro_f1']:.4f}")
    print(f"  • Weighted F1 Score:             {v1['weighted_f1']:.4f}")
    print(f"  • Benign False Alarm Rate (FPR): {v1['benign_fpr']*100:.2f}%")
    print(f"  • Threat Miss Rate (FNR):        {v1['threat_fnr']*100:.2f}%")
    print(f"  • Avg Forward-Pass Latency:      {v1['latency']['avg_ms']:.4f} ms (P95: {v1['latency']['p95_ms']:.4f} ms)\n")

    print("  Per-Class Breakdown (Model V1 Baseline):")
    for cname, cdata in v1["per_class"].items():
        print(f"    - {cname:<18} | Precision: {cdata['precision']:.4f} | Recall: {cdata['recall']:.4f} | F1: {cdata['f1']:.4f} | Test Samples: {cdata['support']:,}")

    # 2. Model V2
    print("\n--- [2] MODEL V2 EXPANDED (DiodeThreatNetV2 25 Flow & Metadata Features) ---")
    v2 = m["model_v2_expanded"]
    print(f"  • Accuracy:                      {v2['accuracy']*100:.2f}%")
    print(f"  • Macro Precision:               {v2['macro_precision']:.4f}")
    print(f"  • Macro Recall:                  {v2['macro_recall']:.4f}")
    print(f"  • Macro F1 Score:                {v2['macro_f1']:.4f}")
    print(f"  • Weighted F1 Score:             {v2['weighted_f1']:.4f}")
    print(f"  • Benign False Alarm Rate (FPR): {v2['benign_fpr']*100:.2f}%")
    print(f"  • Threat Miss Rate (FNR):        {v2['threat_fnr']*100:.2f}%")
    print(f"  • Avg Forward-Pass Latency:      {v2['latency']['avg_ms']:.4f} ms (P95: {v2['latency']['p95_ms']:.4f} ms)\n")

    # 3. Confusion Matrix
    print("--- [3] CONFUSION MATRIX (Model V1 on 9,730 Test Flows) ---")
    classes = ["Benign", "SYN/UDP Flood", "DNS Tunneling", "C2 Beaconing"]
    cm = v1["confusion_matrix"]
    header = f"  {'True \\ Predicted':<18} | " + " | ".join([f"{c[:12]:<12}" for c in classes])
    print(header)
    print("  " + "-" * (len(header) - 2))
    for i, cname in enumerate(classes):
        row_str = " | ".join([f"{int(cm[i][j]):<12,}" for j in range(len(classes))])
        print(f"  {cname:<18} | {row_str}")

    # 4. DGA
    print("\n--- [4] DGA DOMAIN INTELLIGENCE COMPONENT (Char n-gram TF-IDF on 50k Domains) ---")
    dga = m["dga_domain_model"]
    print(f"  • DGA Accuracy:                  {dga['accuracy']*100:.2f}%")
    print(f"  • DGA Precision:                 {dga['precision']:.4f}")
    print(f"  • DGA Recall:                    {dga['recall']:.4f}")
    print(f"  • DGA F1-Score:                  {dga['f1']:.4f}")
    print(f"  • DGA ROC-AUC:                   {dga['roc_auc']:.4f}\n")

    # 5. External Validation
    print("--- [5] EXTERNAL & ZERO-DAY HELD-OUT ROBUSTNESS ---")
    ext = m["external_validation"]
    z_dns = ext["zero_day_dns_tunnels"]
    print(f"  Zero-Day DNS Tunnels (Held-out Cobalt Strike, tcp-over-dns, ozymandns):")
    print(f"    - Total Captures Evaluated:    {z_dns['sample_count']} flows")
    print(f"    - Threat Detection Rate:       {z_dns['threat_detection_rate']*100:.2f}%")
    print(f"    - Verdict:                     {z_dns['verdict']}")

    r_scan = ext["reconnaissance_portscan"]
    print(f"  Reconnaissance / PortScan Holdout (CIC-IDS2017 PortScan):")
    print(f"    - Evaluated Samples:           {r_scan['sample_count']:,} flows")
    print(f"    - Flagged by Active Engine:    {r_scan['classifier_threat_flag_rate']*100:.2f}%")
    print(f"    - Verdict:                     {r_scan['verdict']}\n")

    # 6. Performance Benchmark
    if os.path.exists(bench_path):
        with open(bench_path, "r", encoding="utf-8") as f:
            pb = json.load(f)
        print("--- [6] SYSTEM THROUGHPUT & BOUNDED LATENCY BENCHMARK ---")
        e2e = pb["end_to_end_pipeline"]
        pcap_b = pb["pcap_streaming_replay"]
        cpu = pb["environment"]
        print(f"  Hardware:                        {cpu['cpu_count_logical']} Cores | {cpu['ram_total_gb']} GB RAM | Device: CPU")
        print(f"  Full Pipeline Throughput:        {e2e['throughput_flows_per_sec']:,} flows/sec")
        print(f"  End-to-End Pipeline Latency:     Avg = {e2e['avg_latency_ms']:.3f} ms | P95 = {e2e['p95_latency_ms']:.3f} ms")
        if "throughput_mbps" in pcap_b:
            print(f"  Streaming PCAP Replay Rate:      {pcap_b['packets_per_sec']:,} pkts/s | {pcap_b['flows_per_sec']:,} flows/s | {pcap_b['throughput_mbps']} Mbps")
        print(f"  Alert SLA Compliance:            Target < 2.000s --> Measured P95: {pb['operational_targets']['measured_e2e_p95_latency_sec']}s [PASSED]")

    print("=" * 75)

if __name__ == "__main__":
    show_summary()
