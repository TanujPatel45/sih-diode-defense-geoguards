"""
feature_schema.py
-----------------
Canonical Feature Schemas for GeoGuards (SIH 26145).
Shared across Training, Validation, Testing, PCAP Offline Analysis,
Streaming Replay, and Synthetic Simulation.
"""

import json
import os

FEATURE_SCHEMA_V1 = [
    "iat_mean",
    "iat_std",
    "pkt_len_mean",
    "pkt_len_std",
    "payload_entropy",
    "syn_ratio"
]

FEATURE_SCHEMA_V2 = [
    "flow_duration",
    "packet_count",
    "byte_count",
    "packets_per_second",
    "bytes_per_second",
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_min",
    "pkt_len_max",
    "forward_packet_count",
    "backward_packet_count",
    "forward_bytes",
    "backward_bytes",
    "syn_count",
    "rst_count",
    "fin_count",
    "syn_ratio",
    "payload_entropy",
    "src_port",
    "dst_port",
    "protocol"
]

CLASS_NAMES_V1 = [
    "Benign",
    "SYN/UDP Flood",
    "DNS Tunneling",
    "C2 Beaconing"
]

FULL_THREAT_TAXONOMY = [
    "Benign",
    "SYN/UDP Flood",
    "DNS Tunneling",
    "C2 Beaconing",
    "Recon / Port Scan",
    "Data Exfiltration",
    "Malware in Encrypted Session"
]

def save_schemas(output_dir: str = "models"):
    os.makedirs(output_dir, exist_ok=True)
    
    schema_v1 = {
        "version": "v1.0-baseline",
        "description": "DiodeThreatNet 6-feature baseline schema",
        "features": FEATURE_SCHEMA_V1,
        "input_dim": len(FEATURE_SCHEMA_V1),
        "classes": CLASS_NAMES_V1,
        "num_classes": len(CLASS_NAMES_V1)
    }
    with open(os.path.join(output_dir, "feature_schema_v1.json"), "w") as f:
        json.dump(schema_v1, f, indent=2)

    schema_v2 = {
        "version": "v2.0-expanded-metadata",
        "description": "Expanded 25-feature network flow & metadata schema",
        "features": FEATURE_SCHEMA_V2,
        "input_dim": len(FEATURE_SCHEMA_V2),
        "classes": CLASS_NAMES_V1,
        "num_classes": len(CLASS_NAMES_V1),
        "full_threat_taxonomy": FULL_THREAT_TAXONOMY
    }
    with open(os.path.join(output_dir, "feature_schema_v2.json"), "w") as f:
        json.dump(schema_v2, f, indent=2)

    print(f"Saved feature schemas to {output_dir}/")

if __name__ == "__main__":
    save_schemas()
