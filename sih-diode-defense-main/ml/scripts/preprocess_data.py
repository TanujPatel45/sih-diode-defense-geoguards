"""
preprocess_data.py
------------------
Data preprocessing and leakage-safe dataset construction for GeoGuards (SIH 26145).
Processes:
1. CIC-IDS2017 flow CSVs (Benign, DoS/DDoS, Botnet C2, PortScan, Infiltration)
2. DNS-Tunnel PCAP captures (Known tunnels, Normal DNS, Held-out zero-day tunnels)
3. DGA Domains Dataset (Lexical, n-gram, entropy extraction)
4. Saves fit-on-train-only scalers (scaler_v1.pkl, scaler_v2.pkl) and preprocessed arrays.
"""

import os
import glob
import math
import joblib
import json
import numpy as np
import pandas as pd
from collections import defaultdict
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from feature_schema import FEATURE_SCHEMA_V1, FEATURE_SCHEMA_V2, save_schemas

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)

def calculate_shannon_entropy(payload_bytes: bytes) -> float:
    if not payload_bytes:
        return 0.0
    counts = defaultdict(int)
    for b in payload_bytes:
        counts[b] += 1
    total = len(payload_bytes)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return float(entropy)

def calculate_domain_entropy(domain: str) -> float:
    if not domain:
        return 0.0
    domain = domain.lower()
    counts = defaultdict(int)
    for c in domain:
        counts[c] += 1
    total = len(domain)
    return float(-sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values()))

def extract_flows_from_pcap(pcap_file: str, max_packets: int = 5000) -> list:
    if not SCAPY_AVAILABLE:
        return []
    try:
        pkts = rdpcap(pcap_file, count=max_packets)
    except Exception as exc:
        print(f"Error reading {pcap_file}: {exc}")
        return []

    flows = defaultdict(lambda: {
        "times": [], "lengths": [], "payloads": b"",
        "syn_count": 0, "rst_count": 0, "fin_count": 0,
        "fwd_pkts": 0, "bwd_pkts": 0, "fwd_bytes": 0, "bwd_bytes": 0,
        "src_port": 0, "dst_port": 0, "protocol": 0, "dns_queries": []
    })

    for pkt in pkts:
        if not (IP in pkt or IPv6 in pkt):
            continue
        ip = pkt[IP] if IP in pkt else pkt[IPv6]
        proto = ip.proto
        sport, dport = 0, 0
        is_syn, is_rst, is_fin = 0, 0, 0
        payload = b""

        if TCP in pkt:
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            flags = pkt[TCP].flags
            if flags & 0x02: is_syn = 1
            if flags & 0x04: is_rst = 1
            if flags & 0x01: is_fin = 1
            if hasattr(pkt[TCP], "payload") and bytes(pkt[TCP].payload):
                payload = bytes(pkt[TCP].payload)
        elif UDP in pkt:
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            if hasattr(pkt[UDP], "payload") and bytes(pkt[UDP].payload):
                payload = bytes(pkt[UDP].payload)

        fwd_key = (ip.src, ip.dst, sport, dport, proto)
        rev_key = (ip.dst, ip.src, dport, sport, proto)
        if rev_key in flows:
            key = rev_key
            is_fwd = False
        else:
            key = fwd_key
            is_fwd = True

        fl = flows[key]
        t = float(pkt.time)
        l = len(pkt)
        fl["times"].append(t)
        fl["lengths"].append(l)
        fl["src_port"] = sport
        fl["dst_port"] = dport
        fl["protocol"] = proto
        if len(fl["payloads"]) < 2048 and payload:
            fl["payloads"] += payload[:256]

        if is_fwd:
            fl["fwd_pkts"] += 1
            fl["fwd_bytes"] += l
        else:
            fl["bwd_pkts"] += 1
            fl["bwd_bytes"] += l

        if is_syn: fl["syn_count"] += 1
        if is_rst: fl["rst_count"] += 1
        if is_fin: fl["fin_count"] += 1

        if DNS in pkt and pkt[DNS].qd:
            try:
                qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                fl["dns_queries"].append(qname)
            except Exception:
                pass

    results = []
    for fl in flows.values():
        if len(fl["times"]) < 2:
            continue
        times = np.array(fl["times"])
        lengths = np.array(fl["lengths"])
        iats = np.diff(times)
        dur = float(times[-1] - times[0])
        n_pkts = len(times)
        total_b = int(np.sum(lengths))
        
        iat_m = float(np.mean(iats)) if len(iats) > 0 else 0.0
        iat_s = float(np.std(iats)) if len(iats) > 0 else 0.0
        iat_min = float(np.min(iats)) if len(iats) > 0 else 0.0
        iat_max = float(np.max(iats)) if len(iats) > 0 else 0.0
        
        pkt_m = float(np.mean(lengths))
        pkt_s = float(np.std(lengths))
        pkt_min = float(np.min(lengths))
        pkt_max = float(np.max(lengths))
        
        entropy = calculate_shannon_entropy(fl["payloads"])
        syn_r = float(fl["syn_count"] / n_pkts)
        pps = float(n_pkts / max(dur, 0.001))
        bps = float(total_b / max(dur, 0.001))

        feat_v1 = [iat_m, iat_s, pkt_m, pkt_s, entropy, syn_r]
        feat_v2 = [
            dur, n_pkts, total_b, pps, bps,
            iat_m, iat_s, iat_min, iat_max,
            pkt_m, pkt_s, pkt_min, pkt_max,
            fl["fwd_pkts"], fl["bwd_pkts"], fl["fwd_bytes"], fl["bwd_bytes"],
            fl["syn_count"], fl["rst_count"], fl["fin_count"],
            syn_r, entropy, fl["src_port"], fl["dst_port"], fl["protocol"]
        ]
        results.append({
            "v1": feat_v1,
            "v2": feat_v2,
            "dns_queries": fl["dns_queries"]
        })
    return results

def process_cic_ids(cic_dir: str):
    print("Loading and mapping CIC-IDS2017 CSVs...")
    
    # Files mapping
    benign_files = [
        os.path.join(cic_dir, "Monday-WorkingHours.pcap_ISCX.csv"),
        os.path.join(cic_dir, "Tuesday-WorkingHours.pcap_ISCX.csv")
    ]
    ddos_files = [
        os.path.join(cic_dir, "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"),
        os.path.join(cic_dir, "Wednesday-workingHours.pcap_ISCX.csv")
    ]
    botnet_files = [
        os.path.join(cic_dir, "Friday-WorkingHours-Morning.pcap_ISCX.csv")
    ]
    portscan_files = [
        os.path.join(cic_dir, "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    ]
    infil_files = [
        os.path.join(cic_dir, "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv")
    ]

    def load_mapped(csv_paths, target_label_filter, class_id, max_samples=40000):
        records_v1 = []
        records_v2 = []
        for p in csv_paths:
            if not os.path.exists(p):
                continue
            print(f"  Reading {os.path.basename(p)} for label filter: {target_label_filter}")
            df = pd.read_csv(p, encoding='latin-1', low_memory=False)
            df.columns = [c.strip() for c in df.columns]
            label_col = [c for c in df.columns if 'label' in c.lower()][0]
            
            if target_label_filter:
                mask = df[label_col].astype(str).str.strip().isin(target_label_filter)
                df = df[mask]
            
            if len(df) > max_samples:
                df = df.sample(n=max_samples, random_state=RANDOM_SEED)
                
            # Replace infinities and NaNs
            df = df.replace([np.inf, -np.inf], np.nan).fillna(0.0)
            
            # Map features
            # IAT in CIC is in microseconds, convert to seconds
            iat_mean = (df['Flow IAT Mean'].values / 1e6).clip(0, 1000)
            iat_std = (df['Flow IAT Std'].values / 1e6).clip(0, 1000)
            iat_min = (df['Flow IAT Min'].values / 1e6).clip(0, 1000)
            iat_max = (df['Flow IAT Max'].values / 1e6).clip(0, 1000)
            
            dur = (df['Flow Duration'].values / 1e6).clip(0, 10000)
            fwd_pkts = df['Total Fwd Packets'].values.clip(0, 1e7)
            bwd_pkts = df['Total Backward Packets'].values.clip(0, 1e7)
            n_pkts = fwd_pkts + bwd_pkts
            
            fwd_b = df['Total Length of Fwd Packets'].values.clip(0, 1e9)
            bwd_b = df['Total Length of Bwd Packets'].values.clip(0, 1e9)
            total_b = fwd_b + bwd_b
            
            pps = df['Flow Packets/s'].values.clip(0, 1e7)
            bps = df['Flow Bytes/s'].values.clip(0, 1e9)
            
            pkt_m = df['Packet Length Mean'].values.clip(0, 65535)
            pkt_s = df['Packet Length Std'].values.clip(0, 65535)
            pkt_min = df['Min Packet Length'].values.clip(0, 65535)
            pkt_max = df['Max Packet Length'].values.clip(0, 65535)
            
            syn_c = df['SYN Flag Count'].values if 'SYN Flag Count' in df.columns else np.zeros(len(df))
            rst_c = df['RST Flag Count'].values if 'RST Flag Count' in df.columns else np.zeros(len(df))
            fin_c = df['FIN Flag Count'].values if 'FIN Flag Count' in df.columns else np.zeros(len(df))
            
            syn_r = np.where(n_pkts > 0, syn_c / np.maximum(1, n_pkts), 0.0).clip(0, 1)
            
            # Synthetic/estimated payload entropy proxy from packet length variance/mean
            # Standard network background entropy ~ 3.5 to 5.5 bits
            entropy = (3.8 + (pkt_s / np.maximum(1, pkt_m)) * 1.5).clip(0.0, 7.9)
            
            dst_port = df['Destination Port'].values.clip(0, 65535)
            src_port = np.random.randint(1024, 65535, size=len(df)) # Port randomization if uncaptured
            proto = np.where(dst_port == 53, 17, 6) # TCP (6) or UDP (17)
            
            for i in range(len(df)):
                v1 = [float(iat_mean[i]), float(iat_std[i]), float(pkt_m[i]), float(pkt_s[i]), float(entropy[i]), float(syn_r[i])]
                v2 = [
                    float(dur[i]), float(n_pkts[i]), float(total_b[i]), float(pps[i]), float(bps[i]),
                    float(iat_mean[i]), float(iat_std[i]), float(iat_min[i]), float(iat_max[i]),
                    float(pkt_m[i]), float(pkt_s[i]), float(pkt_min[i]), float(pkt_max[i]),
                    float(fwd_pkts[i]), float(bwd_pkts[i]), float(fwd_b[i]), float(bwd_b[i]),
                    float(syn_c[i]), float(rst_c[i]), float(fin_c[i]),
                    float(syn_r[i]), float(entropy[i]), float(src_port[i]), float(dst_port[i]), float(proto[i])
                ]
                records_v1.append(v1)
                records_v2.append(v2)
                
        return np.array(records_v1, dtype=np.float32), np.array(records_v2, dtype=np.float32)

    # Class 0: Benign (40,000 samples)
    b_v1, b_v2 = load_mapped(benign_files, ['BENIGN'], 0, max_samples=40000)
    
    # Class 1: SYN/UDP Flood (DDoS & DoS Hulk/GoldenEye) (40,000 samples)
    flood_v1, flood_v2 = load_mapped(ddos_files, ['DDoS', 'DoS Hulk', 'DoS GoldenEye', 'DoS slowloris'], 1, max_samples=40000)
    
    # Class 3: C2 Beaconing (Botnet ARES) (all samples ~1,966)
    c2_v1, c2_v2 = load_mapped(botnet_files, ['Bot'], 3, max_samples=10000)
    
    # Recon / PortScan for specialized test (10,000 samples)
    recon_v1, recon_v2 = load_mapped(portscan_files, ['PortScan'], 4, max_samples=10000)

    # Exfiltration / Infiltration (all available samples)
    infil_v1, infil_v2 = load_mapped(infil_files, ['Infiltration'], 5, max_samples=5000)

    print(f"CIC-IDS2017 Loaded: Benign={len(b_v1)}, Flood={len(flood_v1)}, C2={len(c2_v1)}, Recon={len(recon_v1)}, Infil={len(infil_v1)}")
    return (b_v1, b_v2), (flood_v1, flood_v2), (c2_v1, c2_v2), (recon_v1, recon_v2), (infil_v1, infil_v2)

def process_dns_tunnels(dns_dir: str):
    print("Processing DNS Tunnel Datasets...")
    known_tunnel_pcaps = glob.glob(os.path.join(dns_dir, "tunnel", "**", "*.pcap"), recursive=True)
    normal_dns_pcaps = glob.glob(os.path.join(dns_dir, "normal", "**", "*.pcap"), recursive=True)
    unknown_tunnel_pcaps = glob.glob(os.path.join(dns_dir, "unkownTunnel", "**", "*.pcap"), recursive=True)
    wildcard_pcaps = glob.glob(os.path.join(dns_dir, "wildcard", "**", "*.pcap"), recursive=True)
    cross_endpoint_pcaps = glob.glob(os.path.join(dns_dir, "crossEndPoint", "**", "*.pcap"), recursive=True)

    def extract_from_list(pcap_list, max_files=10):
        v1_list, v2_list, queries_list = [], [], []
        for p in pcap_list[:max_files]:
            fls = extract_flows_from_pcap(p, max_packets=3000)
            for fl in fls:
                v1_list.append(fl["v1"])
                v2_list.append(fl["v2"])
                queries_list.extend(fl["dns_queries"])
        return np.array(v1_list, dtype=np.float32), np.array(v2_list, dtype=np.float32), queries_list

    # Class 2: DNS Tunneling (Train/Val)
    dns_v1, dns_v2, dns_train_queries = extract_from_list(known_tunnel_pcaps, max_files=15)
    
    # Held-out Zero-Day DNS Robustness Test Sets
    unk_v1, unk_v2, unk_queries = extract_from_list(unknown_tunnel_pcaps, max_files=10)
    wild_v1, wild_v2, wild_queries = extract_from_list(wildcard_pcaps, max_files=8)
    cross_v1, cross_v2, cross_queries = extract_from_list(cross_endpoint_pcaps, max_files=6)

    print(f"DNS Flows Extracted: Known Tunnels={len(dns_v1)}, Unknown Zero-Day={len(unk_v1)}, Wildcard={len(wild_v1)}, CrossEndPoint={len(cross_v1)}")
    return (dns_v1, dns_v2, dns_train_queries), (unk_v1, unk_v2, unk_queries), (wild_v1, wild_v2, wild_queries), (cross_v1, cross_v2, cross_queries)

def process_dga_dataset(dga_dir: str):
    print("Processing DGA Domains Dataset...")
    full_csv = os.path.join(dga_dir, "DGA_domains_dataset-master", "dga_domains_full.csv")
    df = pd.read_csv(full_csv, header=None, names=["label", "family", "domain"])
    
    # Sample balanced set of 50,000 domains (25,000 legit, 25,000 dga across families)
    legit_df = df[df["label"] == "legit"].sample(n=25000, random_state=RANDOM_SEED)
    dga_df = df[df["label"] == "dga"].sample(n=25000, random_state=RANDOM_SEED)
    combined = pd.concat([legit_df, dga_df]).sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)
    
    # Feature extraction for domain strings
    domains = combined["domain"].astype(str).tolist()
    labels = (combined["label"] == "dga").astype(int).values
    families = combined["family"].tolist()

    return domains, labels, families

def main():
    save_schemas("models")
    os.makedirs("ml/artifacts", exist_ok=True)
    
    cic_dir = os.path.join("datasets", "MachineLearningCSV", "MachineLearningCVE")
    dns_dir = os.path.join("datasets", "DNS-Tunnel-Datasets-main")
    dga_dir = os.path.join("datasets", "DGA_domains_dataset-master")

    # 1. Process CIC-IDS2017
    (b_v1, b_v2), (f_v1, f_v2), (c_v1, c_v2), (r_v1, r_v2), (inf_v1, inf_v2) = process_cic_ids(cic_dir)

    # 2. Process DNS Tunnels
    (dns_v1, dns_v2, dns_queries), unk_dns, wild_dns, cross_dns = process_dns_tunnels(dns_dir)

    # Build 4-Class Dataset for Supervised Classifier:
    # 0: Benign, 1: SYN/UDP Flood, 2: DNS Tunneling, 3: C2 Beaconing
    
    # Ensure balanced subsets
    n_b = min(len(b_v1), 30000)
    n_f = min(len(f_v1), 30000)
    n_d = len(dns_v1)
    n_c = len(c_v1)

    print(f"Selected counts for 4-class training: Benign={n_b}, Flood={n_f}, DNS={n_d}, C2={n_c}")

    # Build X and Y for V1 (6 features) and V2 (25 features)
    X_v1_list = [b_v1[:n_b], f_v1[:n_f], dns_v1, c_v1]
    X_v2_list = [b_v2[:n_b], f_v2[:n_f], dns_v2, c_v2]
    Y_list = [
        np.zeros(n_b, dtype=np.int64),
        np.ones(n_f, dtype=np.int64) * 1,
        np.ones(n_d, dtype=np.int64) * 2,
        np.ones(n_c, dtype=np.int64) * 3
    ]

    X_v1 = np.vstack(X_v1_list)
    X_v2 = np.vstack(X_v2_list)
    y = np.concatenate(Y_list)

    print(f"Total Combined Flows: {len(y)} | V1 shape: {X_v1.shape} | V2 shape: {X_v2.shape}")

    # Stratified Train/Val/Test Split (70% train, 15% val, 15% test)
    idx_train, idx_temp = train_test_split(np.arange(len(y)), test_size=0.30, stratify=y, random_state=RANDOM_SEED)
    idx_val, idx_test = train_test_split(idx_temp, test_size=0.50, stratify=y[idx_temp], random_state=RANDOM_SEED)

    print(f"Splits: Train={len(idx_train)}, Val={len(idx_val)}, Test={len(idx_test)}")

    # Fit scalers ONLY ON TRAINING DATA to prevent leakage
    scaler_v1 = StandardScaler()
    scaler_v1.fit(X_v1[idx_train])
    joblib.dump(scaler_v1, "models/scaler_v1.pkl")
    joblib.dump(scaler_v1, "backend/scaler.pkl")

    scaler_v2 = StandardScaler()
    scaler_v2.fit(X_v2[idx_train])
    joblib.dump(scaler_v2, "models/scaler_v2.pkl")

    print("Saved fit-on-train scalers: models/scaler_v1.pkl and models/scaler_v2.pkl")

    # Save preprocessed flow splits
    np.savez_compressed("ml/artifacts/dataset_v1.npz",
        X_train=X_v1[idx_train], y_train=y[idx_train],
        X_val=X_v1[idx_val], y_val=y[idx_val],
        X_test=X_v1[idx_test], y_test=y[idx_test]
    )

    np.savez_compressed("ml/artifacts/dataset_v2.npz",
        X_train=X_v2[idx_train], y_train=y[idx_train],
        X_val=X_v2[idx_val], y_val=y[idx_val],
        X_test=X_v2[idx_test], y_test=y[idx_test]
    )

    # Save Real Clean Benign Baseline for Isolation Forest
    # Strictly clean Monday/Tuesday benign training flows
    benign_train_v1 = b_v1[:20000]
    benign_train_v2 = b_v2[:20000]
    np.savez_compressed("ml/artifacts/benign_train.npz",
        v1=benign_train_v1, v2=benign_train_v2
    )

    # Save Reconnaissance & Infiltration for specialized testing
    np.savez_compressed("ml/artifacts/specialized_eval.npz",
        recon_v1=r_v1, recon_v2=r_v2,
        infil_v1=inf_v1, infil_v2=inf_v2,
        unk_dns_v1=unk_dns[0], unk_dns_v2=unk_dns[1],
        wild_dns_v1=wild_dns[0], wild_dns_v2=wild_dns[1],
        cross_dns_v1=cross_dns[0], cross_dns_v2=cross_dns[1]
    )

    # 3. Process DGA Dataset
    domains, dga_labels, dga_families = process_dga_dataset(dga_dir)
    d_train, d_temp, y_d_train, y_d_temp = train_test_split(domains, dga_labels, test_size=0.30, stratify=dga_labels, random_state=RANDOM_SEED)
    d_val, d_test, y_d_val, y_d_test = train_test_split(d_temp, y_d_temp, test_size=0.50, stratify=y_d_temp, random_state=RANDOM_SEED)
    
    with open("ml/artifacts/dga_split.json", "w") as f:
        json.dump({
            "train_domains": d_train, "train_labels": y_d_train.tolist(),
            "val_domains": d_val, "val_labels": y_d_val.tolist(),
            "test_domains": d_test, "test_labels": y_d_test.tolist()
        }, f)

    print("Data preprocessing complete. All splits saved to ml/artifacts/")

if __name__ == "__main__":
    main()
