"""
pcap_analyzer.py
----------------
PCAP → Flow Extraction → Feature Engineering → Analysis Pipeline

Implements proper 5-tuple flow/session grouping:
  (source_ip, destination_ip, source_port, destination_port, protocol)

Flow timeout: flows are considered complete if no packet is seen for
FLOW_TIMEOUT_SECONDS. After parsing all packets, any remaining open
flows are also flushed.

Calculated features per flow:
  duration, packet_count, byte_count, packets_per_second, bytes_per_second,
  iat_mean, iat_std, pkt_len_mean, pkt_len_std, payload_entropy,
  syn_ratio, tcp_rst_ratio, tcp_fin_ratio,
  forward_packet_count, backward_packet_count, forward_bytes, backward_bytes,
  source_port, destination_port, protocol

Only features derivable from captured packets are calculated.
No features are invented or estimated.

Usage:
  python pcap_analyzer.py <pcap_file>
  python pcap_analyzer.py <pcap_file> --api http://127.0.0.1:8000
"""

import sys
import math
import time
import argparse
import logging
from collections import defaultdict

import numpy as np
import requests

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ── Flow timeout (seconds) ────────────────────────────────────────────────────
FLOW_TIMEOUT_SECONDS = 60.0

# ── Minimum packets per flow to submit ───────────────────────────────────────
MIN_PACKETS_PER_FLOW = 2


# ── Shannon entropy ───────────────────────────────────────────────────────────

def calculate_shannon_entropy(payload_bytes: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0–8 bits)."""
    if not payload_bytes:
        return 0.0
    counts = defaultdict(int)
    for b in payload_bytes:
        counts[b] += 1
    total   = len(payload_bytes)
    entropy = 0.0
    for count in counts.values():
        p        = count / total
        entropy -= p * math.log2(p)
    return float(entropy)


# ── Flow record ───────────────────────────────────────────────────────────────

def _make_flow():
    return {
        "times"    : [],    # packet timestamps (float seconds)
        "lengths"  : [],    # per-packet lengths (bytes)
        "payloads" : b"",   # concatenated payload bytes
        "syn_count": 0,
        "rst_count": 0,
        "fin_count": 0,
        "fwd_pkts" : 0,     # packets in forward direction
        "bwd_pkts" : 0,
        "fwd_bytes": 0,
        "bwd_bytes": 0,
        "last_seen": 0.0,
        "src_ip"   : "",
        "dst_ip"   : "",
        "src_port" : 0,
        "dst_port" : 0,
        "protocol" : 0,
    }


# ── Feature extraction ────────────────────────────────────────────────────────

def _extract_features(flow: dict) -> dict | None:
    """Extract features from a completed flow record. Returns None if insufficient data."""
    n = len(flow["times"])
    if n < MIN_PACKETS_PER_FLOW:
        return None

    times   = np.array(flow["times"])
    lengths = np.array(flow["lengths"])
    total   = n

    duration       = float(times[-1] - times[0]) if n > 1 else 0.0
    packet_count   = total
    byte_count     = int(np.sum(lengths))

    pps = packet_count / duration if duration > 0 else 0.0
    bps = byte_count   / duration if duration > 0 else 0.0

    iats     = np.diff(times)
    iat_mean = float(np.mean(iats))  if len(iats) > 0 else 0.0
    iat_std  = float(np.std(iats))   if len(iats) > 0 else 0.0

    pkt_len_mean = float(np.mean(lengths))
    pkt_len_std  = float(np.std(lengths)) if total > 1 else 0.0

    payload_entropy = calculate_shannon_entropy(flow["payloads"])

    syn_ratio = flow["syn_count"] / total
    rst_ratio = flow["rst_count"] / total
    fin_ratio = flow["fin_count"] / total

    return {
        "source_ip"        : flow["src_ip"],
        "destination_ip"   : flow["dst_ip"],
        "source_port"      : flow["src_port"],
        "destination_port" : flow["dst_port"],
        "protocol"         : flow["protocol"],

        "duration"         : round(duration,       4),
        "packet_count"     : packet_count,
        "byte_count"       : byte_count,

        "iat_mean"         : round(iat_mean,        6),
        "iat_std"          : round(iat_std,          6),
        "pkt_len_mean"     : round(pkt_len_mean,    2),
        "pkt_len_std"      : round(pkt_len_std,     2),
        "payload_entropy"  : round(payload_entropy, 4),

        "syn_ratio"        : round(syn_ratio,       4),
        "tcp_rst_ratio"    : round(rst_ratio,        4),
        "tcp_fin_ratio"    : round(fin_ratio,        4),

        "forward_pkts"     : flow["fwd_pkts"],
        "backward_pkts"    : flow["bwd_pkts"],
        "forward_bytes"    : flow["fwd_bytes"],
        "backward_bytes"   : flow["bwd_bytes"],
    }


# ── PCAP analysis ─────────────────────────────────────────────────────────────

def analyze_pcap(pcap_file_path: str, api_url: str) -> int:
    """
    Parse a PCAP file, extract flows using 5-tuple grouping, extract features,
    and POST each flow to the analysis API.

    Returns the number of flows submitted.
    """
    log.info("Reading packet capture: %s", pcap_file_path)

    try:
        from scapy.all import rdpcap, IP, TCP, UDP
        packets = rdpcap(pcap_file_path)
    except ImportError:
        log.error("scapy is not installed. Run: pip install scapy")
        return 0
    except Exception as exc:
        log.error("Failed to read PCAP: %s", exc)
        return 0

    log.info("Loaded %d packets. Extracting flows...", len(packets))

    active_flows  : dict[tuple, dict] = {}
    completed     : list[dict]        = []

    for pkt in packets:
        if IP not in pkt:
            continue

        src_ip    = pkt[IP].src
        dst_ip    = pkt[IP].dst
        proto     = pkt[IP].proto
        pkt_time  = float(pkt.time)
        pkt_len   = len(pkt)
        payload_b = b""

        src_port = dst_port = 0

        if TCP in pkt:
            src_port  = pkt[TCP].sport
            dst_port  = pkt[TCP].dport
            flags_str = str(pkt[TCP].flags)
            if pkt[TCP].payload:
                payload_b = bytes(pkt[TCP].payload)
        elif UDP in pkt:
            src_port  = pkt[UDP].sport
            dst_port  = pkt[UDP].dport
            flags_str = ""
            if pkt[UDP].payload:
                payload_b = bytes(pkt[UDP].payload)
        else:
            flags_str = ""

        flow_key     = (src_ip, dst_ip, src_port, dst_port, proto)
        rev_flow_key = (dst_ip, src_ip, dst_port, src_port, proto)

        # Check flow timeout: flush stale flows before adding this packet
        stale_keys = [
            k for k, v in active_flows.items()
            if pkt_time - v["last_seen"] > FLOW_TIMEOUT_SECONDS
        ]
        for k in stale_keys:
            feat = _extract_features(active_flows[k])
            if feat:
                completed.append(feat)
            del active_flows[k]

        # Determine direction and flow entry
        if flow_key in active_flows:
            fkey      = flow_key
            direction = "fwd"
        elif rev_flow_key in active_flows:
            fkey      = rev_flow_key
            direction = "bwd"
        else:
            # New flow
            fkey      = flow_key
            direction = "fwd"
            active_flows[fkey]           = _make_flow()
            active_flows[fkey]["src_ip"]   = src_ip
            active_flows[fkey]["dst_ip"]   = dst_ip
            active_flows[fkey]["src_port"] = src_port
            active_flows[fkey]["dst_port"] = dst_port
            active_flows[fkey]["protocol"] = proto

        f = active_flows[fkey]
        f["times"].append(pkt_time)
        f["lengths"].append(pkt_len)
        f["payloads"]  += payload_b
        f["last_seen"]  = pkt_time

        if direction == "fwd":
            f["fwd_pkts"]  += 1
            f["fwd_bytes"] += pkt_len
        else:
            f["bwd_pkts"]  += 1
            f["bwd_bytes"] += pkt_len

        if TCP in pkt:
            fs = flags_str
            if "S" in fs and "A" not in fs:
                f["syn_count"] += 1
            if "R" in fs:
                f["rst_count"] += 1
            if "F" in fs:
                f["fin_count"] += 1

    # Flush remaining active flows
    for flow_data in active_flows.values():
        feat = _extract_features(flow_data)
        if feat:
            completed.append(feat)

    log.info("Extracted %d flows. Submitting to API: %s", len(completed), api_url)

    submitted = 0
    endpoint  = api_url.rstrip("/") + "/api/v1/analyze-flow"

    for feat in completed:
        try:
            resp = requests.post(endpoint, json=feat, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            log.info(
                "[FLOW] %s:%s → %s:%s | %s (conf=%.1f%%) risk=%.2f [%s]",
                feat["source_ip"], feat["source_port"],
                feat["destination_ip"], feat["destination_port"],
                data.get("prediction", "?"),
                data.get("confidence", 0) * 100,
                data.get("final_risk_score", 0),
                data.get("severity", "?"),
            )
            submitted += 1
        except requests.exceptions.ConnectionError:
            log.error("Cannot connect to API at %s. Is the backend running?", endpoint)
            break
        except Exception as exc:
            log.warning("API error for flow %s→%s: %s", feat["source_ip"], feat["destination_ip"], exc)

    log.info("Done. Submitted %d/%d flows.", submitted, len(completed))
    return submitted


def analyze_pcap_to_list(pcap_file_path: str) -> list[dict]:
    """
    Parse a PCAP file, extract 5-tuple flows, and return feature dicts.
    Does NOT post to the API — caller handles submission.
    Used by the FastAPI /api/v1/analyze-pcap endpoint.

    Returns list of feature dicts (one per completed flow).
    """
    log.info("Reading packet capture (list mode): %s", pcap_file_path)

    try:
        from scapy.all import rdpcap, IP, TCP, UDP
        packets = rdpcap(pcap_file_path)
    except ImportError:
        log.error("scapy is not installed. Run: pip install scapy")
        return []
    except Exception as exc:
        log.error("Failed to read PCAP: %s", exc)
        return []

    log.info("Loaded %d packets. Extracting flows...", len(packets))

    active_flows: dict[tuple, dict] = {}
    completed: list[dict] = []

    for pkt in packets:
        if IP not in pkt:
            continue

        src_ip    = pkt[IP].src
        dst_ip    = pkt[IP].dst
        proto     = pkt[IP].proto
        pkt_time  = float(pkt.time)
        pkt_len   = len(pkt)
        payload_b = b""
        flags_str = ""

        src_port = dst_port = 0

        if TCP in pkt:
            src_port  = pkt[TCP].sport
            dst_port  = pkt[TCP].dport
            flags_str = str(pkt[TCP].flags)
            if pkt[TCP].payload:
                payload_b = bytes(pkt[TCP].payload)
        elif UDP in pkt:
            src_port  = pkt[UDP].sport
            dst_port  = pkt[UDP].dport
            if pkt[UDP].payload:
                payload_b = bytes(pkt[UDP].payload)

        flow_key     = (src_ip, dst_ip, src_port, dst_port, proto)
        rev_flow_key = (dst_ip, src_ip, dst_port, src_port, proto)

        stale_keys = [
            k for k, v in active_flows.items()
            if pkt_time - v["last_seen"] > FLOW_TIMEOUT_SECONDS
        ]
        for k in stale_keys:
            feat = _extract_features(active_flows[k])
            if feat:
                completed.append(feat)
            del active_flows[k]

        if flow_key in active_flows:
            fkey, direction = flow_key, "fwd"
        elif rev_flow_key in active_flows:
            fkey, direction = rev_flow_key, "bwd"
        else:
            fkey, direction = flow_key, "fwd"
            active_flows[fkey]            = _make_flow()
            active_flows[fkey]["src_ip"]   = src_ip
            active_flows[fkey]["dst_ip"]   = dst_ip
            active_flows[fkey]["src_port"] = src_port
            active_flows[fkey]["dst_port"] = dst_port
            active_flows[fkey]["protocol"] = proto

        f = active_flows[fkey]
        f["times"].append(pkt_time)
        f["lengths"].append(pkt_len)
        f["payloads"]  += payload_b
        f["last_seen"]  = pkt_time

        if direction == "fwd":
            f["fwd_pkts"]  += 1
            f["fwd_bytes"] += pkt_len
        else:
            f["bwd_pkts"]  += 1
            f["bwd_bytes"] += pkt_len

        if TCP in pkt:
            if "S" in flags_str and "A" not in flags_str:
                f["syn_count"] += 1
            if "R" in flags_str:
                f["rst_count"] += 1
            if "F" in flags_str:
                f["fin_count"] += 1

    for flow_data in active_flows.values():
        feat = _extract_features(flow_data)
        if feat:
            completed.append(feat)

    log.info("Extracted %d flows from PCAP (list mode).", len(completed))
    return completed


# ── CLI entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyze a PCAP file and submit flows to the NIDS API."
    )
    parser.add_argument(
        "pcap",
        nargs   = "?",
        default = "traffic_sample.pcap",
        help    = "Path to PCAP file (default: traffic_sample.pcap)",
    )
    parser.add_argument(
        "--api",
        default = "http://127.0.0.1:8000",
        help    = "API base URL (default: http://127.0.0.1:8000)",
    )
    args = parser.parse_args()
    analyze_pcap(args.pcap, args.api)