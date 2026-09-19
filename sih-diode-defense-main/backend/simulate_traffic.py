"""
simulate_traffic.py
-------------------
Deterministic demo traffic simulator for SIH 26145.

Injects synthetic flow data into the NIDS analysis API to demonstrate
the detection pipeline without requiring real network traffic.

Supported modes:
  normal      — benign background traffic
  syn_flood   — SYN/UDP Flood attack
  dns_tunnel  — DNS Tunnelling exfiltration
  c2_beacon   — C2 Beaconing (periodic implant communication)
  mixed       — cycles through all profiles in order

Usage:
  python simulate_traffic.py --mode mixed --count 20
  python simulate_traffic.py --mode c2_beacon --count 5 --delay 1.0
  python simulate_traffic.py --mode normal --count 10 --api http://127.0.0.1:8000
"""

import argparse
import random
import time
import sys
import logging

import requests

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

DEFAULT_API_URL = "http://127.0.0.1:8000"

# ── Traffic profiles ──────────────────────────────────────────────────────────
# Each field maps directly to the IngestFlow schema.
# Ranges are defined as (min, max) for uniform sampling within realistic bounds.

PROFILES = {
    "normal": {
        "label"            : "Normal Traffic",
        "source_ip_pool"   : ["10.0.1.10", "10.0.1.11", "10.0.1.12", "192.168.1.50"],
        "destination_ip"   : "10.0.0.1",
        "source_port"      : (1024, 65535),
        "destination_port" : (80, 443),
        "protocol"         : 6,             # TCP
        "iat_mean"         : (0.02, 0.1),
        "iat_std"          : (0.005, 0.04),
        "pkt_len_mean"     : (400, 800),
        "pkt_len_std"      : (50, 150),
        "payload_entropy"  : (4.0, 6.0),
        "syn_ratio"        : (0.01, 0.05),
        "tcp_rst_ratio"    : (0.0, 0.02),
        "tcp_fin_ratio"    : (0.02, 0.1),
        "duration"         : (0.5, 5.0),
        "packet_count"     : (10, 80),
        "byte_count"       : (5000, 40000),
    },
    "syn_flood": {
        "label"            : "SYN Flood Attack",
        "source_ip_pool"   : ["10.0.4.182", "10.0.4.200", "172.20.0.5"],
        "destination_ip"   : "10.0.0.1",
        "source_port"      : (1024, 65535),
        "destination_port" : (80, 80),
        "protocol"         : 6,
        "iat_mean"         : (0.0001, 0.0005),
        "iat_std"          : (0.00001, 0.0001),
        "pkt_len_mean"     : (60, 68),
        "pkt_len_std"      : (0.5, 3.0),
        "payload_entropy"  : (0.05, 0.3),
        "syn_ratio"        : (0.95, 1.0),
        "tcp_rst_ratio"    : (0.0, 0.01),
        "tcp_fin_ratio"    : (0.0, 0.005),
        "duration"         : (0.1, 1.0),
        "packet_count"     : (500, 2000),
        "byte_count"       : (30000, 130000),
    },
    "dns_tunnel": {
        "label"            : "DNS Tunnelling Exfiltration",
        "source_ip_pool"   : ["192.168.10.45", "192.168.10.60"],
        "destination_ip"   : "8.8.8.8",
        "source_port"      : (1024, 65535),
        "destination_port" : (53, 53),
        "protocol"         : 17,           # UDP
        "iat_mean"         : (0.04, 0.2),
        "iat_std"          : (0.01, 0.06),
        "pkt_len_mean"     : (170, 220),
        "pkt_len_std"      : (20, 60),
        "payload_entropy"  : (7.2, 8.0),
        "syn_ratio"        : (0.0, 0.0),
        "tcp_rst_ratio"    : (0.0, 0.0),
        "tcp_fin_ratio"    : (0.0, 0.0),
        "duration"         : (2.0, 15.0),
        "packet_count"     : (20, 100),
        "byte_count"       : (3500, 22000),
    },
    "c2_beacon": {
        "label"            : "C2 Periodic Beaconing",
        "source_ip_pool"   : ["172.16.0.88", "172.16.0.99"],
        "destination_ip"   : "91.195.240.117",
        "source_port"      : (1024, 65535),
        "destination_port" : (443, 443),
        "protocol"         : 6,
        "iat_mean"         : (1.8, 2.2),
        "iat_std"          : (0.00005, 0.0005),
        "pkt_len_mean"     : (110, 140),
        "pkt_len_std"      : (3.0, 8.0),
        "payload_entropy"  : (3.5, 4.8),
        "syn_ratio"        : (0.0, 0.02),
        "tcp_rst_ratio"    : (0.0, 0.01),
        "tcp_fin_ratio"    : (0.01, 0.04),
        "duration"         : (60.0, 180.0),
        "packet_count"     : (30, 90),
        "byte_count"       : (3300, 12600),
    },
}

PROFILE_CYCLE_ORDER = ["normal", "syn_flood", "dns_tunnel", "c2_beacon"]


def _sample_flow(profile_name: str, seed_offset: int = 0) -> dict:
    """Sample one flow from a named profile."""
    p   = PROFILES[profile_name]
    rng = random.Random(time.time() + seed_offset)

    src_ip     = rng.choice(p["source_ip_pool"])
    src_port   = rng.randint(*p["source_port"])
    dst_port   = rng.randint(*p["destination_port"]) if isinstance(p["destination_port"], tuple) else p["destination_port"]
    pkt_count  = rng.randint(*p["packet_count"])
    byte_count = rng.randint(*p["byte_count"])

    return {
        "source_ip"        : src_ip,
        "destination_ip"   : p["destination_ip"],
        "source_port"      : src_port,
        "destination_port" : dst_port,
        "protocol"         : p["protocol"],

        "iat_mean"         : round(rng.uniform(*p["iat_mean"]),        6),
        "iat_std"          : round(rng.uniform(*p["iat_std"]),          6),
        "pkt_len_mean"     : round(rng.uniform(*p["pkt_len_mean"]),    2),
        "pkt_len_std"      : round(rng.uniform(*p["pkt_len_std"]),     2),
        "payload_entropy"  : round(rng.uniform(*p["payload_entropy"]), 4),
        "syn_ratio"        : round(rng.uniform(*p["syn_ratio"]),       4),
        "tcp_rst_ratio"    : round(rng.uniform(*p["tcp_rst_ratio"]),   4),
        "tcp_fin_ratio"    : round(rng.uniform(*p["tcp_fin_ratio"]),   4),
        "duration"         : round(rng.uniform(*p["duration"]),        3),
        "packet_count"     : pkt_count,
        "byte_count"       : byte_count,
        "forward_pkts"     : pkt_count // 2,
        "backward_pkts"    : pkt_count - (pkt_count // 2),
        "forward_bytes"    : byte_count // 2,
        "backward_bytes"   : byte_count - (byte_count // 2),
    }


def run_simulator(mode: str, count: int, delay: float, api_url: str) -> None:
    """Inject `count` synthetic flows into the analysis API."""
    endpoint = api_url.rstrip("/") + "/api/v1/analyze-flow"
    log.info("Starting demo simulator | mode=%s | count=%d | delay=%.1fs", mode, count, delay)

    if mode == "mixed":
        profile_names = [PROFILE_CYCLE_ORDER[i % len(PROFILE_CYCLE_ORDER)] for i in range(count)]
    else:
        if mode not in PROFILES:
            log.error("Unknown mode '%s'. Choose: %s", mode, ", ".join(PROFILES.keys()))
            sys.exit(1)
        profile_names = [mode] * count

    successes = 0
    for i, pname in enumerate(profile_names):
        flow = _sample_flow(pname, seed_offset=i)
        label = PROFILES[pname]["label"]

        try:
            resp = requests.post(endpoint, json=flow, timeout=10)
            resp.raise_for_status()
            data = resp.json()

            log.info(
                "[%02d/%02d] %-28s | %s:%s→%s:%s | pred=%-16s conf=%.1f%% risk=%.3f [%s]",
                i + 1, count, label,
                flow["source_ip"], flow["source_port"],
                flow["destination_ip"], flow["destination_port"],
                data.get("prediction",       "?"),
                data.get("confidence",        0) * 100,
                data.get("final_risk_score",  0),
                data.get("severity",          "?"),
            )
            successes += 1

        except requests.exceptions.ConnectionError:
            log.error("Cannot connect to %s. Is the backend running?", endpoint)
            sys.exit(1)
        except Exception as exc:
            log.warning("Flow %d failed: %s", i + 1, exc)

        if i < count - 1:
            time.sleep(delay)

    log.info("Simulation complete. %d/%d flows submitted successfully.", successes, count)


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description = "Deterministic demo traffic simulator for SIH 26145 NIDS prototype."
    )
    parser.add_argument(
        "--mode",
        choices = list(PROFILES.keys()) + ["mixed"],
        default = "mixed",
        help    = "Traffic profile to simulate (default: mixed)",
    )
    parser.add_argument(
        "--count",
        type    = int,
        default = 20,
        help    = "Number of flows to inject (default: 20)",
    )
    parser.add_argument(
        "--delay",
        type    = float,
        default = 0.5,
        help    = "Delay between flows in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--api",
        default = DEFAULT_API_URL,
        help    = f"API base URL (default: {DEFAULT_API_URL})",
    )

    args = parser.parse_args()
    run_simulator(
        mode    = args.mode,
        count   = args.count,
        delay   = args.delay,
        api_url = args.api,
    )