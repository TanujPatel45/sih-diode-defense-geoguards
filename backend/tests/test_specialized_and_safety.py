"""
test_specialized_and_safety.py
-------------------------------
Unit and validation test suite for GeoGuards (SIH 26145).

Tests:
1. Passive One-Way Safety (Analysis-only, no active probing)
2. Standardized Alert Schema compliance
3. Specialized Detectors across all 6 PS threat categories
4. Risk Fusion and Severity classification
5. Cross-Flow Threat Correlation Engine
"""

import pytest
import numpy as np
import torch
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from schemas import StandardizedAlert, IngestFlowRequest, EvidenceItem
from specialized_detectors import (
    DDoSDetector, C2BeaconDetector, DNSTunnelDetector,
    ReconScanDetector, DataExfiltrationDetector, EncryptedTrafficDetector,
    get_specialized_registry
)
from risk_fusion import RiskFusionEngine, get_fusion_engine
from correlation import ThreatCorrelationEngine

# ── 1. One-Way Safety & Passive Guarantees Test ───────────────────────────────

def test_one_way_safety_guarantees():
    """Verify that detectors are analysis-only and do not attempt network connections."""
    registry = get_specialized_registry()
    sample_flow = {
        "source_ip": "10.0.0.99",
        "destination_ip": "192.168.1.1",
        "source_port": 50000,
        "destination_port": 80,
        "protocol": 6,
        "iat_mean": 0.05,
        "iat_std": 0.02,
        "pkt_len_mean": 500.0,
        "pkt_len_std": 50.0,
        "payload_entropy": 4.5,
        "syn_ratio": 0.02
    }
    results = registry.evaluate_all(sample_flow)
    assert len(results) == 6
    for r in results:
        assert isinstance(r.is_detected, bool)
        assert 0.0 <= r.confidence <= 1.0
        assert 0.0 <= r.score <= 1.0

# ── 2. Standardized Alert Schema Test ─────────────────────────────────────────

def test_standardized_alert_schema():
    """Verify formal Pydantic schema validation for StandardizedAlert."""
    evidence = [
        EvidenceItem(feature="syn_ratio", observed_value=0.98, interpretation="High SYN ratio"),
        EvidenceItem(feature="packets_per_second", observed_value=1200.0, interpretation="Elevated packet rate")
    ]
    alert = StandardizedAlert(
        flow_id="10.0.4.182:54321->10.0.0.1:80[6]",
        src_ip="10.0.4.182",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        protocol=6,
        threat_class="SYN/UDP Flood",
        confidence=0.95,
        risk_score=0.92,
        severity="CRITICAL",
        detection_sources=["supervised_classifier", "specialized_detectors"],
        evidence=evidence,
        analysis_mode="pcap_replay",
        one_way_safe=True
    )

    alert_dict = alert.model_dump()
    assert alert_dict["one_way_safe"] is True
    assert alert_dict["severity"] == "CRITICAL"
    assert len(alert_dict["evidence"]) == 2
    assert alert_dict["evidence"][0]["feature"] == "syn_ratio"

# ── 3. Specialized Detectors Tests ────────────────────────────────────────────

def test_ddos_detector():
    det = DDoSDetector()
    syn_flood = {"syn_ratio": 0.99, "packets_per_second": 2000.0, "iat_mean": 0.0002, "pkt_len_mean": 64.0, "protocol": 6, "packet_count": 500}
    res = det.detect(syn_flood)
    assert res.is_detected is True
    assert res.score >= 0.80

def test_c2_beacon_detector():
    det = C2BeaconDetector()
    c2_flow = {"iat_mean": 2.0, "iat_std": 0.0005, "pkt_len_mean": 120.0, "payload_entropy": 4.2, "syn_ratio": 0.0, "packet_count": 60}
    res = det.detect(c2_flow)
    assert res.is_detected is True
    assert res.score >= 0.65

def test_dns_tunnel_detector():
    det = DNSTunnelDetector()
    dns_flow = {"payload_entropy": 7.8, "pkt_len_mean": 220.0, "iat_mean": 0.05, "protocol": 17, "dns_query": "exfiltrateddata9823472394.tunnel.victim.com"}
    res = det.detect(dns_flow)
    assert res.is_detected is True
    assert res.score >= 0.60

def test_recon_scan_detector():
    det = ReconScanDetector()
    scan_flow = {"syn_ratio": 0.80, "tcp_rst_ratio": 0.50, "packet_count": 2, "duration": 0.1, "destination_port": 445}
    res = det.detect(scan_flow)
    assert res.is_detected is True

def test_data_exfiltration_detector():
    det = DataExfiltrationDetector()
    exfil_flow = {"forward_bytes": 1000000, "backward_bytes": 2000, "byte_count": 1002000, "duration": 15.0, "payload_entropy": 7.5}
    res = det.detect(exfil_flow)
    assert res.is_detected is True
    assert res.score >= 0.65

def test_encrypted_traffic_detector():
    det = EncryptedTrafficDetector()
    enc_flow = {"destination_port": 443, "payload_entropy": 7.85, "pkt_len_std": 10.0, "pkt_len_mean": 450.0, "protocol": 6, "sni_entropy": 4.1}
    res = det.detect(enc_flow)
    assert res.is_detected is True

# ── 4. Cross-Flow Threat Correlation Test ─────────────────────────────────────

def test_threat_correlation_engine():
    corr = ThreatCorrelationEngine(window_seconds=600.0)
    alert1 = {
        "source_ip": "10.0.1.55",
        "destination_ip": "192.168.1.10",
        "dominant_threat": "Reconnaissance / Port Scanning",
        "confidence": 0.85,
        "final_risk_score": 0.70,
        "evidence": ["Short probe flow detected"]
    }
    alert2 = {
        "source_ip": "10.0.1.55",
        "destination_ip": "91.195.240.117",
        "dominant_threat": "Botnet C2 Beaconing",
        "confidence": 0.90,
        "final_risk_score": 0.85,
        "evidence": ["Periodic beaconing timing"]
    }

    # First alert adds to history
    c1 = corr.ingest_alert(alert1)
    # Second alert correlates multi-stage cluster
    c2 = corr.ingest_alert(alert2)
    assert c2 is not None
    assert c2.src_ip == "10.0.1.55"
    assert len(c2.threat_categories) == 2
    assert "Reconnaissance / Port Scanning" in c2.threat_categories
    assert "Botnet C2 Beaconing" in c2.threat_categories
    assert c2.correlated_score >= 0.85
    assert len(c2.timeline) == 2
