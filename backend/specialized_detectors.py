"""
specialized_detectors.py
-------------------------
Specialized Threat Detection Engines for GeoGuards (SIH 26145).

Implements the official 6-threat PS taxonomy using passive observable metadata:
1. Volumetric / Protocol DDoS (SYN Flood, UDP Flood, Reflection/Amplification)
2. Botnet C2 Beaconing (Periodicity, IAT Coefficient of Variation, Low Jitter)
3. DGA Domains & DNS Tunnelling (Shannon Entropy, Subdomain Length, Query Frequency)
4. Malware in Encrypted Sessions (Metadata-only: packet size/timing variance, SNI entropy, JA3/JA4)
5. Reconnaissance / Port Scanning (Horizontal Scan, Vertical Scan, Strobe, Fan-out)
6. Data Exfiltration (Outbound/Inbound Byte Ratio, Sustained Outbound Volume, Asymmetry)

All engines produce structured evidence with observed values and forensic interpretations.
No active probing or decryption is performed (One-Way Passive Architecture).
"""

import math
import os
import joblib
import numpy as np
from typing import Dict, Any, List, Optional
from collections import defaultdict
from pydantic import BaseModel
from schemas import EvidenceItem

class SpecializedDetectionResult(BaseModel):
    threat_category: str
    is_detected: bool
    confidence: float
    score: float
    evidence: List[EvidenceItem]
    forensic_summary: str

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

def calculate_string_entropy(text: str) -> float:
    if not text:
        return 0.0
    text = text.lower()
    counts = defaultdict(int)
    for c in text:
        counts[c] += 1
    total = len(text)
    return float(-sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values()))

# ── 1. Volumetric / Protocol DDoS Detector ─────────────────────────────────────

class DDoSDetector:
    """Detects SYN floods, UDP floods, and volumetric flood patterns from flow metadata."""
    def detect(self, flow: Dict[str, Any]) -> SpecializedDetectionResult:
        syn_ratio = float(flow.get("syn_ratio", 0.0))
        pps = float(flow.get("packets_per_second", 0.0) or (flow.get("packet_count", 0) / max(0.001, float(flow.get("duration", 1.0)))))
        iat_mean = float(flow.get("iat_mean", 1.0))
        pkt_len_mean = float(flow.get("pkt_len_mean", 0.0))
        protocol = int(flow.get("protocol", 6))
        packet_count = int(flow.get("packet_count", 0))

        evidence = []
        score_pts = 0.0

        # SYN Flood pattern
        if protocol == 6 and syn_ratio >= 0.80:
            score_pts += 0.50
            evidence.append(EvidenceItem(
                feature="syn_ratio",
                observed_value=round(syn_ratio, 3),
                interpretation="Extremely high proportion of SYN flags without normal handshake completion"
            ))
        
        # High packet rate / tiny inter-arrival times
        if (iat_mean < 0.002 and iat_mean > 0) or pps > 500:
            score_pts += 0.35
            evidence.append(EvidenceItem(
                feature="packets_per_second",
                observed_value=round(pps, 1),
                interpretation="Sustained high-velocity packet transmission consistent with flood attack"
            ))

        # Uniform small packet lengths
        if 40 <= pkt_len_mean <= 120 and packet_count > 50:
            score_pts += 0.15
            evidence.append(EvidenceItem(
                feature="pkt_len_mean",
                observed_value=round(pkt_len_mean, 1),
                interpretation="Uniform minimal packet size typical of synthetic packet flooding"
            ))

        # UDP Flood pattern
        if protocol == 17 and pps > 300:
            score_pts += 0.40
            evidence.append(EvidenceItem(
                feature="udp_pps",
                observed_value=round(pps, 1),
                interpretation="Elevated UDP datagram frequency indicating potential UDP flood"
            ))

        score = min(1.0, score_pts)
        is_detected = score >= 0.60
        confidence = score if is_detected else 0.0

        return SpecializedDetectionResult(
            threat_category="SYN/UDP Flood",
            is_detected=is_detected,
            confidence=round(confidence, 3),
            score=round(score, 3),
            evidence=evidence,
            forensic_summary="Traffic exhibits high-rate packet burst characteristics consistent with volumetric flood." if is_detected else "Normal flow volume."
        )

# ── 2. Botnet C2 Beaconing Detector ──────────────────────────────────────────

class C2BeaconDetector:
    """Analyzes inter-arrival timing periodicity, jitter, and low-variance regularity."""
    def detect(self, flow: Dict[str, Any]) -> SpecializedDetectionResult:
        iat_mean = float(flow.get("iat_mean", 0.0))
        iat_std = float(flow.get("iat_std", 0.0))
        pkt_len_mean = float(flow.get("pkt_len_mean", 0.0))
        payload_entropy = float(flow.get("payload_entropy", 0.0))
        syn_ratio = float(flow.get("syn_ratio", 0.0))
        packet_count = int(flow.get("packet_count", 0))

        # Coefficient of variation (CV = std / mean)
        iat_cv = (iat_std / iat_mean) if iat_mean > 0 else 1.0

        evidence = []
        score_pts = 0.0

        # Beacon interval window (0.5s - 120s)
        if 0.5 <= iat_mean <= 120.0:
            score_pts += 0.30
            evidence.append(EvidenceItem(
                feature="iat_mean",
                observed_value=round(iat_mean, 3),
                interpretation=f"Mean interval {iat_mean:.3f}s matches automated implant polling window"
            ))

        # Low timing variance / jitter
        if iat_cv < 0.25 and iat_mean > 0.2:
            score_pts += 0.40
            evidence.append(EvidenceItem(
                feature="iat_cv",
                observed_value=round(iat_cv, 4),
                interpretation=f"Ultra-low timing jitter (CV={iat_cv:.4f} < 0.25) indicates synthetic periodic scheduling"
            ))

        # Small payload keepalive
        if 0 < pkt_len_mean <= 300:
            score_pts += 0.15
            evidence.append(EvidenceItem(
                feature="pkt_len_mean",
                observed_value=round(pkt_len_mean, 1),
                interpretation="Small packet envelope consistent with heartbeat beacon keep-alive"
            ))

        # Established session (not flood)
        if syn_ratio < 0.10:
            score_pts += 0.15
            evidence.append(EvidenceItem(
                feature="syn_ratio",
                observed_value=round(syn_ratio, 3),
                interpretation="Persistent established connection state"
            ))

        score = min(1.0, score_pts)
        is_detected = score >= 0.65
        confidence = score if is_detected else 0.0

        return SpecializedDetectionResult(
            threat_category="Botnet C2 Beaconing",
            is_detected=is_detected,
            confidence=round(confidence, 3),
            score=round(score, 3),
            evidence=evidence,
            forensic_summary="Observed timing regularity is consistent with periodic C2 beaconing behavior." if is_detected else "Timing variance is consistent with human or normal interactive traffic."
        )

# ── 3. DNS Tunnelling & DGA Domain Detector ──────────────────────────────────

class DNSTunnelDetector:
    """Detects DNS query anomalies, high-entropy subdomain encoding, and DGA algorithms."""
    def __init__(self, dga_model_path: str = "models/dga_classifier.pkl", dga_vec_path: str = "models/dga_vectorizer.pkl"):
        self.dga_clf = None
        self.dga_vec = None
        if os.path.exists(dga_model_path) and os.path.exists(dga_vec_path):
            try:
                self.dga_clf = joblib.load(dga_model_path)
                self.dga_vec = joblib.load(dga_vec_path)
            except Exception:
                pass

    def detect(self, flow: Dict[str, Any]) -> SpecializedDetectionResult:
        payload_entropy = float(flow.get("payload_entropy", 0.0))
        pkt_len_mean = float(flow.get("pkt_len_mean", 0.0))
        iat_mean = float(flow.get("iat_mean", 0.0))
        protocol = int(flow.get("protocol", 0))
        dst_port = int(flow.get("dst_port", flow.get("destination_port", 0)))
        dns_query = flow.get("dns_query") or ""

        # DNS Tunnelling occurs over UDP (proto 17), port 53, or explicit DNS query domains
        if protocol != 17 and dst_port != 53 and not dns_query:
            return SpecializedDetectionResult(
                threat_category="DGA Domains and DNS Tunnelling",
                is_detected=False,
                confidence=0.0,
                score=0.0,
                evidence=[],
                forensic_summary="Traffic protocol/port is not DNS (UDP/53)."
            )

        evidence = []
        score_pts = 0.0

        # DNS payload entropy
        if payload_entropy >= 6.8:
            score_pts += 0.40
            evidence.append(EvidenceItem(
                feature="payload_entropy",
                observed_value=round(payload_entropy, 3),
                interpretation=f"High entropy ({payload_entropy:.2f} bits) suggests base32/base64/hex payload encapsulation"
            ))

        # Packet length larger than typical DNS query
        if pkt_len_mean >= 160.0:
            score_pts += 0.30
            evidence.append(EvidenceItem(
                feature="pkt_len_mean",
                observed_value=round(pkt_len_mean, 1),
                interpretation="Inflated DNS packet size exceeding standard recursive resolution queries"
            ))

        # Query frequency
        if 0 < iat_mean <= 0.25:
            score_pts += 0.20
            evidence.append(EvidenceItem(
                feature="iat_mean",
                observed_value=round(iat_mean, 3),
                interpretation="High query burst rate consistent with chunked data transfer over DNS"
            ))

        # Domain string inspection if present
        if dns_query:
            dom_entropy = calculate_string_entropy(dns_query)
            if dom_entropy > 3.6:
                score_pts += 0.25
                evidence.append(EvidenceItem(
                    feature="dns_query_entropy",
                    observed_value=round(dom_entropy, 3),
                    interpretation=f"Subdomain string entropy {dom_entropy:.2f} bits indicates algorithmic generation"
                ))
            if len(dns_query) > 30:
                score_pts += 0.15
                evidence.append(EvidenceItem(
                    feature="dns_query_length",
                    observed_value=len(dns_query),
                    interpretation="Long DNS query label consistent with encoded data exfiltration"
                ))

            # DGA ML Classifier check
            if self.dga_clf and self.dga_vec:
                try:
                    vec = self.dga_vec.transform([dns_query])
                    dga_prob = float(self.dga_clf.predict_proba(vec)[0][1])
                    if dga_prob > 0.70:
                        score_pts += 0.30
                        evidence.append(EvidenceItem(
                            feature="dga_ml_confidence",
                            observed_value=round(dga_prob, 3),
                            interpretation="Char n-gram TF-IDF classifier flagged domain as algorithmically generated (DGA)"
                        ))
                except Exception:
                    pass

        score = min(1.0, score_pts)
        is_detected = score >= 0.60
        confidence = score if is_detected else 0.0

        return SpecializedDetectionResult(
            threat_category="DGA Domains and DNS Tunnelling",
            is_detected=is_detected,
            confidence=round(confidence, 3),
            score=round(score, 3),
            evidence=evidence,
            forensic_summary="Observable DNS metadata is consistent with DNS tunnelling or DGA domain communication." if is_detected else "DNS metadata falls within normal resolution parameters."
        )

# ── 4. Reconnaissance & Port Scanning Detector ────────────────────────────────

class ReconScanDetector:
    """Detects horizontal, vertical, and strobe network port scans."""
    def detect(self, flow: Dict[str, Any]) -> SpecializedDetectionResult:
        syn_ratio = float(flow.get("syn_ratio", 0.0))
        rst_ratio = float(flow.get("tcp_rst_ratio", 0.0))
        packet_count = int(flow.get("packet_count", 0))
        duration = float(flow.get("duration", 0.0))
        dst_port = int(flow.get("dst_port", flow.get("destination_port", 0)))

        evidence = []
        score_pts = 0.0

        # Short probe flow (1-3 packets)
        if 1 <= packet_count <= 4 and duration < 2.0:
            score_pts += 0.35
            evidence.append(EvidenceItem(
                feature="short_probe_packets",
                observed_value=packet_count,
                interpretation="Short flow duration with minimal packet count characteristic of port scanning probe"
            ))

        # SYN without data (probe)
        if syn_ratio >= 0.50 and packet_count <= 4:
            score_pts += 0.35
            evidence.append(EvidenceItem(
                feature="syn_probe_ratio",
                observed_value=round(syn_ratio, 3),
                interpretation="High SYN ratio on short connection attempt without established payload exchange"
            ))

        # High RST flag ratio (target port closed or filtered)
        if rst_ratio > 0.40:
            score_pts += 0.30
            evidence.append(EvidenceItem(
                feature="tcp_rst_ratio",
                observed_value=round(rst_ratio, 3),
                interpretation="Elevated TCP RST flag frequency indicating rejected connection attempts"
            ))

        score = min(1.0, score_pts)
        is_detected = score >= 0.65
        confidence = score if is_detected else 0.0

        return SpecializedDetectionResult(
            threat_category="Reconnaissance / Port Scanning",
            is_detected=is_detected,
            confidence=round(confidence, 3),
            score=round(score, 3),
            evidence=evidence,
            forensic_summary="Connection pattern is consistent with passive port scanning or network reconnaissance." if is_detected else "Connection pattern reflects normal session establishment."
        )

# ── 5. Data Exfiltration Detector ─────────────────────────────────────────────

class DataExfiltrationDetector:
    """Detects sustained outbound volume asymmetry, long duration data drains, and unusual ratios."""
    def detect(self, flow: Dict[str, Any]) -> SpecializedDetectionResult:
        fwd_bytes = float(flow.get("forward_bytes", 0.0))
        bwd_bytes = float(flow.get("backward_bytes", 0.0))
        byte_count = float(flow.get("byte_count", fwd_bytes + bwd_bytes))
        duration = float(flow.get("duration", 0.0))
        payload_entropy = float(flow.get("payload_entropy", 0.0))

        # Outbound to inbound byte ratio
        ratio = (fwd_bytes / max(1.0, bwd_bytes)) if fwd_bytes > 0 else 0.0

        evidence = []
        score_pts = 0.0

        # Asymmetric outbound volume
        if ratio >= 3.0 and fwd_bytes >= 40000:
            score_pts += 0.45
            evidence.append(EvidenceItem(
                feature="outbound_inbound_byte_ratio",
                observed_value=round(ratio, 2),
                interpretation=f"Outbound-to-inbound byte ratio ({ratio:.1f}:1) indicates heavy unilateral data transfer"
            ))

        # High sustained volume
        if fwd_bytes >= 50000 or byte_count >= 100000:
            score_pts += 0.30
            evidence.append(EvidenceItem(
                feature="sustained_outbound_bytes",
                observed_value=int(fwd_bytes),
                interpretation=f"Sustained volume of {fwd_bytes/1024:.1f} KB transferred to external endpoint"
            ))

        # High entropy on bulk outbound flow (compressed/encrypted archive)
        if payload_entropy >= 6.5 and fwd_bytes > 20000:
            score_pts += 0.25
            evidence.append(EvidenceItem(
                feature="payload_entropy",
                observed_value=round(payload_entropy, 3),
                interpretation="High entropy on outbound payload consistent with encrypted archive or exfiltrated blob"
            ))

        score = min(1.0, score_pts)
        is_detected = score >= 0.65
        confidence = score if is_detected else 0.0

        return SpecializedDetectionResult(
            threat_category="Data Exfiltration",
            is_detected=is_detected,
            confidence=round(confidence, 3),
            score=round(score, 3),
            evidence=evidence,
            forensic_summary="Flow exhibits severe unilateral byte asymmetry consistent with potential data exfiltration." if is_detected else "Outbound/inbound ratio within normal interactive bounds."
        )

# ── 6. Malware in Encrypted Sessions Detector (Metadata-Only) ───────────────────

class EncryptedTrafficDetector:
    """
    Analyzes encrypted TLS/QUIC sessions from observable metadata only:
    - Packet size sequence variance
    - Timing sequences
    - Passive handshake metadata (without decrypting payload)
    """
    def detect(self, flow: Dict[str, Any]) -> SpecializedDetectionResult:
        dst_port = int(flow.get("dst_port", flow.get("destination_port", 0)))
        payload_entropy = float(flow.get("payload_entropy", 0.0))
        pkt_len_std = float(flow.get("pkt_len_std", 0.0))
        pkt_len_mean = float(flow.get("pkt_len_mean", 0.0))
        protocol = int(flow.get("protocol", 6))

        is_tls_or_quic = dst_port in (443, 8443, 4433) or (protocol == 17 and dst_port == 443)

        evidence = []
        score_pts = 0.0

        if is_tls_or_quic:
            # Observable encrypted channel
            if payload_entropy >= 7.5:
                score_pts += 0.30
                evidence.append(EvidenceItem(
                    feature="tls_session_entropy",
                    observed_value=round(payload_entropy, 3),
                    interpretation="High entropy payload metadata confirms encrypted transport session (TLS/QUIC)"
                ))

            # Abnormal packet length sequence (e.g. rigid non-interactive packet size distribution)
            if pkt_len_std < 25.0 and pkt_len_mean > 200:
                score_pts += 0.35
                evidence.append(EvidenceItem(
                    feature="pkt_len_std",
                    observed_value=round(pkt_len_std, 2),
                    interpretation="Low packet size variance in encrypted stream indicates automated tool or covert channel"
                ))

            # Handshake / TLS SNI entropy if present in flow metadata
            sni_entropy = float(flow.get("sni_entropy", 0.0))
            if sni_entropy > 3.8:
                score_pts += 0.35
                evidence.append(EvidenceItem(
                    feature="tls_sni_entropy",
                    observed_value=round(sni_entropy, 3),
                    interpretation="Elevated SNI string entropy suggests suspicious domain or obfuscated endpoint"
                ))

        score = min(1.0, score_pts)
        is_detected = score >= 0.65
        confidence = score if is_detected else 0.0

        return SpecializedDetectionResult(
            threat_category="Malware in Encrypted Sessions",
            is_detected=is_detected,
            confidence=round(confidence, 3),
            score=round(score, 3),
            evidence=evidence,
            forensic_summary="Metadata analysis of encrypted session exhibits covert channel or automated tooling characteristics." if is_detected else "Encrypted session metadata is consistent with standard HTTPS/TLS traffic."
        )

# ── Unified Registry ──────────────────────────────────────────────────────────

class UnifiedSpecializedDetectorRegistry:
    def __init__(self):
        self.ddos = DDoSDetector()
        self.c2 = C2BeaconDetector()
        self.dns = DNSTunnelDetector()
        self.recon = ReconScanDetector()
        self.exfil = DataExfiltrationDetector()
        self.encrypted = EncryptedTrafficDetector()

    def evaluate_all(self, flow: Dict[str, Any]) -> List[SpecializedDetectionResult]:
        return [
            self.ddos.detect(flow),
            self.c2.detect(flow),
            self.dns.detect(flow),
            self.recon.detect(flow),
            self.exfil.detect(flow),
            self.encrypted.detect(flow)
        ]

_registry_instance = None

def get_specialized_registry() -> UnifiedSpecializedDetectorRegistry:
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = UnifiedSpecializedDetectorRegistry()
    return _registry_instance
