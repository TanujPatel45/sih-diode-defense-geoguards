"""
correlation.py
--------------
Lightweight Passive Cross-Flow Threat Correlation Engine for GeoGuards (SIH 26145).

Correlates individual flow-level detections across:
- Source IP host aggregation
- Destination subnet / external endpoint clustering
- Temporal sliding windows (e.g., 5-minute / 15-minute correlation windows)
- Multi-stage attack progression (e.g., Reconnaissance -> C2 Beaconing -> DNS Tunnelling -> Data Exfiltration)

Produces:
- Correlation Cluster ID
- Multi-Signal Threat Score (Confidence-preserving fused correlation score)
- Correlation Verdict ("Correlated multi-stage activity", NOT overconfident claims)
- Analyst Forensic Timeline with chronological observation steps
"""

import time
import uuid
from typing import Dict, Any, List, Optional
from collections import defaultdict, deque
from datetime import datetime, timezone
from pydantic import BaseModel, Field

class TimelineEvent(BaseModel):
    timestamp: str
    flow_id: str
    threat_category: str
    src_ip: str
    dst_ip: str
    dst_port: int
    confidence: float
    risk_score: float
    key_evidence: str

class CorrelatedThreatGroup(BaseModel):
    cluster_id: str
    src_ip: str
    first_seen: str
    last_seen: str
    total_flows: int
    threat_categories: List[str]
    attack_stages: List[str] = Field(default_factory=list)
    attack_story: Optional[str] = None
    max_risk_score: float
    correlated_score: float
    status: str
    narrative: str
    timeline: List[TimelineEvent]

def map_threat_to_stage(threat_category: str) -> str:
    """Maps a threat category string to a high-level attack lifecycle stage."""
    tc = threat_category.lower()
    if "recon" in tc or "scan" in tc:
        return "Reconnaissance"
    if "c2" in tc or "beacon" in tc:
        return "C2 Beaconing"
    if "dns" in tc or "dga" in tc or "tunnel" in tc:
        return "DNS Tunnelling"
    if "exfil" in tc or "drain" in tc:
        return "Data Exfiltration"
    if "ddos" in tc or "flood" in tc:
        return "Volumetric Attack"
    if "encrypt" in tc or "malware" in tc:
        return "Encrypted Session Malware"
    return threat_category

class ThreatCorrelationEngine:
    """
    Passive state-tracking correlation engine.
    Maintains bounded in-memory sliding windows per Source IP.
    """
    def __init__(self, window_seconds: float = 900.0, max_tracked_hosts: int = 200):
        self.window_seconds = window_seconds
        self.max_tracked_hosts = max_tracked_hosts
        # Map: src_ip -> deque of alerts
        self._host_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        # Map: cluster_id -> CorrelatedThreatGroup
        self._active_clusters: Dict[str, CorrelatedThreatGroup] = {}

    def reset(self):
        """Clears all host history and active correlation clusters."""
        self._host_history.clear()
        self._active_clusters.clear()

    def get_cluster_by_src_ip(self, src_ip: str) -> Optional[CorrelatedThreatGroup]:
        cluster_id = f"cluster-{src_ip.replace('.', '-')}"
        return self._active_clusters.get(cluster_id)

    def ingest_alert(self, alert_dict: Dict[str, Any]) -> Optional[CorrelatedThreatGroup]:
        src_ip = alert_dict.get("source_ip") or alert_dict.get("src_ip") or "0.0.0.0"
        threat = alert_dict.get("dominant_threat") or alert_dict.get("threat_class") or alert_dict.get("prediction") or "Benign"
        
        if threat == "Benign" and not alert_dict.get("is_anomaly", False):
            return None

        now_ts = time.time()
        iso_ts = alert_dict.get("timestamp") or datetime.now(timezone.utc).isoformat()
        flow_id = alert_dict.get("alert_id") or alert_dict.get("flow_id") or str(uuid.uuid4())
        dst_ip = alert_dict.get("destination_ip") or alert_dict.get("dst_ip") or "0.0.0.0"
        dst_port = int(alert_dict.get("destination_port") or alert_dict.get("dst_port") or 0)
        conf = float(alert_dict.get("confidence", 0.5))
        risk = float(alert_dict.get("final_risk_score") or alert_dict.get("risk_score") or 0.5)

        # Extract summary evidence string
        evidence_list = alert_dict.get("evidence", [])
        if evidence_list and isinstance(evidence_list[0], dict):
            key_ev = evidence_list[0].get("interpretation", str(evidence_list[0]))
        elif evidence_list and isinstance(evidence_list[0], str):
            key_ev = evidence_list[0]
        else:
            key_ev = f"{threat} detected with risk {risk:.2f}"

        event = TimelineEvent(
            timestamp=iso_ts,
            flow_id=flow_id,
            threat_category=threat,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            confidence=conf,
            risk_score=risk,
            key_evidence=key_ev
        )

        history = self._host_history[src_ip]
        history.append((now_ts, event))

        # Evict old entries outside window
        while history and (now_ts - history[0][0]) > self.window_seconds:
            history.popleft()

        # If multiple alerts on same host, synthesize correlated cluster
        if len(history) >= 2:
            events = [h[1] for h in history]
            threats = list(set(e.threat_category for e in events))
            max_r = max(e.risk_score for e in events)
            
            # Map categories to lifecycle attack stages in chronological progression order
            canonical_sequence = ["Reconnaissance", "C2 Beaconing", "DNS Tunnelling", "Data Exfiltration", "Volumetric Attack", "Encrypted Session Malware"]
            observed_stages_set = set(map_threat_to_stage(e.threat_category) for e in events)
            
            ordered_stages = [stg for stg in canonical_sequence if stg in observed_stages_set]
            for stg in observed_stages_set:
                if stg not in ordered_stages and stg != "Benign":
                    ordered_stages.append(stg)

            # Multi-signal synergy boost (bounded between max_r and 1.0)
            diversity_multiplier = min(1.3, 1.0 + (len(threats) - 1) * 0.10 + (len(events) - 1) * 0.03)
            corr_score = min(1.0, round(max_r * diversity_multiplier, 3))

            # Forensic narrative and attack story
            attack_story = " -> ".join(ordered_stages)
            if len(ordered_stages) > 1:
                narrative = (
                    f"Host {src_ip} exhibits multi-stage attack progression: "
                    f"{attack_story} across {len(events)} correlated flows in the last "
                    f"{int(self.window_seconds/60)} minutes. Behavior is consistent with coordinated attack lifecycle."
                )
            else:
                narrative = (
                    f"Host {src_ip} triggered {len(events)} repeated {threats[0]} alerts. "
                    f"Sustained pattern suggests automated or persistent activity."
                )

            cluster_id = f"cluster-{src_ip.replace('.', '-')}"
            group = CorrelatedThreatGroup(
                cluster_id=cluster_id,
                src_ip=src_ip,
                first_seen=events[0].timestamp,
                last_seen=events[-1].timestamp,
                total_flows=len(events),
                threat_categories=threats,
                attack_stages=ordered_stages,
                attack_story=attack_story,
                max_risk_score=round(max_r, 3),
                correlated_score=corr_score,
                status="ACTIVE",
                narrative=narrative,
                timeline=events[-20:] # Keep latest 20 timeline steps
            )
            self._active_clusters[cluster_id] = group
            return group

        return None

    def get_active_clusters(self) -> List[CorrelatedThreatGroup]:
        return list(self._active_clusters.values())

_correlation_instance = None

def get_correlation_engine() -> ThreatCorrelationEngine:
    global _correlation_instance
    if _correlation_instance is None:
        _correlation_instance = ThreatCorrelationEngine()
    return _correlation_instance

