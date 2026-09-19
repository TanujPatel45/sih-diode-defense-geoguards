"""
schemas.py
----------
Standardized Alert Schema and Pydantic validation models for GeoGuards (SIH 26145).
Enforces formal typing, evidence structure, and passive one-way safety guarantees.
"""

from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class EvidenceItem(BaseModel):
    feature: str = Field(..., description="Observed feature name or metadata signal")
    observed_value: Any = Field(..., description="Actual measured value (numeric or string)")
    interpretation: str = Field(..., description="Human-readable forensic interpretation")

class StandardizedAlert(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO 8601 UTC timestamp")
    flow_id: str = Field(..., description="Unique flow or session identifier")
    src_ip: str = Field(..., description="Observed source IP address")
    dst_ip: str = Field("0.0.0.0", description="Observed destination IP address")
    src_port: int = Field(0, ge=0, le=65535, description="Source port")
    dst_port: int = Field(0, ge=0, le=65535, description="Destination port")
    protocol: int = Field(0, description="IP protocol (6=TCP, 17=UDP, 1=ICMP)")
    
    threat_class: str = Field(..., description="Categorized threat class from taxonomy")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Calibrated classification confidence")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Fused multi-signal risk score")
    severity: str = Field(..., description="CRITICAL | HIGH | MEDIUM | LOW | BENIGN")
    
    detection_sources: List[str] = Field(..., description="Contributing engines: supervised_classifier, anomaly_detector, behaviour_analytics, dga_engine, etc.")
    evidence: List[EvidenceItem] = Field(default_factory=list, description="Structured measurable forensic evidence")
    
    model_version: str = Field("DiodeThreatNet-v1.0-baseline", description="Active model version")
    feature_schema_version: str = Field("v1.0-baseline", description="Active feature schema version")
    analysis_mode: str = Field("live_ingest", description="live_ingest | pcap_replay | offline_pcap | synthetic_demo")
    one_way_safe: bool = Field(True, description="Enforces that no outbound packet was transmitted")
    dataset_source: Optional[str] = Field(None, description="Benchmark or dataset origin if applicable")

class IngestFlowRequest(BaseModel):
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: str = Field("0.0.0.0", description="Destination IP address")
    source_port: int = Field(0, ge=0, le=65535)
    destination_port: int = Field(0, ge=0, le=65535)
    protocol: int = Field(0, description="IP protocol number")

    # 6 Baseline features
    iat_mean: float = Field(..., ge=0.0)
    iat_std: float = Field(..., ge=0.0)
    pkt_len_mean: float = Field(..., ge=0.0)
    pkt_len_std: float = Field(..., ge=0.0)
    payload_entropy: float = Field(..., ge=0.0, le=8.0)
    syn_ratio: float = Field(..., ge=0.0, le=1.0)

    # Optional extended metadata features
    duration: Optional[float] = Field(0.0, ge=0.0)
    packet_count: Optional[int] = Field(0, ge=0)
    byte_count: Optional[int] = Field(0, ge=0)
    packets_per_second: Optional[float] = Field(0.0, ge=0.0)
    bytes_per_second: Optional[float] = Field(0.0, ge=0.0)
    iat_min: Optional[float] = Field(0.0, ge=0.0)
    iat_max: Optional[float] = Field(0.0, ge=0.0)
    pkt_len_min: Optional[float] = Field(0.0, ge=0.0)
    pkt_len_max: Optional[float] = Field(0.0, ge=0.0)
    forward_packet_count: Optional[int] = Field(0, ge=0)
    backward_packet_count: Optional[int] = Field(0, ge=0)
    forward_bytes: Optional[int] = Field(0, ge=0)
    backward_bytes: Optional[int] = Field(0, ge=0)
    syn_count: Optional[int] = Field(0, ge=0)
    rst_count: Optional[int] = Field(0, ge=0)
    fin_count: Optional[int] = Field(0, ge=0)
    tcp_rst_ratio: Optional[float] = Field(0.0, ge=0.0, le=1.0)
    tcp_fin_ratio: Optional[float] = Field(0.0, ge=0.0, le=1.0)
    dns_query: Optional[str] = Field(None, description="Optional DNS query string if DNS flow")
    analysis_mode: Optional[str] = Field("live_ingest")
