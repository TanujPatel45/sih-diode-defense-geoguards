/**
 * types.ts — Shared TypeScript interfaces for GeoGuards SOC Dashboard (SIH 26145)
 */

export interface StructuredEvidence {
  feature:          string;
  observed_value:   string | number | boolean;
  interpretation:   string;
}

export interface Alert {
  alert_id:              string;
  timestamp:             string;
  flow_id?:              string;
  model_version?:        string;
  feature_schema_version?: string;
  analysis_mode?:        string;
  one_way_safe?:         boolean;
  source_ip:             string;
  destination_ip:        string;
  source_port:           number;
  destination_port:      number;
  protocol:              number;
  prediction:            string;
  confidence:            number;
  threat_class?:         string;
  dominant_threat:       string;
  anomaly_score:         number;
  is_anomaly:            boolean;
  behaviour_score:       number;
  behaviour_type:        string;
  final_risk_score:      number;
  risk_score?:           number;
  severity:              string;
  detection_sources?:    string[];
  evidence:              (string | StructuredEvidence)[];
  explanation:           string;
  inference_latency_ms?: number;
  features?:             Record<string, number | string>;
}

export interface Stats {
  flows_processed:                number;
  threats_detected:               number;
  high_risk_alerts:               number;
  anomaly_count:                  number;
  average_inference_latency_ms:   number | null;
  last_inference_latency_ms?:     number | null;
  storage_backend:                string;
  model_version:                  string;
  feature_schema_version?:        string;
  anomaly_baseline_source?:       string;
  one_way_safe?:                  boolean;
  started_at:                     string;
  active_analysis_mode?:          string;
  last_alert_source?:             string;
}

export interface HealthStatus {
  status:                  string;
  model_loaded:            boolean;
  scaler_loaded:           boolean;
  db_available:            boolean;
  model_version:           string;
  feature_schema_version?: string;
  one_way_safe?:           boolean;
  mode?:                   string;
}

export interface TimelineEvent {
  timestamp:       string;
  flow_id:         string;
  threat_category: string;
  src_ip:          string;
  dst_ip:          string;
  dst_port:        number;
  confidence:      number;
  risk_score:      number;
  key_evidence:    string;
}

export interface CorrelationCluster {
  cluster_id:        string;
  src_ip:            string;
  first_seen:        string;
  last_seen:         string;
  total_flows:       number;
  threat_categories: string[];
  max_risk_score:    number;
  correlated_score:  number;
  status:            string;
  narrative:         string;
  timeline:          TimelineEvent[];
}

export interface StreamingTelemetry {
  status:                   string;
  packets_processed:        number;
  bytes_processed:          number;
  flows_processed:          number;
  alerts_emitted:           number;
  elapsed_time_sec:         number;
  flows_per_second:         number;
  throughput_mbps:          number;
  avg_inference_latency_ms: number;
  p50_inference_latency_ms: number;
  p95_inference_latency_ms: number;
}

export interface StreamingReplayResponse {
  message:          string;
  telemetry:        StreamingTelemetry;
  total_alerts?:    number;
  returned_alerts?: number;
  alerts_count:     number;
  alerts_truncated?: boolean;
  alerts:           Alert[];
}

export interface PcapAnalysisResult {
  message:          string;
  flow_count?:      number;
  total_alerts?:    number;
  returned_alerts?: number;
  alerts_count?:    number;
  alerts_truncated?: boolean;
  results:          Alert[];
  telemetry?:       StreamingTelemetry;
}

export interface TrendPoint {
  time:    string;
  threats: number;
  benign:  number;
}

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type ApiStatus     = 'ok' | 'error' | 'loading';
