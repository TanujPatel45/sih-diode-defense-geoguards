# GEOGUARDS — PRODUCTIZATION AUDIT REPORT (PHASE 1)
**SIH 2026 Problem Statement 26145**: *AI-Based Detection of Cyber Threats in Unidirectional IP Traffic*  
**Date**: September 2026  
**System**: GeoGuards Passive Cyber Intelligence Platform  

---

## 1. Executive Summary

An exhaustive audit of the existing GeoGuards backend and frontend codebases was conducted to identify existing capabilities, reusable primitives, API contracts, telemetry paths, and UI components prior to final productization.

The core architecture follows a strictly **passive software monitoring layer designed to operate behind a hardware-enforced unidirectional boundary**, adhering to the principle:
$$\text{Traffic} \longrightarrow \text{Passive Ingestion} \longrightarrow \text{Flow Extraction} \longrightarrow \text{Multi-Signal Detection} \longrightarrow \text{Risk Fusion} \longrightarrow \text{Forensic Alert} \longrightarrow \text{Correlation} \longrightarrow \text{Attack Story} \longrightarrow \text{Continuous Monitoring}$$

**Zero active network intervention is performed**: No packet blocking, RST injection, ICMP unreachable generation, port scanning, or firewall manipulation exists or will be added.

---

## 2. Existing Correlation Functionality

### Backend Implementation (`backend/correlation.py`)
- **Engine Class**: `ThreatCorrelationEngine` (singleton via `get_correlation_engine()`).
- **Data Models**:
  - `TimelineEvent`: `timestamp`, `flow_id`, `threat_category`, `src_ip`, `dst_ip`, `dst_port`, `confidence`, `risk_score`, `key_evidence`.
  - `CorrelatedThreatGroup`: `cluster_id`, `src_ip`, `first_seen`, `last_seen`, `total_flows`, `threat_categories`, `max_risk_score`, `correlated_score`, `status`, `narrative`, `timeline`.
- **Correlation Logic**:
  - Groups incoming alerts by `src_ip` within a configurable sliding temporal window (`window_seconds=900.0`, i.e., 15 minutes).
  - Purges inactive clusters older than `2 * window_seconds`.
  - Maintains an ordered `timeline` of events per cluster.
  - **Multi-Signal Synergy Boost**: Calculates a synergistic correlated risk boost when multiple threat categories or high flow volumes are observed:
    $$\text{synergy} = \min(0.25, 0.05 \times (\text{distinct\_categories} - 1) + 0.02 \times \min(5, \text{total\_flows} - 1))$$
    $$\text{correlated\_score} = \min(1.0, \text{max\_risk} + \text{synergy})$$
  - **Attack Story Progression & Narrative Synthesis**:
    - Generates dynamic, factual narratives based on the observed progression:
      - Reconnaissance followed by exploitation/C2/exfiltration.
      - Periodic C2 beaconing followed by high-entropy DNS data tunneling.
      - Volumetric flood accompanied by multi-vector probe traffic.
    - Honors epistemic humility: uses precise, restrained language ("consistent with", "suspected", "observed", "passive metadata indicates") rather than fabricating assumptions of host compromise.
- **Frontend State**:
  - `API.correlationClusters()` fetches `CorrelationCluster[]`.
  - The frontend type `CorrelationCluster` and `TimelineEvent` are already declared in `frontend/app/lib/types.ts`.

---

## 3. Existing Incident & Cluster APIs

| HTTP Method | Endpoint | Handler | Description | Return Type |
|---|---|---|---|---|
| `GET` | `/api/v1/correlation/clusters` | `get_correlation_clusters()` | Returns active threat clusters grouped by source IP within the correlation window with timeline & narrative. | `List[CorrelatedThreatGroup]` |
| `GET` | `/api/v1/alerts` | `get_alerts(limit, severity)` | Retrieves recent alerts from in-memory ring buffer (up to 1,000) or MongoDB. | `List[StandardizedAlert]` |
| `GET` | `/api/v1/alerts/{alert_id}` | `get_alert_by_id(alert_id)` | Retrieves single alert with structured evidence. | `StandardizedAlert` |
| `GET` | `/api/v1/flows` | `get_flows(limit)` | Retrieves all analyzed flows (benign + malicious) from memory ring buffer (up to 2,000). | `List[StandardizedAlert]` |

---

## 4. Existing Alert Fields & Schemas

### Standardized Alert (`backend/schemas.py` & `backend/main.py`)
- **Identification & Timestamps**: `alert_id`, `timestamp` (ISO 8601 UTC), `flow_id`.
- **5-Tuple Flow Metadata**: `source_ip` / `src_ip`, `destination_ip` / `dst_ip`, `source_port` / `src_port`, `destination_port` / `dst_port`, `protocol` (6=TCP, 17=UDP, 1=ICMP).
- **Classification & Consensus**:
  - `prediction` / `threat_class`: ML classifier prediction.
  - `confidence`: PyTorch MLP softmax score $[0, 1]$.
  - `dominant_threat`: Primary recognized signature.
  - `anomaly_score`: Isolation Forest outlier score $[0, 1]$.
  - `is_anomaly`: Boolean threshold flag ($\ge 0.55$).
  - `behaviour_score`: Heuristic score $[0, 1]$.
  - `behaviour_type`: Specific heuristic pattern name.
  - `final_risk_score` / `risk_score`: Calibrated consensus score $[0, 1]$.
  - `severity`: Categorical band (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `BENIGN`).
- **Explainability & Attribution**:
  - `detection_sources`: Contributing detectors (`supervised_classifier`, `anomaly_detector`, `behaviour_analytics`, `ddos_detector`, `c2_beacon_detector`, `dns_tunnel_detector`, `recon_scan_detector`, `data_exfiltration_detector`, `encrypted_traffic_detector`).
  - `evidence`: List of `EvidenceItem` (`feature`, `observed_value`, `interpretation`).
  - `explanation`: Plain-language forensic rationale generated from observed features.
- **Operational Provenance**:
  - `model_version`: `DiodeThreatNet-v1.0-baseline`.
  - `feature_schema_version`: `v1.0-baseline`.
  - `analysis_mode`: `streaming_pcap_replay` | `demo_simulation` | `live_ingest` | `offline_pcap`.
  - `one_way_safe`: `True` (enforcing zero packet egress).

---

## 5. Existing Telemetry & System Statistics

### System Stats (`GET /api/v1/stats`)
- `flows_processed`: Total flow count processed by the backend.
- `threats_detected`: Count of non-benign flow alerts emitted.
- `high_risk_alerts`: Count of `HIGH` and `CRITICAL` severity events.
- `anomaly_count`: Count of Isolation Forest outlier detections.
- `average_inference_latency_ms`: Measured cumulative average inference latency per flow (typically $0.05 - 0.08\text{ ms}$).
- `last_inference_latency_ms`: Latency of most recent inference evaluation.
- `storage_backend`: Active backend (`in-memory (high performance)` or `MongoDB`).
- `model_version`: Active model identifier.
- `anomaly_baseline_source`: Origin of benign baseline (`Real Clean Benign Traffic (CIC-IDS2017 Monday/Tuesday)`).
- `one_way_safe`: System-wide unidirectional safety flag (`True`).
- `active_analysis_mode`: Current active operational ingestion mode.
- `last_alert_source`: Provenance of the most recent alert.

### Health Check (`GET /api/v1/health`)
- `status`: `"ok"`.
- `model_loaded`: `True`.
- `scaler_loaded`: `True`.
- `db_available`: `False` (in-memory mode) or `True` (MongoDB connected).
- `model_version`: Active version string.
- `one_way_safe`: `True`.
- `mode`: `"PASSIVE_UNIDIRECTIONAL_MONITORING"`.

---

## 6. Existing PCAP Replay Functionality

- **Engine (`backend/streaming_engine.py`)**:
  - `StreamingReplaySession`: Incremental packet reader using Scapy `PcapReader` in a background worker thread (`_run_replay_worker`).
  - Decoupled from the async event loop using `asyncio.Queue` and threadsafe scheduling, preventing FastAPI/Uvicorn event loop blockages.
  - Streaming endpoints:
    - `POST /api/v1/stream-pcap?speed=0.0`: Chunked upload handling, Server-Sent Events (SSE) streaming progress (`progress`), alerts (`alert`), errors (`error`), and completion (`complete`).
    - `POST /api/v1/analyze-pcap`: Bounded JSON response with telemetry metrics and capped alert arrays (up to 500 alerts), preventing unbounded memory bloat.
- **Frontend Integration (`frontend/app/pcap/page.tsx`)**:
  - Live progress display: packets processed, bytes processed, flows processed, alerts emitted, elapsed time, flows/sec, Mbps throughput, and measured P50/P95 latencies.
  - Live alert feed updated in real-time as SSE alerts arrive.
  - Labeled clearly as "PCAP Replay".

---

## 7. Existing "Continuous Monitoring" Functionality

- The backend architecture operates purely asynchronously and non-blockingly.
- **Flow Preservation**: All observed flows (both normal benign flows and suspicious threat flows) are ingested, evaluated, and stored in `_mem_flows` (`deque(maxlen=2000)`).
- Detection of a threat in flow $N$ does **NOT** stop, drop, or impede flow $N+1$.
- No blocking sockets, iptables commands, or connection drops exist in the codebase.
- In the frontend, `frontend/app/flows/page.tsx` already displays all flows from `GET /api/v1/flows`, but the main dashboard and live monitor currently highlight threats without a dedicated side-by-side "Continuous Operations" card demonstrating ongoing benign flow monitoring alongside detected threats.

---

## 8. Audit of UI Elements & Existing Pages

| Page Route | Purpose | Existing Components | Gaps / Required Additions |
|---|---|---|---|
| `/` (Overview) | SOC Executive Dashboard | Quick Burst Launcher, 4 KPI cards, 6-min trend chart, threat distribution pie, live threat table, Network Topology, HealthPanel. | Add dedicated "Continuous Operations" parallel flow card; add Correlated Attack Stories preview linking to incidents. |
| `/monitor` | Live SOC Telemetry | 4 KPI cards, rolling window risk trend, live alerts table, source provenance tags (`PCAP Replay`, `Demo Simulation`, `Live Ingest`). | Add Parallel Traffic Stream (Benign $\leftrightarrow$ Threat coexistence view) and clear Passive Operations badge. |
| `/threats` | Threat Feed & Filters | Severity filter chips (`ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), searchable alert table, click-to-drawer. | Integrate correlated incident grouping filter/switch so analysts can view alerts grouped by Correlated Attack Story. |
| `/flows` | Full Flow Explorer | 5-tuple flow table (benign + malicious), feature inspector drawer. | Already lists all flows. Ensure clear distinction between normal monitored flows and threat flows. |
| `/detection` | Detection Engine Explainer | 3 Pillar cards (DiodeThreatNet, IsolationForest, Heuristics), consensus weights, implemented vs future. | Update with the 6 official PS threat categories distinguishing Implemented vs Validated baseline. |
| `/analytics` | Statistical Telemetry | Historical metrics, model confidence distribution, confusion matrix reference. | Keep as-is. |
| `/pcap` | PCAP Analysis & Replay | Drag & drop uploader, mode selector (Streaming SSE vs Offline), telemetry HUD, live results table. | Stable and operational. Ensure source tagging is maintained. |
| `/demo` | Demo Lab | Interactive parameter slider flow generator, attack scenario launchers. | Operational. Ensure synthetic labels are visible. |
| Shared `AlertDrawer` | Forensic Investigation | Header with source & one-way tag, risk bar, 3-pillar breakdown, contributing detectors, flow metadata, structured evidence, explanation. | Retitle to **"Why did GeoGuards alert?"**; add explicit **Novel Behaviour** callout for Isolation Forest. |

---

## 9. Endpoints Used by Each Frontend Page

| Page | Endpoints Used |
|---|---|
| `app/page.tsx` | `GET /api/v1/stats`, `GET /api/v1/alerts`, `POST /api/v1/analyze-flow`, `GET /api/v1/health` (via `HealthPanel`) |
| `app/monitor/page.tsx` | `GET /api/v1/stats`, `GET /api/v1/alerts`, `GET /api/v1/health` |
| `app/threats/page.tsx` | `GET /api/v1/alerts` |
| `app/flows/page.tsx` | `GET /api/v1/flows` |
| `app/detection/page.tsx` | Static documentation + design system |
| `app/analytics/page.tsx` | `GET /api/v1/stats`, `GET /api/v1/alerts`, `GET /api/v1/benchmark/summary` |
| `app/pcap/page.tsx` | `POST /api/v1/stream-pcap`, `POST /api/v1/analyze-pcap` |
| `app/demo/page.tsx` | `POST /api/v1/analyze-flow`, `GET /api/v1/stats` |

---

## 10. Audit Conclusions & Plan of Action

1. **Reusability**:
   - `backend/correlation.py` already implements full cluster grouping, timelines, synergy scoring, and narrative generation. No backend rewriting needed.
   - `backend/specialized_detectors.py` already implements all 6 threat categories with structured `EvidenceItem`.
   - `backend/anomaly_detector.py` is fitted on real clean benign traffic and outputs `anomaly_score` and `is_anomaly`.
   - `backend/streaming_engine.py` is non-blocking and stable with SSE streaming.
2. **Productization Deliverables**:
   - **Feature A & B (Continuous Operations & Parallel Flow Coexistence)**: Add a real-time Continuous Operations view showing benign flows (`🟢 ACTIVE / MONITORED`) alongside threat flows (`🔴 DETECTED`) without blocking, proving that passive monitoring preserves traffic flow.
   - **Feature C & Timeline (Attack Story / Incident Correlation)**: Create a dedicated **Attack Stories** page/view (`/incidents` or within `/threats` & `/`) pulling from `/api/v1/correlation/clusters` with full attack progression, timeline, and restrained narrative.
   - **Feature D ("Why did GeoGuards alert?")**: Refactor `AlertDrawer.tsx` to prominently display "Why did GeoGuards alert?", actual measured evidence values, detector attribution, and the novel behaviour distinction.
   - **Feature E (Novel Behaviour)**: Ensure Isolation Forest flags are framed as "Traffic differs significantly from the learned benign baseline", never as confirmed attacks.
   - **Feature G (One-Way Safety Panel)**: Update `NetworkTopology.tsx` and `HealthPanel.tsx` with standard wording: "Software representation of a unidirectional architecture", Active Probing: NONE, Outbound Response: NONE.
   - **Feature H (Threat Coverage)**: Display the 6-class PS taxonomy in `app/detection/page.tsx` clearly separating Implemented from Validated baseline.
