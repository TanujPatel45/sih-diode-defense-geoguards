# SIH 26145 — Implementation Report

**Prepared:** 2026-09-05
**Prototype version:** 2.0.0
**Baseline model:** DiodeThreatNet-v1.0-baseline

---

## What Was Changed

### Security & Configuration (Phase 2)

| Item | Before | After |
|------|--------|-------|
| MongoDB credentials | Hardcoded in `main.py` line 23 | Loaded from `.env` via `python-dotenv` |
| CORS origins | `allow_origins=["*"]` | Configurable via `CORS_ORIGINS` env var |
| Model/scaler paths | Hardcoded relative paths | Configurable via `MODEL_PATH`/`SCALER_PATH` |
| `.env` in git | No `.gitignore` entry | Added `.env` to `.gitignore` |

### Flow Extraction (Phase 3)

| Item | Before | After |
|------|--------|-------|
| Grouping key | Source IP only | 5-tuple: `(src_ip, dst_ip, src_port, dst_port, protocol)` |
| Flow timeout | None | 60 seconds (configurable) |
| Features extracted | 6 | 21 |
| Bidirectional tracking | No | Yes (fwd/bwd packet + byte counts) |
| TCP flags | SYN only | SYN, RST, FIN |

### Backend (Phases 4–8)

**New files created:**
- `backend/anomaly_detector.py` — Isolation Forest with synthetic benign baseline
- `backend/behaviour_analytics.py` — Statistical heuristics for C2/DNS/Slow patterns
- `backend/risk_fusion.py` — Configurable weighted fusion engine

**`backend/main.py` extended:**
- `IngestFlow` schema: 6 → 20+ fields
- Three-pillar detection pipeline per request
- `GET /api/v1/stats` — real operational counters
- `GET /api/v1/alerts/{id}` — individual alert lookup
- `inference_latency_ms` measured per request
- In-memory `deque` fallback when MongoDB unavailable
- Alert includes: `evidence[]`, `explanation`, `anomaly_score`, `behaviour_score`, `final_risk_score`, `severity`, `dominant_threat`, `model_version`

### PCAP Pipeline (Phase 13)

**`backend/pcap_analyzer.py` replaced:**
- Proper 5-tuple flow extraction
- Flow timeout expiration
- All 21 features submitted to API
- Bidirectional tracking
- CLI arguments (`--api`)

### Traffic Simulator (Phase 12)

**`backend/simulate_traffic.py` replaced:**
- Infinite random loop → deterministic CLI with `--mode`, `--count`, `--delay`
- 5 modes: `normal`, `syn_flood`, `dns_tunnel`, `c2_beacon`, `mixed`
- Submits full extended feature set
- Prints prediction + risk score per flow

### Frontend (Phases 9–11)

**`frontend/app/page.tsx` replaced:**
- All `Math.random()` calls removed
- KPI cards fetched from `/api/v1/stats`
- Threat trend chart computed from real alert timestamps
- Threat distribution pie from real alert predictions
- Alert table: Source→Dest, Protocol, Classification, Risk bar, Severity
- Alert detail modal: evidence list, explanation, all scores, flow metadata
- One-way data path card (software prototype indicator)
- Demo mode panel (calls backend API directly, no separate process needed)

**`frontend/app/layout.tsx`:** Updated title/description for SIH 26145
**`frontend/app/globals.css`:** Dark design system, animations, severity colours

### Requirements (Phase 16)

`requirements.txt` updated from 3 packages (`streamlit`, `pandas`, `numpy`) to full backend dependency list including FastAPI, PyTorch, scikit-learn, Scapy, Motor, pydantic, python-dotenv.

### Documentation

- `README.md` — architecture, setup, run commands, API reference, limitations
- `REPORT.md` — this file
- `backend/evaluate.py` — evaluation scaffolding

---

## What Is Currently Implemented

### ✅ Working

- FastAPI backend with startup validation of model + scaler
- Three-pillar detection per flow:
  1. DiodeThreatNet supervised classifier (PyTorch, 4 classes)
  2. Isolation Forest anomaly detector (scikit-learn)
  3. Statistical behaviour analytics (heuristic, transparent)
- Risk fusion with configurable weights
- Explainable alerts with evidence list and plain-language explanation
- In-memory storage fallback (MongoDB optional)
- Real operational counters (`/api/v1/stats`)
- 5-tuple flow extraction from PCAP
- Deterministic demo simulator (5 modes, CLI)
- Next.js dashboard with real data only
- Alert detail modal
- One-way data path visualization (software indicator)
- Demo mode panel in dashboard

### ⚠️ Prototype-Level (functional but approximate)

- Isolation Forest fitted on synthetic benign baseline (not real traffic)
- Behaviour analytics thresholds are heuristic starting points
- Risk fusion weights are default values (0.50/0.25/0.25), not tuned
- Severity bands are illustrative defaults

---

## What Remains Future Work

1. **Model retraining** on a properly labeled dataset (e.g., CICIDS, custom capture)
2. **Real benign baseline** for Isolation Forest fitting
3. **Threshold tuning** for behaviour analytics (requires labeled data)
4. **Expanded attack taxonomy** (more threat classes)
5. **Performance benchmarking** at realistic packet rates
6. **PCAP→DPDK/AF_XDP integration** for high-speed capture
7. **Alert correlation** across multiple flows (campaign detection)
8. **Historical alert storage and search** in MongoDB
9. **Anomaly score calibration** against real traffic distributions
10. **Authentication** for the dashboard API in production deployments

---

## Demo Commands

```bash
# 1. Start backend
cd backend
uvicorn main:app --reload

# 2. Start frontend
cd frontend
npm run dev
# Open http://localhost:3000

# 3. Run mixed demo scenario (CLI)
cd backend
python simulate_traffic.py --mode mixed --count 20

# 4. Analyse PCAP
cd backend
python pcap_analyzer.py traffic_sample.pcap

# 5. Check API health
curl http://127.0.0.1:8000/api/v1/health

# 6. View stats
curl http://127.0.0.1:8000/api/v1/stats

# 7. View alerts
curl http://127.0.0.1:8000/api/v1/alerts
```

---

## Verification Checklist

| Test | Expected Result |
|------|----------------|
| `uvicorn main:app` | Starts without error; model + scaler loaded |
| `curl /api/v1/health` | `{"status":"ok","model_loaded":true,...}` |
| `python simulate_traffic.py --mode mixed --count 5` | 5 flows submitted, predictions printed |
| `python pcap_analyzer.py traffic_sample.pcap` | Flows extracted + submitted |
| `curl /api/v1/stats` | Real counter values (not zeros after simulation) |
| `curl /api/v1/alerts` | Alert list with `evidence` and `explanation` fields |
| Dashboard loads | Real KPI values, no "N/A" after simulation |
| Alert row click | Modal shows evidence + explanation |
| No `.env` in git | `git status` does not show `.env` |
| No credentials in source | `grep -r "mongodb+srv" backend/` returns nothing |
