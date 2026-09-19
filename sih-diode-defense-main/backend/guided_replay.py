"""
guided_replay.py
----------------
Guided Multi-Stage Attack Replay & Correlation Manager for GeoGuards (SIH 26145).

Manages the guided replay state machine:
  IDLE ↔ RUNNING ↔ PAUSED ↔ COMPLETED  (Reset → IDLE)

Replays scenario PCAPs through StreamingReplaySession, feeding the detection
pipeline (ML + Anomaly + Behaviour + Specialized Detectors → Risk Fusion → Correlation).

Features:
- Prevents duplicate replay sessions
- Handles pause / resume / reset gracefully
- Preserves chronological timeline of events
- Synthesizes correlated multi-stage incident story
- Preserves 100% passive monitoring architecture
"""

import os
import sys
import time
import asyncio
import logging
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from multi_stage_generator import generate_multi_stage_pcap
from streaming_engine import StreamingReplaySession
from correlation import get_correlation_engine, map_threat_to_stage
from schemas import StandardizedAlert

log = logging.getLogger(__name__)

# State Constants
STATE_IDLE = "IDLE"
STATE_RUNNING = "RUNNING"
STATE_PAUSED = "PAUSED"
STATE_COMPLETED = "COMPLETED"

SCENARIO_NAME = "Multi-Stage Exfiltration"
TARGET_HOST_IP = "10.0.1.55"

class GuidedReplayController:
    """
    Singleton controller managing state, control commands, and telemetry for
    guided multi-stage attack replay.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self.state = STATE_IDLE
        self.scenario_name = SCENARIO_NAME
        self.target_ip = TARGET_HOST_IP
        
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        
        self.current_stage: str = "Not Started"
        self.packets_processed: int = 0
        self.flows_processed: int = 0
        self.alerts_emitted: int = 0
        
        self.timeline_events: List[Dict[str, Any]] = []
        self._replay_task: Optional[asyncio.Task] = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set() # Unpaused by default

        self.last_error: Optional[str] = None

    def start(self, scenario: str = SCENARIO_NAME, speed: float = 0.0) -> Dict[str, Any]:
        with self._lock:
            if self.state == STATE_RUNNING:
                return {
                    "status": "warning",
                    "message": "Replay is already running.",
                    "state": self.state
                }

            if self.state == STATE_PAUSED:
                self._pause_event.set()
                self.state = STATE_RUNNING
                return {
                    "status": "success",
                    "message": "Replay resumed from paused state.",
                    "state": self.state
                }

            # Reset internal state for fresh run
            self._reset_internal_state()

            # Ensure scenario PCAP exists
            pcap_path = os.path.join("backend", "scenarios", "multi_stage_exfiltration.pcap")
            if not os.path.exists(pcap_path):
                try:
                    generate_multi_stage_pcap(pcap_path)
                except Exception as exc:
                    self.last_error = str(exc)
                    log.error("Failed to generate scenario PCAP: %s", exc)
                    return {
                        "status": "error",
                        "message": f"Failed to locate or generate scenario PCAP: {exc}",
                        "state": self.state
                    }

            self.scenario_name = scenario
            self.state = STATE_RUNNING
            self.start_time = time.time()
            self._stop_event.clear()
            self._pause_event.set()

            # Launch background worker task
            try:
                loop = asyncio.get_running_loop()
                self._replay_task = loop.create_task(self._run_guided_replay_pipeline(pcap_path, speed))
            except RuntimeError:
                # If no running event loop in current thread, run in background thread
                def _bg_runner():
                    asyncio.run(self._run_guided_replay_pipeline(pcap_path, speed))
                t = threading.Thread(target=_bg_runner, daemon=True, name="guided-replay-worker")
                t.start()

            return {
                "status": "success",
                "message": f"Started guided attack replay for scenario '{scenario}'.",
                "state": self.state,
                "pcap_path": pcap_path
            }

    def pause(self) -> Dict[str, Any]:
        with self._lock:
            if self.state == STATE_RUNNING:
                self.state = STATE_PAUSED
                self._pause_event.clear()
                return {"status": "success", "message": "Guided replay paused.", "state": self.state}
            elif self.state == STATE_PAUSED:
                return {"status": "info", "message": "Replay is already paused.", "state": self.state}
            else:
                return {"status": "warning", "message": f"Cannot pause while replay is in {self.state} state.", "state": self.state}

    def resume(self) -> Dict[str, Any]:
        with self._lock:
            if self.state == STATE_PAUSED:
                self.state = STATE_RUNNING
                self._pause_event.set()
                return {"status": "success", "message": "Guided replay resumed.", "state": self.state}
            elif self.state == STATE_RUNNING:
                return {"status": "info", "message": "Replay is already running.", "state": self.state}
            else:
                return {"status": "warning", "message": f"Cannot resume while replay is in {self.state} state.", "state": self.state}

    def reset(self) -> Dict[str, Any]:
        with self._lock:
            self._stop_event.set()
            self._pause_event.set()
            if self._replay_task and not self._replay_task.done():
                self._replay_task.cancel()
            
            self._reset_internal_state()

            # Clear correlation engine history
            corr_eng = get_correlation_engine()
            corr_eng.reset()

            self.state = STATE_IDLE
            return {
                "status": "success",
                "message": "Guided replay state and correlation history reset to IDLE.",
                "state": self.state
            }

    def _reset_internal_state(self):
        self.current_stage = "Idle"
        self.packets_processed = 0
        self.flows_processed = 0
        self.alerts_emitted = 0
        self.start_time = None
        self.end_time = None
        self.timeline_events.clear()
        self.last_error = None

    async def _run_guided_replay_pipeline(self, pcap_path: str, speed: float):
        """Executes PCAP replay through StreamingReplaySession and syncs alerts."""
        from main import _model, _scaler, _anomaly_det, _behav_eng, _fusion_eng, record_flow_alert

        session = StreamingReplaySession(
            pcap_path=pcap_path,
            replay_speed=speed,
            model=_model,
            scaler=_scaler,
            anomaly_detector=_anomaly_det,
            behaviour_engine=_behav_eng,
            fusion_engine=_fusion_eng
        )

        try:
            async for evt in session.stream_replay():
                if self._stop_event.is_set():
                    break

                # Respect pause signal
                while not self._pause_event.is_set() and not self._stop_event.is_set():
                    await asyncio.sleep(0.10)

                evt_type = evt.get("type")
                if evt_type == "progress":
                    self.packets_processed = evt.get("packets_processed", self.packets_processed)
                    self.flows_processed = evt.get("flows_processed", self.flows_processed)
                    self.alerts_emitted = evt.get("alerts_emitted", self.alerts_emitted)

                elif evt_type == "alert" and evt.get("alert"):
                    alert = evt["alert"]
                    record_flow_alert(alert)

                    self.flows_processed += 1
                    self.alerts_emitted += 1

                    # Update guided timeline
                    threat = alert.get("dominant_threat") or alert.get("threat_class") or "Benign"
                    stage = map_threat_to_stage(threat)
                    self.current_stage = stage

                    timeline_item = {
                        "timestamp": alert.get("timestamp"),
                        "alert_id": alert.get("alert_id"),
                        "stage": stage,
                        "threat_category": threat,
                        "source_ip": alert.get("source_ip") or alert.get("src_ip"),
                        "destination_ip": alert.get("destination_ip") or alert.get("dst_ip"),
                        "destination_port": alert.get("destination_port") or alert.get("dst_port"),
                        "confidence": alert.get("confidence"),
                        "risk_score": alert.get("final_risk_score") or alert.get("risk_score"),
                        "severity": alert.get("severity"),
                        "explanation": alert.get("explanation"),
                    }
                    self.timeline_events.append(timeline_item)

                elif evt_type == "complete":
                    self.end_time = time.time()
                    self.state = STATE_COMPLETED
                    self.current_stage = "Completed — Correlated Multi-Stage Incident Generated"
                    if "telemetry" in evt and isinstance(evt["telemetry"], dict):
                        tel = evt["telemetry"]
                        self.packets_processed = tel.get("packets_processed", self.packets_processed)
                        self.flows_processed = tel.get("flows_processed", self.flows_processed)
                        self.alerts_emitted = tel.get("alerts_emitted", self.alerts_emitted)
                    log.info("Guided replay scenario '%s' completed successfully.", self.scenario_name)

                elif evt_type == "error":
                    self.last_error = evt.get("message")
                    log.error("Guided replay error: %s", self.last_error)

        except asyncio.CancelledError:
            log.info("Guided replay task cancelled.")
        except Exception as err:
            self.last_error = str(err)
            log.error("Unexpected exception during guided replay: %s", err)

    def get_status(self) -> Dict[str, Any]:
        corr_eng = get_correlation_engine()
        cluster = corr_eng.get_cluster_by_src_ip(self.target_ip)

        stages_completed = []
        if cluster:
            if hasattr(cluster, "attack_stages") and cluster.attack_stages:
                stages_completed = list(cluster.attack_stages)
            elif hasattr(cluster, "threat_categories") and cluster.threat_categories:
                stages_completed = [map_threat_to_stage(tc) for tc in cluster.threat_categories]

        return {
            "status": self.state,
            "state": self.state,
            "scenario_name": self.scenario_name,
            "target_host_ip": self.target_ip,
            "current_stage": self.current_stage,
            "stages_completed": stages_completed,
            "packets_processed": self.packets_processed,
            "flows_processed": self.flows_processed,
            "alerts_emitted": self.alerts_emitted,
            "timeline_length": len(self.timeline_events),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "last_error": self.last_error,
            "correlated_incident_active": cluster is not None,
            "cluster_id": cluster.cluster_id if cluster else None,
            "correlated_score": cluster.correlated_score if cluster else None,
            "attack_story": cluster.attack_story if cluster else None,
        }

    def get_timeline(self) -> List[Dict[str, Any]]:
        return sorted(self.timeline_events, key=lambda x: x.get("timestamp", ""))

    def get_incident(self) -> Dict[str, Any]:
        corr_eng = get_correlation_engine()
        cluster = corr_eng.get_cluster_by_src_ip(self.target_ip)
        if cluster:
            return cluster.model_dump()
        return {
            "status": "NO_INCIDENT",
            "message": f"No correlated incident cluster found for host {self.target_ip} yet.",
            "target_ip": self.target_ip
        }

_controller_instance: Optional[GuidedReplayController] = None

def get_replay_controller() -> GuidedReplayController:
    global _controller_instance
    if _controller_instance is None:
        _controller_instance = GuidedReplayController()
    return _controller_instance
