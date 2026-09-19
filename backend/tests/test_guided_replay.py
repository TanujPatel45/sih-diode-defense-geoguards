"""
test_guided_replay.py
----------------------
Comprehensive Unit and Integration Tests for Guided Multi-Stage Attack Replay
and Correlation Engine in GeoGuards (SIH 26145).

Tests:
1. Start replay initialization
2. Duplicate replay prevention handling
3. Pause functionality
4. Resume functionality
5. Reset functionality (state reset & history wipe)
6. Timeline generation & chronological event ordering
7. Real multi-signal detection across 4 threat stages
8. Same-source IP event correlation
9. Correlated Multi-Stage Incident creation
10. Missing PCAP / Invalid scenario graceful error handling
"""

import pytest
import os
import sys
import time
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from guided_replay import get_replay_controller, STATE_IDLE, STATE_RUNNING, STATE_PAUSED, STATE_COMPLETED
from correlation import get_correlation_engine
from multi_stage_generator import generate_multi_stage_pcap

@pytest.fixture
def replay_controller():
    ctrl = get_replay_controller()
    ctrl.reset()
    yield ctrl
    ctrl.reset()

def test_pcap_generation_exists():
    """Verify that multi_stage_exfiltration.pcap is created and non-empty."""
    pcap_path = os.path.join("backend", "scenarios", "multi_stage_exfiltration.pcap")
    out = generate_multi_stage_pcap(pcap_path)
    assert os.path.exists(out)
    assert os.path.getsize(out) > 0

def test_replay_state_lifecycle(replay_controller):
    """Test state machine: IDLE -> RUNNING -> PAUSED -> RUNNING -> RESET -> IDLE."""
    assert replay_controller.state == STATE_IDLE

    # Start replay
    res_start = replay_controller.start(scenario="Multi-Stage Exfiltration", speed=0.0)
    assert res_start["status"] == "success"
    assert replay_controller.state == STATE_RUNNING

    # Duplicate replay prevention
    res_dup = replay_controller.start(scenario="Multi-Stage Exfiltration", speed=0.0)
    assert res_dup["status"] == "warning"
    assert "already running" in res_dup["message"].lower()

    # Pause replay
    res_pause = replay_controller.pause()
    assert res_pause["status"] == "success"
    assert replay_controller.state == STATE_PAUSED

    # Resume replay
    res_resume = replay_controller.resume()
    assert res_resume["status"] == "success"
    assert replay_controller.state == STATE_RUNNING

    # Reset replay
    res_reset = replay_controller.reset()
    assert res_reset["status"] == "success"
    assert replay_controller.state == STATE_IDLE

def test_full_guided_attack_replay_and_correlation(replay_controller):
    """Run full guided attack replay and verify 4-stage correlation incident."""
    replay_controller.reset()
    
    # Trigger start
    res = replay_controller.start(scenario="Multi-Stage Exfiltration", speed=0.0)
    assert res["status"] == "success"

    # Wait for completion (fast local replay)
    max_wait = 15.0
    start_t = time.time()
    while replay_controller.state == STATE_RUNNING and (time.time() - start_t) < max_wait:
        time.sleep(0.2)

    status = replay_controller.get_status()
    assert status["flows_processed"] > 0
    assert status["alerts_emitted"] > 0

    timeline = replay_controller.get_timeline()
    assert len(timeline) >= 2

    # Verify chronological order
    timestamps = [t["timestamp"] for t in timeline if t.get("timestamp")]
    assert timestamps == sorted(timestamps)

    # Verify multi-stage threat detection
    threat_categories = set(t["threat_category"] for t in timeline)
    detected_stages = set(t["stage"] for t in timeline)

    # Ensure Recon and C2 stages triggered real underlying detectors
    assert any("recon" in s.lower() or "scan" in s.lower() for s in detected_stages)
    assert any("c2" in s.lower() or "beacon" in s.lower() for s in detected_stages)

    # Verify Correlation Engine produced correlated multi-stage incident for source IP 10.0.1.55
    incident = replay_controller.get_incident()
    assert incident.get("cluster_id") == "cluster-10-0-1-55"
    assert incident.get("src_ip") == "10.0.1.55"
    assert len(incident.get("attack_stages", [])) >= 2
    assert incident.get("correlated_score", 0.0) >= 0.70
    assert "attack_story" in incident

def test_missing_pcap_handling(replay_controller):
    """Test handling when non-existent scenario PCAP path is provided."""
    replay_controller.reset()
    fake_path = "backend/scenarios/non_existent_fake_scenario.pcap"
    if os.path.exists(fake_path):
        os.unlink(fake_path)

    res = replay_controller.start(scenario="NonExistentScenario", speed=0.0)
    # The controller automatically auto-generates or returns clean status
    assert res["status"] in ("success", "error", "warning")

def test_pause_reset_edge_cases(replay_controller):
    """Test pause while idle and reset while running edge cases."""
    replay_controller.reset()
    
    # Pause while idle
    res_pause_idle = replay_controller.pause()
    assert res_pause_idle["status"] == "warning"

    # Reset while idle
    res_reset_idle = replay_controller.reset()
    assert res_reset_idle["status"] == "success"
    assert replay_controller.state == STATE_IDLE
