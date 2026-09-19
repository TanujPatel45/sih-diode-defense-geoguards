"""
streaming_engine.py
--------------------
Streaming PCAP Replay Engine for GeoGuards (SIH 26145).

Mandatory Requirement: Incremental processing, NOT batch.
Processes packets and flow-windows incrementally, extracts 5-tuple flows,
performs multi-signal threat detection on-the-fly, fuses risk,
and emits alerts in real-time as flows complete.

Supports:
- Standard PCAP (.pcap)
- Next-Gen PCAP (.pcapng)
- Live telemetry streaming with non-blocking event-loop cooperative yielding
- Bounded memory footprint (flows flushed as they expire)

=== STABILITY FIX NOTES (SIH-26145) ===
Root cause 1: O(N²) stale-flow scan
    The previous code ran:
        stale_keys = [k for k, v in active_flows.items()
                      if (pkt_time - v["last_seen"]) > self.flow_timeout_sec]
    for EVERY packet. For a PCAP with tens of thousands of packets and
    thousands of concurrent flows, this is O(flows × packets) dict
    iterations on the main async event loop — causing CPU exhaustion that
    starves the uvicorn server and makes /health requests appear to hang.

    FIX: Use a min-heap (heapq) keyed on (expiry_time, flow_key). Flow
    expiry times are updated lazily; only process flows that are actually
    expired without scanning all active flows.

Root cause 2: Unbounded latencies_ms list
    The previous code appended one float per flow to self.latencies_ms.
    For 20k+ flows, np.percentile() on this list every get_metrics() call
    is O(N log N) and grows RAM linearly.

    FIX: Track running Welford-style variance for mean/std. For P95,
    maintain a capped rolling reservoir (1000 samples) instead of the full
    list.

Root cause 3: Silent exception swallowing
    The previous sse_event_generator() only logged str(err), discarding
    the traceback. Crash causes were invisible.

    FIX: Always log full traceback on exception.

Root cause 4: Malformed packet handling
    A malformed Scapy packet could raise an arbitrary exception mid-loop,
    terminating the generator and disconnecting the SSE stream without a
    proper error event.

    FIX: Per-packet try/except with skipped-packet counter and logging.

Root cause 5: Bounded flow state
    High-cardinality attack traffic (e.g., SYN floods) can produce
    unbounded growth of active_flows, causing OOM.

    FIX: Configurable MAX_ACTIVE_FLOWS. When exceeded, oldest (by
    first-seen) flows are evicted and processed immediately. Evictions
    are counted in telemetry.
"""

import os
import time
import math
import uuid
import heapq
import logging
import asyncio
import threading
import traceback
import numpy as np
from typing import Dict, Any, List, Optional, AsyncGenerator, Tuple
from collections import defaultdict
from datetime import datetime, timezone

from schemas import EvidenceItem
from specialized_detectors import get_specialized_registry
from correlation import get_correlation_engine
from anomaly_detector import get_detector
from behaviour_analytics import get_engine as get_behaviour_engine
from risk_fusion import get_fusion_engine

log = logging.getLogger(__name__)

# ── Configuration Constants ────────────────────────────────────────────────────
MAX_ACTIVE_FLOWS          = 8_000   # Evict oldest flows above this limit
COOPERATIVE_YIELD_EVERY   = 50      # packets — how often to yield event loop
PROGRESS_EMIT_INTERVAL_S  = 0.30   # seconds between progress SSE events
LATENCY_RESERVOIR_SIZE    = 1_000  # max samples for P95 tracking


class _WelfordStats:
    """Online one-pass mean/variance computation (Welford's algorithm)."""
    __slots__ = ("n", "mean", "_M2")

    def __init__(self):
        self.n   = 0
        self.mean = 0.0
        self._M2  = 0.0

    def update(self, x: float):
        self.n += 1
        delta  = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self._M2 += delta * delta2

    @property
    def variance(self) -> float:
        return (self._M2 / (self.n - 1)) if self.n >= 2 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)


class StreamingReplaySession:
    def __init__(
        self,
        pcap_path: str,
        replay_speed: float = 0.0,   # 0.0 = max throughput, 1.0 = real-time
        flow_timeout_sec: float = 15.0,
        model=None,
        scaler=None,
        anomaly_detector=None,
        behaviour_engine=None,
        fusion_engine=None,
        class_names=None,
        max_active_flows: int = MAX_ACTIVE_FLOWS,
    ):
        self.pcap_path         = pcap_path
        self.replay_speed      = replay_speed
        self.flow_timeout_sec  = flow_timeout_sec
        self.model             = model
        self.scaler            = scaler
        self.anomaly_detector  = anomaly_detector or get_detector()
        self.behaviour_engine  = behaviour_engine or get_behaviour_engine()
        self.fusion_engine     = fusion_engine or get_fusion_engine()
        self.class_names       = class_names or ["Benign", "SYN/UDP Flood", "DNS Tunneling", "C2 Beaconing"]
        self.max_active_flows  = max_active_flows

        # Detection engines — use global singletons (read-only during inference)
        self.specialized_registry = get_specialized_registry()
        self.correlation_engine   = get_correlation_engine()

        # ── Telemetry counters ────────────────────────────────────────────────
        self.start_time        = 0.0
        self.end_time          = 0.0
        self.packets_processed = 0
        self.bytes_processed   = 0
        self.flows_processed   = 0
        self.alerts_emitted    = 0
        self.packets_skipped   = 0    # malformed / parse errors
        self.flows_evicted     = 0    # forced evictions due to flow-table cap
        self.is_running        = False

        # Rolling latency stats (avoids unbounded list growth)
        self._latency_stats    = _WelfordStats()
        self._latency_reservoir: List[float] = []   # capped at LATENCY_RESERVOIR_SIZE

    # ── Telemetry ──────────────────────────────────────────────────────────────

    def get_metrics(self) -> Dict[str, Any]:
        elapsed = max(0.0001, (self.end_time if self.end_time > 0 else time.perf_counter()) - self.start_time)
        fps  = round(self.flows_processed / elapsed, 2)
        mbps = round((self.bytes_processed * 8.0) / (elapsed * 1_000_000.0), 3)

        avg_lat = round(self._latency_stats.mean, 3) if self._latency_stats.n > 0 else 0.0
        if self._latency_reservoir:
            sorted_res = sorted(self._latency_reservoir)
            n = len(sorted_res)
            p50_lat = round(sorted_res[int(n * 0.50)], 3)
            p95_lat = round(sorted_res[int(n * 0.95)], 3)
        else:
            p50_lat = p95_lat = 0.0

        return {
            "status"                    : "COMPLETED" if self.end_time > 0 else ("RUNNING" if self.is_running else "IDLE"),
            "packets_processed"         : self.packets_processed,
            "packets_skipped"           : self.packets_skipped,
            "bytes_processed"           : self.bytes_processed,
            "flows_processed"           : self.flows_processed,
            "flows_evicted"             : self.flows_evicted,
            "alerts_emitted"            : self.alerts_emitted,
            "elapsed_time_sec"          : round(elapsed, 3),
            "flows_per_second"          : fps,
            "throughput_mbps"           : mbps,
            "avg_inference_latency_ms"  : avg_lat,
            "p50_inference_latency_ms"  : p50_lat,
            "p95_inference_latency_ms"  : p95_lat,
        }

    # ── Background Worker & Streaming Generator ────────────────────────────────

    def _run_replay_worker(
        self,
        queue: asyncio.Queue,
        loop: asyncio.AbstractEventLoop,
        stop_event: threading.Event,
    ) -> None:
        """
        Runs entirely in a background worker thread.
        Performs synchronous Scapy packet reading, flow tracking with min-heap expiry,
        and detection pipeline evaluation.
        Emits events to the asyncio.Queue via loop.call_soon_threadsafe so the main
        async event loop is NEVER blocked and remains responsive to HTTP traffic.
        """
        def emit(evt: Dict[str, Any]):
            # Natural backpressure: if queue has more than 500 unconsumed items,
            # pause reading packets to keep memory bounded on slow network clients
            while queue.qsize() > 500 and not stop_event.is_set():
                time.sleep(0.01)
            if stop_event.is_set():
                return
            loop.call_soon_threadsafe(queue.put_nowait, evt)

        try:
            from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS
        except ImportError:
            log.error("Scapy is required for PCAP streaming replay.")
            emit({"type": "error", "message": "Scapy library not available for packet parsing."})
            loop.call_soon_threadsafe(queue.put_nowait, None)
            return

        self.is_running = True
        self.start_time = time.perf_counter()

        # Flow state: key → flow_dict
        active_flows: Dict[tuple, Dict[str, Any]] = {}
        # Min-heap for efficient expiry: (expiry_wall_time, flow_key)
        expiry_heap: List[Tuple[float, tuple]] = []
        # Per-key expiry times (authoritative)
        flow_expiry: Dict[tuple, float] = {}

        last_pkt_time      = 0.0
        last_progress_time = time.perf_counter()

        pcap_reader = None
        is_pcapng   = self.pcap_path.lower().endswith((".pcapng", ".ntar"))
        try:
            if is_pcapng:
                try:
                    from scapy.all import PcapNgReader
                    pcap_reader = PcapNgReader(self.pcap_path)
                    log.info("Opened PcapNgReader for %s", self.pcap_path)
                except Exception as ng_err:
                    log.warning("PcapNgReader failed (%s); falling back to PcapReader", ng_err)
                    pcap_reader = PcapReader(self.pcap_path)
            else:
                pcap_reader = PcapReader(self.pcap_path)
                log.info("Opened PcapReader for %s", self.pcap_path)
        except Exception as open_err:
            tb = traceback.format_exc()
            log.error("Failed to open PCAP reader for %s:\n%s", self.pcap_path, tb)
            self.is_running = False
            emit({"type": "error", "message": f"Failed to open PCAP reader: {open_err}", "traceback": tb})
            loop.call_soon_threadsafe(queue.put_nowait, None)
            return

        # Initial progress event
        emit({
            "type": "progress",
            "packets_processed" : 0,
            "bytes_processed"   : 0,
            "flows_processed"   : 0,
            "alerts_emitted"    : 0,
            "elapsed_time_sec"  : 0.0,
        })

        try:
            for pkt in pcap_reader:
                if stop_event.is_set():
                    log.info("PCAP replay worker received stop signal.")
                    break

                try:
                    self.packets_processed += 1
                    pkt_len = len(pkt)
                    self.bytes_processed += pkt_len
                except Exception as pkt_err:
                    self.packets_skipped += 1
                    log.debug("Skipping malformed packet #%d: %s", self.packets_processed, pkt_err)
                    continue

                now_t = time.perf_counter()
                if (now_t - last_progress_time) > PROGRESS_EMIT_INTERVAL_S:
                    last_progress_time = now_t
                    emit({
                        "type"              : "progress",
                        "packets_processed" : self.packets_processed,
                        "bytes_processed"   : self.bytes_processed,
                        "flows_processed"   : self.flows_processed,
                        "alerts_emitted"    : self.alerts_emitted,
                        "elapsed_time_sec"  : round(now_t - self.start_time, 3),
                    })

                try:
                    if IP in pkt:
                        ip    = pkt[IP]
                        proto = getattr(ip, "proto", 6)
                    elif IPv6 in pkt:
                        ip    = pkt[IPv6]
                        proto = getattr(ip, "nh", getattr(ip, "proto", 6))
                    else:
                        continue
                    src_ip, dst_ip = ip.src, ip.dst
                except Exception:
                    self.packets_skipped += 1
                    continue

                try:
                    sport = dport = 0
                    is_syn = is_rst = is_fin = 0
                    payload_b  = b""
                    dns_qname  = None

                    if TCP in pkt:
                        sport, dport = pkt[TCP].sport, pkt[TCP].dport
                        flags = pkt[TCP].flags
                        if flags & 0x02: is_syn = 1
                        if flags & 0x04: is_rst = 1
                        if flags & 0x01: is_fin = 1
                        raw = bytes(pkt[TCP].payload) if hasattr(pkt[TCP], "payload") else b""
                        payload_b = raw if raw else b""
                    elif UDP in pkt:
                        sport, dport = pkt[UDP].sport, pkt[UDP].dport
                        raw = bytes(pkt[UDP].payload) if hasattr(pkt[UDP], "payload") else b""
                        payload_b = raw if raw else b""

                    if DNS in pkt and pkt[DNS].qd:
                        try:
                            dns_qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                        except Exception:
                            pass

                    pkt_time = float(pkt.time)
                except Exception:
                    self.packets_skipped += 1
                    continue

                if self.replay_speed > 0 and last_pkt_time > 0:
                    dt = (pkt_time - last_pkt_time) / self.replay_speed
                    if 0 < dt < 0.05:
                        time.sleep(dt)
                last_pkt_time = pkt_time

                fwd_key = (src_ip, dst_ip, sport, dport, proto)
                rev_key = (dst_ip, src_ip, dport, sport, proto)

                if rev_key in active_flows:
                    key    = rev_key
                    is_fwd = False
                else:
                    key    = fwd_key
                    is_fwd = True

                if key not in active_flows:
                    if len(active_flows) >= self.max_active_flows:
                        evicted = self._evict_oldest_flow(active_flows, flow_expiry, expiry_heap)
                        if evicted:
                            alert = self._process_single_flow(evicted)
                            if alert:
                                emit({"type": "alert", "alert": alert})
                        self.flows_evicted += 1

                    active_flows[key] = {
                        "times"     : [],
                        "lengths"   : [],
                        "payloads"  : b"",
                        "syn_count" : 0,
                        "rst_count" : 0,
                        "fin_count" : 0,
                        "fwd_pkts"  : 0,
                        "bwd_pkts"  : 0,
                        "fwd_bytes" : 0,
                        "bwd_bytes" : 0,
                        "src_ip"    : src_ip if is_fwd else dst_ip,
                        "dst_ip"    : dst_ip if is_fwd else src_ip,
                        "src_port"  : sport  if is_fwd else dport,
                        "dst_port"  : dport  if is_fwd else sport,
                        "protocol"  : proto,
                        "first_seen": pkt_time,
                        "last_seen" : pkt_time,
                        "dns_query" : dns_qname,
                    }

                fl = active_flows[key]
                fl["times"].append(pkt_time)
                fl["lengths"].append(pkt_len)
                fl["last_seen"] = pkt_time

                if is_fwd:
                    fl["fwd_pkts"]  += 1
                    fl["fwd_bytes"] += pkt_len
                else:
                    fl["bwd_pkts"]  += 1
                    fl["bwd_bytes"] += pkt_len

                if is_syn: fl["syn_count"] += 1
                if is_rst: fl["rst_count"] += 1
                if is_fin: fl["fin_count"] += 1
                if len(fl["payloads"]) < 2048 and payload_b:
                    fl["payloads"] += payload_b[:256]
                if dns_qname and not fl["dns_query"]:
                    fl["dns_query"] = dns_qname

                new_expiry = pkt_time + self.flow_timeout_sec
                flow_expiry[key] = new_expiry
                heapq.heappush(expiry_heap, (new_expiry, key))

                while expiry_heap and expiry_heap[0][0] <= pkt_time:
                    if stop_event.is_set():
                        break
                    exp_time, exp_key = heapq.heappop(expiry_heap)
                    if exp_key not in active_flows:
                        continue
                    if flow_expiry.get(exp_key, 0) > exp_time:
                        continue

                    expired_fl = active_flows.pop(exp_key)
                    flow_expiry.pop(exp_key, None)
                    alert = self._process_single_flow(expired_fl)
                    if alert:
                        emit({"type": "alert", "alert": alert})

            # Flush remaining active flows
            if not stop_event.is_set():
                log.info("PCAP scan complete. Flushing %d remaining active flows.", len(active_flows))
                for fl in list(active_flows.values()):
                    if stop_event.is_set():
                        break
                    alert = self._process_single_flow(fl)
                    if alert:
                        emit({"type": "alert", "alert": alert})

                self.end_time = time.perf_counter()
                final_metrics = self.get_metrics()
                emit({
                    "type"     : "complete",
                    "telemetry": final_metrics,
                    "message"  : (
                        f"Successfully replayed PCAP "
                        f"({self.packets_processed} pkts, "
                        f"{self.flows_processed} flows, "
                        f"{self.alerts_emitted} alerts emitted"
                        f"{', ' + str(self.packets_skipped) + ' skipped' if self.packets_skipped else ''}"
                        f"{', ' + str(self.flows_evicted) + ' evictions' if self.flows_evicted else ''}"
                        f")."
                    ),
                })
        except Exception as loop_err:
            tb = traceback.format_exc()
            log.error("FATAL error in PCAP replay worker loop:\n%s", tb)
            emit({
                "type"              : "error",
                "message"           : f"Replay worker error at packet {self.packets_processed}: {loop_err}",
                "traceback"         : tb,
                "packets_processed" : self.packets_processed,
                "flows_processed"   : self.flows_processed,
                "alerts_emitted"    : self.alerts_emitted,
            })
        finally:
            if pcap_reader is not None:
                try:
                    pcap_reader.close()
                    log.info("PcapReader closed for %s", self.pcap_path)
                except Exception as close_err:
                    log.warning("PcapReader.close() raised: %s", close_err)
            self.end_time = time.perf_counter()
            self.is_running = False
            try:
                if not loop.is_closed():
                    loop.call_soon_threadsafe(queue.put_nowait, None)
            except RuntimeError:
                pass

    async def stream_replay(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        True asynchronous generator that consumes events emitted by the background
        replay worker thread via an asyncio.Queue.
        Guarantees that the main asyncio event loop is never blocked by packet parsing
        or ML model inference, keeping HTTP /health and /stats responsive.
        """
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        loop = asyncio.get_running_loop()
        stop_event = threading.Event()

        worker_thread = threading.Thread(
            target=self._run_replay_worker,
            args=(queue, loop, stop_event),
            daemon=True,
            name=f"pcap-worker-{os.path.basename(self.pcap_path)}",
        )
        worker_thread.start()

        try:
            while True:
                evt = await queue.get()
                if evt is None:
                    break
                yield evt
        finally:
            stop_event.set()

    # ── Evict oldest flow when table is full ───────────────────────────────────

    def _evict_oldest_flow(
        self,
        active_flows: Dict[tuple, Dict],
        flow_expiry: Dict[tuple, float],
        expiry_heap: list,
    ) -> Optional[Dict[str, Any]]:
        """
        Evict the flow with the smallest first_seen timestamp.
        Uses a simple linear scan (called rarely — only when at cap).
        """
        oldest_key = None
        oldest_time = float("inf")
        for k, fl in active_flows.items():
            fs = fl.get("first_seen", float("inf"))
            if fs < oldest_time:
                oldest_time = fs
                oldest_key  = k

        if oldest_key is None:
            return None

        evicted_fl = active_flows.pop(oldest_key)
        flow_expiry.pop(oldest_key, None)
        log.debug("Evicted oldest flow %s (first_seen=%.3f)", oldest_key, oldest_time)
        return evicted_fl

    # ── Single-flow detection pipeline ────────────────────────────────────────

    def _process_single_flow(self, fl: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Run the full detection pipeline for one completed flow.
        Returns a standardized alert dict, or None if the flow has < 2 packets.
        All exceptions are caught and logged; returns None on failure.
        """
        n_pkts = len(fl.get("times", []))
        if n_pkts < 2:
            return None

        try:
            return self._run_pipeline(fl, n_pkts)
        except Exception as pipe_err:
            tb = traceback.format_exc()
            log.error(
                "Detection pipeline error for flow %s:%s->%s:%s[%s]:\n%s",
                fl.get("src_ip"), fl.get("src_port"),
                fl.get("dst_ip"), fl.get("dst_port"),
                fl.get("protocol"),
                tb,
            )
            return None   # Do NOT crash the stream; skip this flow

    def _run_pipeline(self, fl: Dict[str, Any], n_pkts: int) -> Optional[Dict[str, Any]]:
        t0 = time.perf_counter()
        self.flows_processed += 1

        times   = np.array(fl["times"],   dtype=np.float64)
        lengths = np.array(fl["lengths"], dtype=np.float32)
        iats    = np.diff(times)
        dur     = float(times[-1] - times[0])
        tot_bytes = int(np.sum(lengths))

        iat_m = float(np.mean(iats))   if len(iats) > 0 else 0.0
        iat_s = float(np.std(iats))    if len(iats) > 0 else 0.0
        pkt_m = float(np.mean(lengths))
        pkt_s = float(np.std(lengths)) if len(lengths) > 1 else 0.0

        # Payload entropy
        counts = defaultdict(int)
        for b in fl["payloads"]:
            counts[b] += 1
        plen    = len(fl["payloads"])
        entropy = float(
            -sum((c / plen) * math.log2(c / plen) for c in counts.values())
        ) if plen > 0 else 0.0

        syn_r = float(fl["syn_count"] / n_pkts)
        rst_r = float(fl["rst_count"] / n_pkts)
        fin_r = float(fl["fin_count"] / n_pkts)

        flow_dict = {
            "source_ip"       : fl["src_ip"],
            "destination_ip"  : fl["dst_ip"],
            "source_port"     : fl["src_port"],
            "destination_port": fl["dst_port"],
            "protocol"        : fl["protocol"],
            "iat_mean"        : iat_m,
            "iat_std"         : iat_s,
            "pkt_len_mean"    : pkt_m,
            "pkt_len_std"     : pkt_s,
            "payload_entropy" : entropy,
            "syn_ratio"       : syn_r,
            "tcp_rst_ratio"   : rst_r,
            "tcp_fin_ratio"   : fin_r,
            "duration"        : dur,
            "packet_count"    : n_pkts,
            "byte_count"      : tot_bytes,
            "forward_bytes"   : fl["fwd_bytes"],
            "backward_bytes"  : fl["bwd_bytes"],
            "forward_pkts"    : fl["fwd_pkts"],
            "backward_pkts"   : fl["bwd_pkts"],
            "dns_query"       : fl.get("dns_query"),
        }

        # 1. Supervised Model inference
        prediction = "Benign"
        confidence = 0.50
        if self.model and self.scaler:
            import torch
            v1_raw    = np.array([[iat_m, iat_s, pkt_m, pkt_s, entropy, syn_r]], dtype=np.float32)
            v1_scaled = self.scaler.transform(v1_raw)
            with torch.no_grad():
                logits = self.model(torch.tensor(v1_scaled, dtype=torch.float32))
                probs  = torch.softmax(logits, dim=1).numpy()[0]
                pidx   = int(np.argmax(probs))
                confidence = float(probs[pidx])
                prediction = self.class_names[pidx]

        # 2. Anomaly Detection
        ano_score = 0.0
        is_ano    = False
        if self.anomaly_detector:
            ano_res   = self.anomaly_detector.score(flow_dict)
            ano_score = ano_res["anomaly_score"]
            is_ano    = ano_res["is_anomaly"]

        # 3. Behaviour Analytics
        behav_score = 0.0
        behav_type  = "Benign"
        behav_ev    = []
        if self.behaviour_engine:
            b_res       = self.behaviour_engine.analyse(flow_dict)
            behav_score = b_res.behaviour_score
            behav_type  = b_res.behaviour_type
            behav_ev    = b_res.evidence

        # 4. Specialized Detectors
        spec_results  = self.specialized_registry.evaluate_all(flow_dict)
        spec_evidence = []
        spec_max_score = 0.0
        for s in spec_results:
            if s.is_detected:
                spec_evidence.extend(s.evidence)
                if s.score > spec_max_score:
                    spec_max_score = s.score

        # 5. Risk Fusion
        fusion = self.fusion_engine.fuse(
            supervised_prediction = prediction,
            supervised_confidence = confidence,
            anomaly_score         = ano_score,
            behaviour_score       = behav_score,
            behaviour_type        = behav_type,
            behaviour_evidence    = behav_ev,
            spec_score            = spec_max_score,
        )

        t1     = time.perf_counter()
        lat_ms = (t1 - t0) * 1000.0

        # Update latency stats without growing an unbounded list
        self._latency_stats.update(lat_ms)
        # Rolling reservoir for percentile tracking (capped size)
        if len(self._latency_reservoir) < LATENCY_RESERVOIR_SIZE:
            self._latency_reservoir.append(lat_ms)
        else:
            # Replace a pseudo-random slot (cheap approximation)
            idx = self.flows_processed % LATENCY_RESERVOIR_SIZE
            self._latency_reservoir[idx] = lat_ms

        # 6. Build Standardized Alert
        alert_id  = str(uuid.uuid4())
        flow_id   = (
            f"{fl['src_ip']}:{fl['src_port']}"
            f"->{fl['dst_ip']}:{fl['dst_port']}"
            f"[{fl['protocol']}]"
        )

        evidence_items = []
        for item in spec_evidence:
            evidence_items.append({
                "feature"       : item.feature,
                "observed_value": item.observed_value,
                "interpretation": item.interpretation,
            })
        for ev_str in fusion.evidence:
            evidence_items.append({
                "feature"       : "fusion_signal",
                "observed_value": ev_str,
                "interpretation": ev_str,
            })

        spec_detected_classes = [s.threat_category for s in spec_results if s.is_detected]
        threat_cls = fusion.dominant_threat
        if spec_detected_classes:
            threat_cls = spec_detected_classes[0]
        elif threat_cls == "Benign":
            threat_cls = prediction
        detection_sources = ["supervised_classifier"]
        if is_ano:                                       detection_sources.append("anomaly_detector")
        if behav_type != "Benign":                       detection_sources.append("behaviour_analytics")
        if any(s.is_detected for s in spec_results):    detection_sources.append("specialized_detectors")

        alert_doc = {
            "alert_id"              : alert_id,
            "timestamp"             : datetime.now(timezone.utc).isoformat(),
            "flow_id"               : flow_id,
            "src_ip"                : fl["src_ip"],
            "dst_ip"                : fl["dst_ip"],
            "src_port"              : fl["src_port"],
            "dst_port"              : fl["dst_port"],
            "protocol"              : fl["protocol"],
            "source_ip"             : fl["src_ip"],
            "destination_ip"        : fl["dst_ip"],
            "source_port"           : fl["src_port"],
            "destination_port"      : fl["dst_port"],
            "prediction"            : prediction,
            "confidence"            : round(confidence, 4),
            "threat_class"          : threat_cls,
            "dominant_threat"       : threat_cls,
            "risk_score"            : fusion.final_risk_score,
            "final_risk_score"      : fusion.final_risk_score,
            "severity"              : fusion.severity,
            "anomaly_score"         : ano_score,
            "is_anomaly"            : is_ano,
            "behaviour_score"       : behav_score,
            "behaviour_type"        : behav_type,
            "detection_sources"     : detection_sources,
            "evidence"              : evidence_items,
            "explanation"           : fusion.explanation,
            "model_version"         : "DiodeThreatNet-v1.0-baseline",
            "feature_schema_version": "v1.0-baseline",
            "analysis_mode"         : "streaming_pcap_replay",
            "one_way_safe"          : True,
            "inference_latency_ms"  : round(lat_ms, 3),
            "features"              : flow_dict,
        }

        self.alerts_emitted += 1
        return alert_doc
