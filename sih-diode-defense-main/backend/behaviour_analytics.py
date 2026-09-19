"""
behaviour_analytics.py
-----------------------
Lightweight Behaviour Analytics Engine for passive cyber threat detection.
Uses transparent statistical heuristics — NOT a deep learning model.

Detects behavioural signatures of:
  1. C2 Beaconing         — periodic low-volume comms to rare destinations
  2. DNS Tunnelling       — high-entropy, long-query DNS exfiltration
  3. Slow/Low-and-Slow    — persistent low-rate connections

Input  : flow feature dict (derived from actual measured packets)
Output : behaviour_score (float 0-1), behaviour_type (str), evidence (list[str])

All evidence strings describe actual measured values, not assumptions.
"""

import math
from dataclasses import dataclass, field


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class BehaviourResult:
    behaviour_type  : str
    evidence        : list[str]
    behaviour_score : float = 0.0

    def as_dict(self) -> dict:
        return {
            "behaviour_score": round(self.behaviour_score, 4),
            "behaviour_type" : self.behaviour_type,
            "evidence"       : self.evidence,
        }


# ── Heuristic Thresholds (all configurable) ───────────────────────────────────

C2_THRESHOLDS = {
    "iat_mean_low"       : 0.5,    # seconds — periodic but not flood-rate
    "iat_mean_high"      : 120.0,  # seconds — max realistic beacon interval
    "iat_std_max"        : 0.5,    # low variance → highly regular
    "pkt_len_mean_max"   : 300.0,  # C2 beacons are small
    "payload_entropy_max": 6.0,    # not maximally random
    "syn_ratio_max"      : 0.1,    # established sessions
}

DNS_THRESHOLDS = {
    "payload_entropy_min": 6.5,    # high entropy payload
    "pkt_len_mean_min"   : 150.0,  # longer-than-typical DNS queries
    "iat_mean_max"       : 2.0,    # frequent queries
    "protocol_udp"       : 17,     # UDP protocol number
}

SLOW_THRESHOLDS = {
    "duration_min"       : 30.0,   # seconds — long connection
    "pkt_len_mean_max"   : 600.0,  # small packets
    "iat_mean_min"       : 0.5,    # slow inter-packet timing
}


class BehaviourAnalyticsEngine:
    """
    Statistical heuristic engine for behavioural threat detection.

    This is NOT a trained ML model. Scores and thresholds are heuristic
    approximations. All evidence is derived from actual measured features.
    """

    def analyse(self, features: dict) -> BehaviourResult:
        """
        Analyse a single flow and return a BehaviourResult.

        Parameters
        ----------
        features : dict
            Keys: iat_mean, iat_std, pkt_len_mean, pkt_len_std,
                  payload_entropy, syn_ratio, tcp_rst_ratio, tcp_fin_ratio,
                  duration, packet_count, protocol (optional)

        Returns
        -------
        BehaviourResult
        """
        results = [
            self._score_c2_beaconing(features),
            self._score_dns_tunnelling(features),
            self._score_slow_low_and_slow(features),
        ]

        # Pick highest-scoring behaviour
        best = max(results, key=lambda r: r.behaviour_score)

        # If score is negligible, label as Benign
        if best.behaviour_score < 0.15:
            best.behaviour_type = "Benign"
            best.evidence = []

        return best

    # ── C2 Beaconing ──────────────────────────────────────────────────────────

    def _score_c2_beaconing(self, f: dict) -> BehaviourResult:
        """
        C2 Beaconing signals:
        - Regular, repeated connection intervals (low IAT std)
        - Low-volume, small packets (implant keep-alive / task pull)
        - Established TCP session (low SYN ratio)
        - IAT falls within plausible beacon interval range
        """
        evidence : list[str] = []
        score_pts : float    = 0.0
        max_pts   : float    = 5.0

        iat_mean      = float(f.get("iat_mean",       0.0))
        iat_std       = float(f.get("iat_std",         0.0))
        pkt_len_mean  = float(f.get("pkt_len_mean",   0.0))
        payload_ent   = float(f.get("payload_entropy", 0.0))
        syn_ratio     = float(f.get("syn_ratio",       0.0))
        packet_count  = float(f.get("packet_count",    0.0))

        t = C2_THRESHOLDS

        # Regular interval (not too fast, not too slow)
        if t["iat_mean_low"] <= iat_mean <= t["iat_mean_high"]:
            score_pts += 1.5
            evidence.append(
                f"Mean inter-packet interval {iat_mean:.3f}s falls within beacon range "
                f"({t['iat_mean_low']}–{t['iat_mean_high']}s)"
            )

        # Low variance → very regular timing
        if iat_std < t["iat_std_max"] and iat_mean > 0:
            regularity = max(0.0, 1.0 - (iat_std / t["iat_std_max"]))
            score_pts += 1.5 * regularity
            evidence.append(
                f"Low interval variance (IAT std={iat_std:.4f}s) — highly regular timing"
            )

        # Small packet size typical of beacon keep-alives
        if 0 < pkt_len_mean <= t["pkt_len_mean_max"]:
            score_pts += 0.7
            evidence.append(
                f"Small mean packet length ({pkt_len_mean:.0f} B) — consistent with implant keep-alive"
            )

        # Established session (not SYN flood)
        if syn_ratio < t["syn_ratio_max"]:
            score_pts += 0.5
            evidence.append(
                f"Low SYN ratio ({syn_ratio:.3f}) — established persistent session"
            )

        # Moderate entropy (not encrypted noise, not plaintext)
        if 2.0 <= payload_ent <= t["payload_entropy_max"]:
            score_pts += 0.3
            evidence.append(
                f"Payload entropy {payload_ent:.2f} bits — consistent with lightweight C2 protocol"
            )

        score = min(1.0, score_pts / max_pts)
        return BehaviourResult("C2 Beaconing", evidence, score)

    # ── DNS Tunnelling ─────────────────────────────────────────────────────────

    def _score_dns_tunnelling(self, f: dict) -> BehaviourResult:
        """
        DNS Tunnelling signals:
        - High payload entropy (encoded data in DNS labels)
        - Longer-than-normal packet lengths for DNS traffic
        - Frequent query intervals
        - UDP protocol (typical DNS transport)
        """
        evidence : list[str] = []
        score_pts : float    = 0.0
        max_pts   : float    = 4.0

        payload_ent  = float(f.get("payload_entropy", 0.0))
        pkt_len_mean = float(f.get("pkt_len_mean",   0.0))
        iat_mean     = float(f.get("iat_mean",         0.0))
        protocol     = int  (f.get("protocol",         0  ))

        t = DNS_THRESHOLDS

        # High entropy payload (base64/hex encoded labels)
        if payload_ent >= t["payload_entropy_min"]:
            score_pts += 1.5
            evidence.append(
                f"High payload entropy ({payload_ent:.2f} bits ≥ {t['payload_entropy_min']}) — "
                f"suggests encoded data in DNS queries"
            )

        # Longer packets than typical DNS responses/queries
        if pkt_len_mean >= t["pkt_len_mean_min"]:
            score_pts += 1.0
            evidence.append(
                f"Mean packet length {pkt_len_mean:.0f} B ≥ {t['pkt_len_mean_min']} B — "
                f"larger than typical DNS traffic"
            )

        # Frequent queries
        if 0 < iat_mean <= t["iat_mean_max"]:
            score_pts += 1.0
            evidence.append(
                f"Query frequency: mean IAT {iat_mean:.3f}s — repeated DNS-rate queries"
            )

        # UDP protocol typical for DNS
        if protocol == t["protocol_udp"]:
            score_pts += 0.5
            evidence.append("UDP protocol — consistent with DNS transport layer")

        score = min(1.0, score_pts / max_pts)
        return BehaviourResult("DNS Tunnelling", evidence, score)

    # ── Slow / Low-and-Slow ───────────────────────────────────────────────────

    def _score_slow_low_and_slow(self, f: dict) -> BehaviourResult:
        """
        Slow/Low-and-slow signals:
        - Long connection duration
        - Low packet rate / large inter-packet intervals
        - Small to medium packet sizes
        """
        evidence : list[str] = []
        score_pts : float    = 0.0
        max_pts   : float    = 3.0

        duration     = float(f.get("duration",      0.0))
        iat_mean     = float(f.get("iat_mean",       0.0))
        pkt_len_mean = float(f.get("pkt_len_mean",   0.0))
        packet_count = float(f.get("packet_count",   0.0))

        t = SLOW_THRESHOLDS

        if duration >= t["duration_min"]:
            score_pts += 1.5
            evidence.append(
                f"Long flow duration ({duration:.1f}s ≥ {t['duration_min']}s) — "
                f"persistent low-activity connection"
            )

        if iat_mean >= t["iat_mean_min"]:
            score_pts += 1.0
            evidence.append(
                f"Slow packet rate (mean IAT {iat_mean:.3f}s) — low-and-slow transmission pattern"
            )

        if 0 < pkt_len_mean <= t["pkt_len_mean_max"] and duration > 0 and packet_count > 0:
            pps = packet_count / duration if duration > 0 else 0
            score_pts += 0.5
            evidence.append(
                f"Small packets ({pkt_len_mean:.0f} B avg) at low rate ({pps:.2f} pkt/s)"
            )

        score = min(1.0, score_pts / max_pts)
        return BehaviourResult("Slow/Low-and-Slow", evidence, score)


# ── Module-level singleton ────────────────────────────────────────────────────
_engine_instance: BehaviourAnalyticsEngine | None = None


def get_engine() -> BehaviourAnalyticsEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = BehaviourAnalyticsEngine()
    return _engine_instance


# ── Quick self-test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    eng = get_engine()

    c2_flow = {
        "iat_mean": 2.001, "iat_std": 0.0001, "pkt_len_mean": 125,
        "pkt_len_std": 5, "payload_entropy": 4.1, "syn_ratio": 0.0,
        "duration": 120, "packet_count": 60, "protocol": 6,
    }
    dns_flow = {
        "iat_mean": 0.08, "iat_std": 0.02, "pkt_len_mean": 190,
        "pkt_len_std": 35, "payload_entropy": 7.9, "syn_ratio": 0.0,
        "duration": 5, "packet_count": 60, "protocol": 17,
    }
    benign_flow = {
        "iat_mean": 0.05, "iat_std": 0.03, "pkt_len_mean": 500,
        "pkt_len_std": 80, "payload_entropy": 5.0, "syn_ratio": 0.02,
        "duration": 2, "packet_count": 40, "protocol": 6,
    }

    for name, flow in [("C2 Beacon", c2_flow), ("DNS Tunnel", dns_flow), ("Benign", benign_flow)]:
        r = eng.analyse(flow)
        print(f"\n{name}: type={r.behaviour_type}, score={r.behaviour_score:.3f}")
        for ev in r.evidence:
            print(f"  • {ev}")
