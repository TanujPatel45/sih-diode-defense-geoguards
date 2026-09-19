"""
risk_fusion.py
--------------
Risk Fusion Engine for passive cyber threat detection.

Combines outputs from three independent detection pillars:
  1. Supervised Classifier     — DiodeThreatNet confidence score
  2. Anomaly Detector          — Isolation Forest score
  3. Behaviour Analytics       — Statistical heuristic score

Produces a single fused risk score, severity label, and plain-language explanation.

All weights and severity thresholds are configurable.
Default weights are NOT scientifically validated — treat as starting points.
"""

from dataclasses import dataclass, field


# ── Configurable defaults ─────────────────────────────────────────────────────

DEFAULT_WEIGHTS = {
    "supervised" : 0.50,  # w1: supervised classifier (most specific signal)
    "anomaly"    : 0.25,  # w2: anomaly detector (general outlier signal)
    "behaviour"  : 0.25,  # w3: behaviour heuristics (pattern signal)
}

# Severity bands (inclusive lower bound)
DEFAULT_SEVERITY_BANDS = [
    (0.85, "CRITICAL"),
    (0.65, "HIGH"),
    (0.40, "MEDIUM"),
    (0.00, "LOW"),
]

# How to handle BENIGN prediction from supervised model
BENIGN_SUPERVISED_SCORE = 0.0   # benign → 0 supervised contribution


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class FusionResult:
    final_risk_score : float
    severity         : str
    dominant_threat  : str
    evidence         : list[str]  = field(default_factory=list)
    explanation      : str        = ""

    def as_dict(self) -> dict:
        return {
            "final_risk_score": round(self.final_risk_score, 4),
            "severity"        : self.severity,
            "dominant_threat" : self.dominant_threat,
            "evidence"        : self.evidence,
            "explanation"     : self.explanation,
        }


# ── Templates for explanation generation ─────────────────────────────────────

_EXPLANATION_TEMPLATES = {
    "SYN/UDP Flood": (
        "Traffic characteristics are consistent with a volumetric denial-of-service pattern. "
        "The observed flow exhibits a very high SYN ratio, extremely low inter-packet interval, "
        "and small uniform packet sizes, which may indicate a SYN or UDP flood attempt. "
        "Further investigation is recommended."
    ),
    "DNS Tunneling": (
        "Traffic characteristics are consistent with DNS-based data tunnelling and may warrant "
        "investigation for possible data exfiltration. The flow shows high payload entropy and "
        "above-average packet lengths for DNS traffic, suggesting encoded data may be present "
        "in DNS query labels. This is a passive metadata-based indicator only."
    ),
    "C2 Beaconing": (
        "Periodic outbound timing is consistent with beacon-like command-and-control behaviour. "
        "The flow exhibits highly regular communication intervals with low inter-packet variance "
        "and small packet sizes, which may indicate periodic check-in traffic. "
        "This is a passive indicator — intent cannot be confirmed from metadata alone."
    ),
    "Slow/Low-and-Slow": (
        "Flow characteristics are consistent with low-and-slow evasive behaviour. "
        "The connection persisted over an unusually long duration with very low packet rate, "
        "which may indicate evasive reconnaissance, slow exfiltration, or persistent keep-alive "
        "probing. Further correlation with other signals is recommended."
    ),
    "Anomaly": (
        "The flow deviates significantly from the established benign baseline across multiple "
        "statistical dimensions, which may indicate anomalous or unusual traffic. "
        "The supervised classifier was unable to confirm a specific threat family. "
        "Manual investigation is recommended."
    ),
    "Benign": (
        "No significant threat indicators detected. Traffic statistics fall within normal "
        "baselines across all detection pillars."
    ),
}


def _make_explanation(
    dominant_threat   : str,
    supervised_pred   : str,
    confidence        : float,
    anomaly_score     : float,
    behaviour_type    : str,
    behaviour_score   : float,
    final_risk_score  : float,
    severity          : str,
) -> str:
    base = _EXPLANATION_TEMPLATES.get(
        dominant_threat,
        _EXPLANATION_TEMPLATES["Anomaly"]
    )

    detail_parts = []
    if confidence > 0.5:
        detail_parts.append(
            f"Supervised classifier predicted '{supervised_pred}' with "
            f"{confidence*100:.1f}% confidence."
        )
    if anomaly_score > 0.5:
        detail_parts.append(
            f"Anomaly score {anomaly_score:.2f} indicates significant deviation from "
            f"normal traffic baseline."
        )
    if behaviour_score > 0.3 and behaviour_type not in ("Benign", ""):
        detail_parts.append(
            f"Behaviour analytics identified '{behaviour_type}' pattern "
            f"(score {behaviour_score:.2f})."
        )

    detail = " ".join(detail_parts)
    return f"{base} {detail}".strip()


# ── Risk Fusion Engine ────────────────────────────────────────────────────────

class RiskFusionEngine:
    """
    Combines signals from supervised classifier, anomaly detector, and
    behaviour analytics into a single risk assessment.

    Parameters
    ----------
    weights : dict, optional
        Keys: 'supervised', 'anomaly', 'behaviour'. Must sum to 1.0.
    severity_bands : list[tuple[float, str]], optional
        List of (lower_bound, label) tuples, sorted descending.
    """

    def __init__(
        self,
        weights        : dict | None = None,
        severity_bands : list | None = None,
    ):
        self.weights        = weights or DEFAULT_WEIGHTS.copy()
        self.severity_bands = severity_bands or DEFAULT_SEVERITY_BANDS

        # Validate weights
        total = sum(self.weights.values())
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"Fusion weights must sum to 1.0, got {total:.4f}. "
                f"Weights: {self.weights}"
            )

    def fuse(
        self,
        supervised_prediction : str,
        supervised_confidence : float,
        anomaly_score         : float,
        behaviour_score       : float,
        behaviour_type        : str,
        behaviour_evidence    : list[str],
        spec_score            : float = 0.0,
    ) -> FusionResult:
        """
        Produce a fused risk assessment.

        Parameters
        ----------
        supervised_prediction : str   CLASS_NAMES label from DiodeThreatNet
        supervised_confidence : float [0, 1]
        anomaly_score         : float [0, 1] from AnomalyDetector
        behaviour_score       : float [0, 1] from BehaviourAnalyticsEngine
        behaviour_type        : str   e.g. 'C2 Beaconing'
        behaviour_evidence    : list[str]
        spec_score            : float [0, 1] max score from Specialized Registry

        Returns
        -------
        FusionResult
        """
        # Supervised score: 0 for Benign, raw confidence for threats
        if supervised_prediction == "Benign":
            sup_score = BENIGN_SUPERVISED_SCORE
        else:
            sup_score = supervised_confidence

        # Weighted fusion
        final_risk = (
            self.weights["supervised"] * sup_score     +
            self.weights["anomaly"]    * anomaly_score +
            self.weights["behaviour"]  * behaviour_score
        )
        if spec_score > 0.0:
            final_risk = max(final_risk, spec_score)

        final_risk = round(float(min(1.0, max(0.0, final_risk))), 4)

        # Severity band
        severity = "LOW"
        for threshold, label in self.severity_bands:
            if final_risk >= threshold:
                severity = label
                break

        # Dominant threat determination
        if severity in ("LOW", "BENIGN"):
            dominant_threat = "Benign"
        else:
            dominant_threat = self._determine_dominant_threat(
                supervised_prediction, sup_score,
                behaviour_type, behaviour_score,
                anomaly_score,
            )

        # Collect evidence
        evidence = list(behaviour_evidence)
        if sup_score > 0.5:
            evidence.insert(0,
                f"Classifier: '{supervised_prediction}' at {supervised_confidence*100:.1f}% confidence"
            )
        if anomaly_score > 0.5:
            evidence.append(
                f"Anomaly detector: score {anomaly_score:.3f} above normal baseline"
            )

        explanation = _make_explanation(
            dominant_threat        = dominant_threat,
            supervised_pred        = supervised_prediction,
            confidence             = supervised_confidence,
            anomaly_score          = anomaly_score,
            behaviour_type         = behaviour_type,
            behaviour_score        = behaviour_score,
            final_risk_score       = final_risk,
            severity               = severity,
        )

        return FusionResult(
            final_risk_score = final_risk,
            severity         = severity,
            dominant_threat  = dominant_threat,
            evidence         = evidence,
            explanation      = explanation,
        )

    def _determine_dominant_threat(
        self,
        supervised_prediction : str,
        sup_score             : float,
        behaviour_type        : str,
        behaviour_score       : float,
        anomaly_score         : float,
    ) -> str:
        """
        Pick the most likely threat label from available signals.
        Priority: supervised classifier (if confident) > behaviour analytics > anomaly > benign
        """
        if sup_score >= 0.60 and supervised_prediction != "Benign":
            return supervised_prediction
        if behaviour_score >= 0.50 and behaviour_type not in ("Benign", ""):
            return behaviour_type
        if anomaly_score >= 0.70:
            return "Anomaly"
        return "Benign"


# ── Module-level singleton ────────────────────────────────────────────────────
_engine_instance: RiskFusionEngine | None = None


def get_fusion_engine() -> RiskFusionEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = RiskFusionEngine()
    return _engine_instance


# ── Quick self-test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    eng = get_fusion_engine()

    result = eng.fuse(
        supervised_prediction = "C2 Beaconing",
        supervised_confidence = 0.97,
        anomaly_score         = 0.81,
        behaviour_score       = 0.78,
        behaviour_type        = "C2 Beaconing",
        behaviour_evidence    = [
            "Mean inter-packet interval 2.001s falls within beacon range",
            "Low interval variance (IAT std=0.0001s)",
            "Small mean packet length (125 B)",
        ],
    )

    print("Risk score  :", result.final_risk_score)
    print("Severity    :", result.severity)
    print("Threat      :", result.dominant_threat)
    print("Explanation :", result.explanation)
    print("Evidence    :")
    for ev in result.evidence:
        print("  •", ev)
