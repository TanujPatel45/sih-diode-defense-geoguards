"""
evaluate.py
-----------
Evaluation scaffolding for the SIH 26145 NIDS prototype.

Computes classification metrics against a labeled CSV test dataset.

IMPORTANT:
  - Results are clearly labelled as BASELINE (current 6-feature model).
  - No metrics are fabricated. If no test data is available, the script
    explains how to generate or obtain a labeled dataset.
  - Inference latency is measured on the local machine and reflects
    hardware-dependent conditions.

CSV format expected:
  iat_mean, iat_std, pkt_len_mean, pkt_len_std, payload_entropy, syn_ratio,
  [optional: tcp_rst_ratio, tcp_fin_ratio, duration, packet_count],
  label  (string: "Benign", "SYN/UDP Flood", "DNS Tunneling", "C2 Beaconing")

Usage:
  python evaluate.py --data test_data.csv
  python evaluate.py --data test_data.csv --output results.txt
"""

import argparse
import os
import sys
import time
import logging
from pathlib import Path

import numpy as np
import pandas as pd

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

CLASS_NAMES = ["Benign", "SYN/UDP Flood", "DNS Tunneling", "C2 Beaconing"]
BASELINE_FEATURES = [
    "iat_mean", "iat_std", "pkt_len_mean",
    "pkt_len_std", "payload_entropy", "syn_ratio",
]

MODEL_VERSION = "DiodeThreatNet-v1.0-baseline"


def load_model_and_scaler(model_path: str, scaler_path: str):
    """Load PyTorch model and scikit-learn scaler. Raise on failure."""
    import torch
    import torch.nn as nn
    import joblib

    class DiodeThreatNet(nn.Module):
        def __init__(self, input_dim=6, num_classes=4):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(input_dim, 64),
                nn.BatchNorm1d(64),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(64, 32),
                nn.BatchNorm1d(32),
                nn.ReLU(),
                nn.Linear(32, num_classes),
            )
        def forward(self, x):
            return self.net(x)

    log.info("Loading model: %s", model_path)
    model = DiodeThreatNet()
    try:
        state = torch.load(model_path, map_location="cpu", weights_only=True)
    except Exception:
        state = torch.load(model_path, map_location="cpu")
    model.load_state_dict(state)
    model.eval()

    log.info("Loading scaler: %s", scaler_path)
    scaler = joblib.load(scaler_path)

    return model, scaler


def run_inference(model, scaler, X: np.ndarray) -> tuple[list[int], list[float], float]:
    """
    Run inference on feature matrix X.
    Returns: predictions (int list), confidences (float list), avg_latency_ms (float)
    """
    import torch

    predictions  = []
    confidences  = []
    latencies    = []

    for i in range(len(X)):
        row   = X[i:i+1]
        t0    = time.perf_counter()
        scaled = scaler.transform(row)
        tensor = torch.tensor(scaled, dtype=torch.float32)
        with torch.no_grad():
            logits = model(tensor)
            probs  = torch.softmax(logits, dim=1).numpy()[0]
        t1 = time.perf_counter()

        pred_idx = int(np.argmax(probs))
        predictions.append(pred_idx)
        confidences.append(float(probs[pred_idx]))
        latencies.append((t1 - t0) * 1000)

    avg_latency = float(np.mean(latencies)) if latencies else 0.0
    return predictions, confidences, avg_latency


def compute_metrics(y_true: list[int], y_pred: list[int], n_classes: int) -> dict:
    """
    Compute per-class and macro precision, recall, F1.
    Also compute overall accuracy and false positive rate.
    All computed from first principles to avoid scikit-learn version issues.
    """
    from sklearn.metrics import (
        classification_report,
        confusion_matrix,
        accuracy_score,
    )

    acc = accuracy_score(y_true, y_pred)
    cm  = confusion_matrix(y_true, y_pred, labels=list(range(n_classes)))
    report = classification_report(
        y_true, y_pred,
        labels      = list(range(n_classes)),
        target_names= CLASS_NAMES,
        output_dict = True,
        zero_division= 0,
    )

    # False positive rate (macro average across non-benign classes)
    fpr_list = []
    for i in range(n_classes):
        fp  = int(cm[:, i].sum()) - int(cm[i, i])
        tn  = int(cm.sum()) - int(cm[i, :].sum()) - int(cm[:, i].sum()) + int(cm[i, i])
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fpr_list.append(fpr)

    return {
        "accuracy"          : round(acc, 4),
        "macro_precision"   : round(report["macro avg"]["precision"], 4),
        "macro_recall"      : round(report["macro avg"]["recall"],    4),
        "macro_f1"          : round(report["macro avg"]["f1-score"],  4),
        "false_positive_rate_macro": round(float(np.mean(fpr_list)), 4),
        "confusion_matrix"  : cm.tolist(),
        "per_class"         : {
            name: {
                "precision": round(report[name]["precision"], 4),
                "recall"   : round(report[name]["recall"],    4),
                "f1"       : round(report[name]["f1-score"],  4),
                "support"  : report[name]["support"],
            }
            for name in CLASS_NAMES
            if name in report
        },
    }


def print_report(metrics: dict, avg_latency_ms: float, n_samples: int, output_path: str | None):
    lines = [
        "=" * 70,
        "EVALUATION REPORT — SIH 26145 NIDS Prototype",
        f"MODEL: {MODEL_VERSION}",
        f"LABEL: BASELINE (6-feature supervised classifier)",
        "=" * 70,
        f"Samples evaluated    : {n_samples}",
        f"Avg inference latency: {avg_latency_ms:.3f} ms / flow",
        "-" * 70,
        f"Accuracy             : {metrics['accuracy']:.4f}",
        f"Macro Precision      : {metrics['macro_precision']:.4f}",
        f"Macro Recall         : {metrics['macro_recall']:.4f}",
        f"Macro F1             : {metrics['macro_f1']:.4f}",
        f"Macro FPR            : {metrics['false_positive_rate_macro']:.4f}",
        "-" * 70,
        "Per-class results:",
    ]
    for cls, vals in metrics["per_class"].items():
        lines.append(
            f"  {cls:<20} P={vals['precision']:.3f}  R={vals['recall']:.3f}  "
            f"F1={vals['f1']:.3f}  support={vals['support']}"
        )
    lines += [
        "-" * 70,
        "Confusion matrix (rows=actual, cols=predicted):",
        "  Classes: " + ", ".join(CLASS_NAMES),
    ]
    for row in metrics["confusion_matrix"]:
        lines.append("  " + str(row))
    lines.append("=" * 70)

    report_text = "\n".join(lines)
    print(report_text)

    if output_path:
        Path(output_path).write_text(report_text, encoding="utf-8")
        log.info("Report saved to: %s", output_path)


def main():
    parser = argparse.ArgumentParser(
        description = "Evaluate the baseline NIDS classifier on a labeled CSV dataset."
    )
    parser.add_argument(
        "--data",
        required = True,
        help     = "Path to labeled CSV test file",
    )
    parser.add_argument(
        "--model",
        default = os.path.join(os.path.dirname(__file__), "diode_threat_model.pth"),
        help    = "Path to model .pth file",
    )
    parser.add_argument(
        "--scaler",
        default = os.path.join(os.path.dirname(__file__), "scaler.pkl"),
        help    = "Path to scaler.pkl",
    )
    parser.add_argument(
        "--output",
        default = None,
        help    = "Save report to this file path (optional)",
    )
    args = parser.parse_args()

    # Load data
    log.info("Loading test data: %s", args.data)
    try:
        df = pd.read_csv(args.data)
    except FileNotFoundError:
        log.error("CSV file not found: %s", args.data)
        print(
            "\nNo test data found. To evaluate the model, provide a labeled CSV with columns:\n"
            f"  {', '.join(BASELINE_FEATURES)}, label\n"
            "  where 'label' is one of: " + ", ".join(f'"{c}"' for c in CLASS_NAMES)
        )
        sys.exit(1)

    # Validate columns
    missing = [c for c in BASELINE_FEATURES + ["label"] if c not in df.columns]
    if missing:
        log.error("CSV is missing required columns: %s", missing)
        sys.exit(1)

    # Filter valid labels
    df = df[df["label"].isin(CLASS_NAMES)].copy()
    if df.empty:
        log.error("No rows with valid labels found. Expected: %s", CLASS_NAMES)
        sys.exit(1)

    X = df[BASELINE_FEATURES].values.astype(float)
    y_true_names = df["label"].tolist()
    y_true = [CLASS_NAMES.index(name) for name in y_true_names]

    log.info("Loaded %d samples.", len(X))

    # Load model
    model, scaler = load_model_and_scaler(args.model, args.scaler)

    # Inference
    log.info("Running inference...")
    y_pred, confidences, avg_latency = run_inference(model, scaler, X)

    # Metrics
    metrics = compute_metrics(y_true, y_pred, n_classes=len(CLASS_NAMES))

    # Report
    print_report(metrics, avg_latency, len(X), args.output)


if __name__ == "__main__":
    main()
