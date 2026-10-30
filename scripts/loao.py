"""Leave-one-attack-out: retrain A1 without one attack class, see whether A1 / fusion still catch it.

A2 is reused as-is: it is fitted on BENIGN only, so it never saw the held-out class anyway.
"""
import argparse
import json
import sys
import time
from pathlib import Path

# scripts/inspect.py shadows stdlib `inspect`; drop scripts/ from path before numpy/pandas import it
_here = Path(__file__).resolve().parent
sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != _here]
sys.path.insert(0, str(_here.parent))

import pandas as pd

from src.agents.anomaly import AnomalyAgent
from src.agents.threat import ThreatDetector
from src.config import A2_MODEL, BENIGN, CLASSES, EVAL_CLEAN, LABEL_COL, OUTPUTS_DIR, TRAIN_CLEAN
from src.pipeline import run


def loao(holdout: str) -> dict:
    train = pd.read_parquet(TRAIN_CLEAN)
    train = train.loc[train[LABEL_COL] != holdout]
    t = time.time()
    a1 = ThreatDetector().fit(train)
    fit_s = time.time() - t

    ev = pd.read_parquet(EVAL_CLEAN)
    r = run(ev, a1, AnomalyAgent.load(A2_MODEL), shap=False)
    held = r[LABEL_COL] == holdout
    h = r[held]
    res = {
        "holdout": holdout,
        "n_holdout_eval": int(held.sum()),
        "a1_fit_seconds": round(fit_s, 1),
        # A1 can never name the unseen class; "detected" = called any attack (not BENIGN)
        "a1_detect_rate": round(float((h["a1_class"] != BENIGN).mean()), 6),
        "fused_detect_rate": round(float((h["final_class"] != BENIGN).mean()), 6),
        "fused_block_or_review_rate": round(float(h["policy"].isin(["BLOCK", "REVIEW"]).mean()), 6),
        "a2_flag_rate": round(float(h["a2_anomalous"].mean()), 6),
        "a1_predicted_as": h["a1_class"].value_counts().to_dict(),
        "fused_predicted_as": h["final_class"].value_counts().to_dict(),
        "status_counts": h["status"].value_counts().to_dict(),
        "benign_false_block_rate": round(float((r.loc[r[LABEL_COL] == BENIGN, "policy"] == "BLOCK").mean()), 6),
    }
    (OUTPUTS_DIR / f"loao_{holdout}.json").write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2))
    return res


if __name__ == "__main__":
    attacks = [c for c in CLASSES if c != BENIGN]
    ap = argparse.ArgumentParser()
    ap.add_argument("--holdout", choices=attacks + ["ALL"], default="PORT_SCAN")
    args = ap.parse_args()
    for cls in attacks if args.holdout == "ALL" else [args.holdout]:
        loao(cls)
