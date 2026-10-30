"""Metrics for A1 alone vs fused, on all eval rows and on eval rows unseen in train."""
import argparse
import json

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

from src.config import BENIGN, CLASSES, EVAL_CLEAN, EVAL_RESULTS, ID_COL, LABEL_COL, METRICS, PREP_STATS, TRAIN_CLEAN


def scores(y: np.ndarray, pred: np.ndarray) -> dict:
    per = f1_score(y, pred, labels=CLASSES, average=None, zero_division=0)
    return {"accuracy": round(accuracy_score(y, pred), 6),
            "macro_f1": round(f1_score(y, pred, labels=CLASSES, average="macro", zero_division=0), 6),
            "per_class_f1": {c: round(float(f), 6) for c, f in zip(CLASSES, per)}}


def block(r: pd.DataFrame) -> dict:
    y, a1, fused = r[LABEL_COL].to_numpy(), r["a1_class"].to_numpy(), r["final_class"].to_numpy()
    over = a1 != fused
    return {
        "n": int(len(r)),
        "a1": scores(y, a1),
        "fused": scores(y, fused),
        "agreement_rate": round(float((~over).mean()), 6),
        "override_count": int(over.sum()),
        "override_correct": int((over & (fused == y)).sum()),
        "override_broke_correct_a1": int((over & (a1 == y)).sum()),
    }


def unseen_mask(results: pd.DataFrame) -> np.ndarray:
    """True for eval rows whose feature vector does not appear exactly in (deduped) train."""
    feats = json.loads(PREP_STATS.read_text())["features"]
    tr = pd.read_parquet(TRAIN_CLEAN, columns=feats)
    ev = pd.read_parquet(EVAL_CLEAN, columns=[ID_COL, *feats])
    seen = set(pd.util.hash_pandas_object(tr, index=False))
    ev_seen = pd.Series(pd.util.hash_pandas_object(ev[feats], index=False).isin(seen).to_numpy(),
                        index=ev[ID_COL])
    return ~ev_seen.reindex(results[ID_COL]).fillna(False).to_numpy(bool)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(EVAL_RESULTS))
    ap.add_argument("--out", default=str(METRICS))
    args = ap.parse_args()

    r = pd.read_parquet(args.results)
    unseen = unseen_mask(r)
    y_attack = (r[LABEL_COL] != BENIGN).to_numpy()
    metrics = {
        "all": block(r),
        "unseen_in_train": block(r[unseen]),
        "status_counts": r["status"].value_counts().to_dict(),
        "evidence_strength_counts": r["evidence_strength"].value_counts().to_dict(),
        "policy_counts": r["policy"].value_counts().to_dict(),
        "a2": {"roc_auc_attack_vs_benign": round(float(roc_auc_score(y_attack, r["a2_score"])), 6),
               "flag_rate_per_class": {k: round(float(v), 6) for k, v in
                                       r["a2_anomalous"].groupby(r[LABEL_COL]).mean().items()}},
    }
    with open(args.out, "w") as f:
        json.dump(metrics, f, indent=2)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
