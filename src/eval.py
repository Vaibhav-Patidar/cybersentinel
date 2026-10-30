"""Metrics for A1 alone vs fused, on all eval rows and on eval rows unseen in train."""
import argparse
import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score

from src.config import (BENIGN, CLASSES, CONFUSION_A1_PNG, CONFUSION_FUSED_PNG, EVAL_CLEAN, EVAL_RESULTS, ID_COL,
                        LABEL_COL, METRICS, PIPELINE_STATS, PREP_STATS, TRAIN_CLEAN)


def scores(y: np.ndarray, pred: np.ndarray) -> dict:
    p, r, f, _ = precision_recall_fscore_support(y, pred, labels=CLASSES, average=None, zero_division=0)
    per = lambda v: {c: round(float(x), 6) for c, x in zip(CLASSES, v)}
    return {"accuracy": round(accuracy_score(y, pred), 6),
            "macro_precision": round(float(p.mean()), 6),
            "macro_recall": round(float(r.mean()), 6),
            "macro_f1": round(float(f.mean()), 6),
            "per_class_precision": per(p),
            "per_class_recall": per(r),
            "per_class_f1": per(f)}


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
        "override_accuracy": round(float((fused[over] == y[over]).mean()), 6) if over.any() else None,
        "override_broke_correct_a1": int((over & (a1 == y)).sum()),
    }


def plot_confusion(y: np.ndarray, pred: np.ndarray, title: str, path) -> list[list[int]]:
    cm = confusion_matrix(y, pred, labels=CLASSES)
    norm = cm / np.maximum(cm.sum(1, keepdims=True), 1)
    fig, ax = plt.subplots(figsize=(6.5, 5.5))
    ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
    for i, j in np.ndindex(cm.shape):
        ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", fontsize=9,
                color="white" if norm[i, j] > 0.5 else "black")
    ax.set_xticks(range(len(CLASSES)), CLASSES, rotation=30, ha="right")
    ax.set_yticks(range(len(CLASSES)), CLASSES)
    ax.set_xlabel("predicted")
    ax.set_ylabel("true")
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return cm.tolist()


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
        "confusion": {
            "labels": CLASSES,
            "a1": plot_confusion(r[LABEL_COL], r["a1_class"], "A1 alone", CONFUSION_A1_PNG),
            "fused": plot_confusion(r[LABEL_COL], r["final_class"], "Fused (A3)", CONFUSION_FUSED_PNG),
        },
        "status_counts": r["status"].value_counts().to_dict(),
        "evidence_strength_counts": r["evidence_strength"].value_counts().to_dict(),
        "policy_counts": r["policy"].value_counts().to_dict(),
        "status_by_class": pd.crosstab(r[LABEL_COL], r["status"]).to_dict(orient="index"),
        "evidence_strength_by_class": pd.crosstab(r[LABEL_COL], r["evidence_strength"]).to_dict(orient="index"),
        "a2": {"roc_auc_attack_vs_benign": round(float(roc_auc_score(y_attack, r["a2_score"])), 6),
               "flag_rate_per_class": {k: round(float(v), 6) for k, v in
                                       r["a2_anomalous"].groupby(r[LABEL_COL]).mean().items()}},
    }
    if PIPELINE_STATS.exists():
        metrics["throughput"] = json.loads(PIPELINE_STATS.read_text())
    with open(args.out, "w") as f:
        json.dump(metrics, f, indent=2)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
