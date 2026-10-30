"""A2 Anomaly Agent: IsolationForest fitted on BENIGN rows only. Never sees attack labels."""
import argparse
import json
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

from src.agents.base import Agent
from src.config import (A2_BASELINE, A2_MODEL, BENIGN, EVAL_CLEAN, ID_COL, LABEL_COL, PREP_STATS,
                        RANDOM_STATE, TRAIN_CLEAN)

THRESHOLD_PCT = 97


class AnomalyAgent(Agent):
    name = "a2"

    def __init__(self, features: list[str] | None = None, threshold_pct: float = THRESHOLD_PCT):
        self.features = features or json.loads(PREP_STATS.read_text())["features"]
        self.threshold_pct = threshold_pct
        self.model = IsolationForest(n_estimators=100, n_jobs=-1, random_state=RANDOM_STATE)

    def fit(self, benign: pd.DataFrame) -> "AnomalyAgent":
        """benign: BENIGN rows only, feature columns only. Caller filters; no labels enter here."""
        x = benign[self.features]
        self.model.fit(x)
        self.median = x.median().to_numpy(np.float32)
        iqr = (x.quantile(0.75) - x.quantile(0.25)).to_numpy(np.float32)
        self.iqr = np.where(iqr > 0, iqr, 1).astype(np.float32)
        self.threshold = float(np.percentile(self.score(benign), self.threshold_pct))
        return self

    def score(self, df: pd.DataFrame) -> np.ndarray:
        # -score_samples is the IsolationForest anomaly score s(x) in (0, 1]; higher = more anomalous
        return (-self.model.score_samples(df[self.features])).astype(np.float32)

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        s = self.score(df)
        z = (df[self.features].to_numpy(np.float32) - self.median) / self.iqr
        top = np.argsort(-np.abs(z), axis=1)[:, :3]
        evidence = [[[self.features[j], round(float(row[j]), 3)] for j in t] for row, t in zip(z, top)]
        return pd.DataFrame({
            ID_COL: df[ID_COL].to_numpy(),
            "a2_score": s,
            "a2_anomalous": s > self.threshold,
            "a2_evidence": evidence,
        })

    def baseline(self) -> dict:
        return {"threshold_pct": self.threshold_pct, "threshold": self.threshold,
                "features": self.features,
                "benign_median": self.median.tolist(), "benign_iqr": self.iqr.tolist()}


def train() -> AnomalyAgent:
    train_df = pd.read_parquet(TRAIN_CLEAN)
    benign = train_df.loc[train_df[LABEL_COL] == BENIGN].drop(columns=[LABEL_COL])
    t = time.time()
    a2 = AnomalyAgent().fit(benign)
    print(f"fit on {len(benign)} BENIGN rows in {time.time() - t:.0f}s, threshold={a2.threshold:.4f}")
    a2.save(A2_MODEL)
    A2_BASELINE.write_text(json.dumps(a2.baseline(), indent=2))

    # labels used here for reporting only, after fitting
    ev = pd.read_parquet(EVAL_CLEAN)
    out = a2.predict(ev)
    y_attack = (ev[LABEL_COL] != BENIGN).to_numpy()
    print(f"eval ROC-AUC attack vs benign: {roc_auc_score(y_attack, out['a2_score']):.4f}")
    print("flag rate per class:", out["a2_anomalous"].groupby(ev[LABEL_COL].to_numpy()).mean().round(4).to_dict())
    return a2


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true")
    args = ap.parse_args()
    if args.train:
        train()
