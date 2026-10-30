"""A1 Threat Detector: LightGBM multiclass on the prep feature list."""
import argparse
import json
import time

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.model_selection import train_test_split

from src.agents.base import Agent
from src.config import A1_MODEL, CLASSES, EVAL_CLEAN, ID_COL, LABEL_COL, PREP_STATS, RANDOM_STATE, TRAIN_CLEAN

CAL_FRAC = 0.15

PARAMS = dict(
    objective="multiclass",
    n_estimators=300,
    learning_rate=0.1,
    num_leaves=63,
    class_weight="balanced",
    subsample=0.8,
    subsample_freq=1,
    colsample_bytree=0.8,
    random_state=RANDOM_STATE,
    n_jobs=-1,
    verbose=-1,
)


class ThreatDetector(Agent):
    name = "a1"

    def __init__(self, features: list[str] | None = None):
        self.features = features or json.loads(PREP_STATS.read_text())["features"]
        self.model = lgb.LGBMClassifier(**PARAMS)
        self.calibrators: list[IsotonicRegression] = []

    def _y(self, df: pd.DataFrame) -> np.ndarray:
        return df[LABEL_COL].map({c: i for i, c in enumerate(CLASSES)}).to_numpy()

    def fit(self, df: pd.DataFrame) -> "ThreatDetector":
        # hold out a stratified slice of train for one-vs-rest isotonic calibration
        y = self._y(df)
        fit_idx, cal_idx = train_test_split(np.arange(len(df)), test_size=CAL_FRAC,
                                            stratify=y, random_state=RANDOM_STATE)
        self.model.fit(df[self.features].iloc[fit_idx], y[fit_idx])
        raw = self.model.predict_proba(df[self.features].iloc[cal_idx])
        self.calibrators = [
            IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1).fit(raw[:, k], y[cal_idx] == k)
            for k in range(len(CLASSES))
        ]
        return self

    def predict_proba(self, df: pd.DataFrame, calibrated: bool = True) -> np.ndarray:
        p = self.model.predict_proba(df[self.features])
        if not calibrated or not self.calibrators:
            return p
        p = np.column_stack([c.predict(p[:, k]) for k, c in enumerate(self.calibrators)])
        s = p.sum(1, keepdims=True)
        return np.divide(p, s, out=np.full_like(p, 1 / p.shape[1]), where=s > 0)

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        p = self.predict_proba(df)
        # isotonic clips many probs to exactly 0; break ties with raw model scores
        raw = self.predict_proba(df, calibrated=False)
        order = np.argsort(-(p + 1e-9 * raw), axis=1)
        rows = np.arange(len(p))
        names = np.array(CLASSES)
        return pd.DataFrame({
            ID_COL: df[ID_COL].to_numpy(),
            "a1_class": names[order[:, 0]],
            "a1_conf": p[rows, order[:, 0]].astype(np.float32),
            "a1_top2": names[order[:, 1]],
            "a1_top2_prob": p[rows, order[:, 1]].astype(np.float32),
        })


def train() -> ThreatDetector:
    df = pd.read_parquet(TRAIN_CLEAN)
    t = time.time()
    a1 = ThreatDetector().fit(df)
    print(f"trained on {len(df)} rows, {len(a1.features)} features in {time.time() - t:.0f}s")
    ev = pd.read_parquet(EVAL_CLEAN)
    y = a1._y(ev)
    for cal in (False, True):
        p = a1.predict_proba(ev, calibrated=cal)
        conf = p.max(1)
        acc = (p.argmax(1) == y)
        # expected calibration error over 10 confidence bins
        bins = np.minimum((conf * 10).astype(int), 9)
        ece = sum(abs(acc[bins == b].mean() - conf[bins == b].mean()) * (bins == b).mean()
                  for b in range(10) if (bins == b).any())
        print(f"calibrated={cal}: ECE={ece:.4f}, acc={acc.mean():.4f}, conf<0.9: {(conf < 0.9).mean():.2%}")
    print(a1.predict(ev).head().to_string())
    return a1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true")
    args = ap.parse_args()
    if args.train:
        train()
