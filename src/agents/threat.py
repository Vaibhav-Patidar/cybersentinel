"""A1 Threat Detector: LightGBM multiclass on the prep feature list."""
import argparse
import json
import time

import lightgbm as lgb
import numpy as np
import pandas as pd

from src.agents.base import Agent
from src.config import A1_MODEL, CLASSES, ID_COL, LABEL_COL, PREP_STATS, RANDOM_STATE, TRAIN_CLEAN

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

    def _y(self, df: pd.DataFrame) -> np.ndarray:
        return df[LABEL_COL].map({c: i for i, c in enumerate(CLASSES)}).to_numpy()

    def fit(self, df: pd.DataFrame) -> "ThreatDetector":
        self.model.fit(df[self.features], self._y(df))
        return self

    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        return self.model.predict_proba(df[self.features])

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        p = self.predict_proba(df)
        return pd.DataFrame({ID_COL: df[ID_COL].to_numpy(),
                             "a1_class": np.array(CLASSES)[p.argmax(1)]})


def train() -> ThreatDetector:
    df = pd.read_parquet(TRAIN_CLEAN)
    t = time.time()
    a1 = ThreatDetector().fit(df)
    print(f"trained on {len(df)} rows, {len(a1.features)} features in {time.time() - t:.0f}s")
    return a1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true")
    args = ap.parse_args()
    if args.train:
        train()
