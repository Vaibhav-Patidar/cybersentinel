"""A3 Evidence Fusion: rule table over A1 + A2 outputs. Thresholds from fusion_config.json if tuned."""
import argparse
import itertools
import json
import time

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split

from src.agents.base import Agent
from src.config import (A1_MODEL, A2_MODEL, BENIGN, CLASSES, FUSION_CONFIG, ID_COL, LABEL_COL,
                        RANDOM_STATE, TRAIN_CLEAN)

CONF_T = 0.8   # A1 hi-conf cut
TOP2_T = 0.3   # ANOMALY_ONLY: switch to A1's top-2 attack class if its prob exceeds this

GRID = {
    "conf_t": [0.5, 0.6, 0.7, 0.8, 0.9, 0.95],
    "top2_t": [0.05, 0.1, 0.2, 0.3, 0.5],
    "anomaly_pct": [90, 95, 97, 99, 99.5],
}


class EvidenceFusion(Agent):
    name = "a3"

    def __init__(self, conf_t: float = CONF_T, top2_t: float = TOP2_T,
                 anomaly_threshold: float | None = None):
        """anomaly_threshold None -> use A2's own a2_anomalous flag."""
        self.conf_t, self.top2_t, self.anomaly_threshold = conf_t, top2_t, anomaly_threshold

    @classmethod
    def from_config(cls) -> "EvidenceFusion":
        if not FUSION_CONFIG.exists():
            return cls()
        c = json.loads(FUSION_CONFIG.read_text())
        return cls(c["conf_t"], c["top2_t"], c["anomaly_threshold"])

    def fit(self, df: pd.DataFrame) -> "EvidenceFusion":
        return self  # rule-based; thresholds come from tune()

    def anomalous(self, df: pd.DataFrame) -> np.ndarray:
        if self.anomaly_threshold is None:
            return df["a2_anomalous"].to_numpy(bool)
        return df["a2_score"].to_numpy() > self.anomaly_threshold

    def decide(self, df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Vectorised fusion table -> (status, final_class, policy)."""
        cls, top2 = df["a1_class"].to_numpy(), df["a1_top2"].to_numpy()
        conf, top2_p = df["a1_conf"].to_numpy(), df["a1_top2_prob"].to_numpy()
        anom = self.anomalous(df)
        attack, hi = cls != BENIGN, conf >= self.conf_t
        top2_attack = top2 != BENIGN

        conds = [
            attack & hi & anom,                 # CORROBORATED attack
            attack & hi & ~anom,                # CLASSIFIER_ONLY
            attack & ~hi & ~anom,               # CONFLICT
            ~attack & ~anom,                    # CORROBORATED benign
            ~attack & hi & anom,                # ANOMALY_ONLY
            ~hi & anom,                         # TIEBREAK
        ]
        switch = top2_attack & (top2_p > self.top2_t)
        status = np.select(conds, ["CORROBORATED", "CLASSIFIER_ONLY", "CONFLICT", "CORROBORATED",
                                   "ANOMALY_ONLY", "TIEBREAK"], "CONFLICT")
        final = np.select(conds, [
            cls, cls,
            cls,                                       # CONFLICT: keep A1 class, ALLOW + flag
            cls,
            np.where(switch, top2, BENIGN),            # ANOMALY_ONLY
            np.where(attack, cls, np.where(top2_attack, top2, cls)),  # TIEBREAK: lean attack
        ], cls)
        policy = np.select(conds, ["BLOCK", "BLOCK", "ALLOW", "ALLOW",
                                   np.where(switch, "BLOCK", "REVIEW"), "BLOCK"], "REVIEW")
        return status, final, policy

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """df: merged A1 + A2 outputs (a1_*, a2_* columns) keyed by record_id."""
        status, final, policy = self.decide(df)
        anom = self.anomalous(df)

        a1_feats = [{f for f, _ in ev} for ev in df["a1_shap"]]
        a2_feats = [{f for f, _ in ev} for ev in df["a2_evidence"]]
        overlap = np.array([bool(a & b) for a, b in zip(a1_feats, a2_feats)])
        strength = np.where(overlap, "STRONG",
                            np.where(status == "CORROBORATED", "MODERATE", "WEAK"))

        a2_top = [ev[0][0] if len(ev) else "-" for ev in df["a2_evidence"]]
        rationale = [
            f"{st}: A1 says {c} ({cf:.2f}), A2 {'anomalous' if an else 'normal'} "
            f"(score {sc:.3f}, top {ft}) -> {fc}, {po}"
            + (" [flag: low-confidence attack, A2 normal]" if st == "CONFLICT" else "")
            for st, c, cf, an, sc, ft, fc, po in zip(status, df["a1_class"], df["a1_conf"], anom,
                                                     df["a2_score"].to_numpy(), a2_top, final, policy)
        ]
        return pd.DataFrame({
            ID_COL: df[ID_COL].to_numpy(),
            "final_class": final,
            "status": status,
            "evidence_strength": strength,
            "policy": policy,
            "rationale": rationale,
        })


def tune() -> dict:
    """Grid-search on A1's calibration slice of train (unseen by the booster), never on eval."""
    from src.agents.anomaly import AnomalyAgent
    from src.agents.threat import CAL_FRAC, ThreatDetector

    a1, a2 = ThreatDetector.load(A1_MODEL), AnomalyAgent.load(A2_MODEL)
    train = pd.read_parquet(TRAIN_CLEAN)
    _, cal_idx = train_test_split(np.arange(len(train)), test_size=CAL_FRAC,
                                  stratify=a1._y(train), random_state=RANDOM_STATE)
    cal = train.iloc[cal_idx].reset_index(drop=True)
    benign_scores = a2.score(train.loc[train[LABEL_COL] == BENIGN])

    merged = pd.concat([a1.predict(cal, shap=False),
                        pd.DataFrame({"a2_score": a2.score(cal)})], axis=1)
    y = cal[LABEL_COL].to_numpy()
    t, results = time.time(), []
    for conf_t, top2_t, pct in itertools.product(*GRID.values()):
        thr = float(np.percentile(benign_scores, pct))
        _, final, _ = EvidenceFusion(conf_t, top2_t, thr).decide(merged)
        results.append((f1_score(y, final, labels=CLASSES, average="macro"), conf_t, top2_t, pct, thr))
    best_f1 = max(r[0] for r in results)
    # ties: prefer the defaults (0.8, 0.3, 97), then the closest config to them
    best = min((r for r in results if r[0] >= best_f1 - 1e-9),
               key=lambda r: (abs(r[1] - CONF_T), abs(r[2] - TOP2_T), abs(r[3] - 97)))
    default = next(r for r in results if (r[1], r[2], r[3]) == (CONF_T, TOP2_T, 97))
    config = {"conf_t": best[1], "top2_t": best[2], "anomaly_pct": best[3], "anomaly_threshold": best[4],
              "macro_f1_tune": round(best[0], 6), "macro_f1_default": round(default[0], 6),
              "n_configs": len(results), "n_configs_at_best": sum(r[0] >= best_f1 - 1e-9 for r in results),
              "tune_set": f"train calibration slice ({len(cal)} rows, unseen by A1 booster)"}
    FUSION_CONFIG.write_text(json.dumps(config, indent=2))
    print(f"{len(results)} configs in {time.time() - t:.0f}s")
    print(json.dumps(config, indent=2))
    return config


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--tune", action="store_true")
    args = ap.parse_args()
    if args.tune:
        tune()
