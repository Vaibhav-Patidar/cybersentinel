"""A3 Evidence Fusion: rule table over A1 + A2 outputs. Fixed thresholds (Day 1, no tuning)."""
import numpy as np
import pandas as pd

from src.agents.base import Agent
from src.config import BENIGN, ID_COL

CONF_T = 0.8   # A1 hi-conf cut
TOP2_T = 0.3   # ANOMALY_ONLY: switch to A1's top-2 attack class if its prob exceeds this


class EvidenceFusion(Agent):
    name = "a3"

    def __init__(self, conf_t: float = CONF_T, top2_t: float = TOP2_T):
        self.conf_t, self.top2_t = conf_t, top2_t

    def fit(self, df: pd.DataFrame) -> "EvidenceFusion":
        return self  # rule-based; thresholds fixed

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """df: merged A1 + A2 outputs (a1_*, a2_* columns) keyed by record_id."""
        cls, top2 = df["a1_class"].to_numpy(), df["a1_top2"].to_numpy()
        conf, top2_p = df["a1_conf"].to_numpy(), df["a1_top2_prob"].to_numpy()
        anom = df["a2_anomalous"].to_numpy(bool)
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
            for st, c, cf, an, sc, ft, fc, po in zip(status, cls, conf, anom, df["a2_score"].to_numpy(),
                                                     a2_top, final, policy)
        ]
        return pd.DataFrame({
            ID_COL: df[ID_COL].to_numpy(),
            "final_class": final,
            "status": status,
            "evidence_strength": strength,
            "policy": policy,
            "rationale": rationale,
        })
