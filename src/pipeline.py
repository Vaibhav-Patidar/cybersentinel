"""Clean parquet in -> A1 + A2 -> A3 -> results parquet. Row order and extra columns preserved."""
import argparse
import json
import time
from pathlib import Path

import pandas as pd

from src.agents.anomaly import AnomalyAgent
from src.agents.fusion import EvidenceFusion
from src.agents.threat import ThreatDetector
from src.config import A1_MODEL, A2_MODEL, EVAL_CLEAN, EVAL_RESULTS, ID_COL, LABEL_COL, PIPELINE_STATS
from src.prep import PASSTHROUGH

LIST_COLS = ["a1_shap", "a2_evidence"]  # mixed [str, float] pairs -> JSON strings in parquet


def run(df: pd.DataFrame, a1: ThreatDetector, a2: AnomalyAgent, shap: bool = True) -> pd.DataFrame:
    r1 = a1.predict(df, shap=shap)
    r2 = a2.predict(df)
    merged = pd.concat([r1, r2.drop(columns=[ID_COL])], axis=1)
    r3 = EvidenceFusion.from_config().predict(merged)
    keep = [c for c in df.columns if c in (ID_COL, *PASSTHROUGH, LABEL_COL)]
    return pd.concat([df[keep].reset_index(drop=True), merged.drop(columns=[ID_COL]),
                      r3.drop(columns=[ID_COL])], axis=1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(EVAL_CLEAN))
    ap.add_argument("--out", default=str(EVAL_RESULTS))
    ap.add_argument("--no-shap", action="store_true", help="a1_shap = []")
    args = ap.parse_args()

    a1, a2 = ThreatDetector.load(A1_MODEL), AnomalyAgent.load(A2_MODEL)
    df = pd.read_parquet(args.input)
    t = time.time()
    out = run(df, a1, a2, shap=not args.no_shap)
    dt = time.time() - t
    assert len(out) == len(df) and (out[ID_COL].to_numpy() == df[ID_COL].to_numpy()).all()

    for c in LIST_COLS:
        out[c] = out[c].map(json.dumps)
    out.to_parquet(args.out, index=False)
    stats_path = PIPELINE_STATS if args.out == str(EVAL_RESULTS) else Path(args.out).with_suffix(".stats.json")
    stats_path.write_text(json.dumps({
        "input": args.input, "rows": len(out), "seconds": round(dt, 3),
        "flows_per_sec": round(len(out) / dt, 1), "shap": not args.no_shap}, indent=2))
    print(f"{len(out)} rows in {dt:.1f}s ({len(out) / dt:,.0f} flows/s) -> {args.out}")
    print(out["status"].value_counts().to_dict())


if __name__ == "__main__":
    main()
