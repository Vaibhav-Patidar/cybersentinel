"""Level 2 ordered replay: A1-A3 results -> A4 correlation -> A5 defense -> submission CSVs.

Strict seq order. An IP with an active policy is BLOCKed (A4/A5 skipped); otherwise the flow is
ALLOWed and A4 then A5 run, and A5 may activate a policy for later records only.
"""
import argparse
import json

import pandas as pd

from src.agents.correlation import CorrelationAgent
from src.agents.defense import DefenseAgent
from src.config import HIDDEN_RESULTS, ID_COL, POLICY_LOG, REPLAY_TRACE, SUBMISSION_DIR, TEMPLATES_DIR

CLASSIFICATION = {"record_id": ID_COL, "predicted_class": "final_class", "anomaly_score": "a2_score",
                  "evidence_status": "status"}


def template_header(name: str) -> list[str]:
    return (TEMPLATES_DIR / f"{name}.csv").read_text().strip().splitlines()[0].split(",")


def replay(df: pd.DataFrame) -> tuple[pd.DataFrame, DefenseAgent]:
    df = df.sort_values("seq", kind="stable").reset_index(drop=True)
    assert (df["seq"].to_numpy() == range(1, len(df) + 1)).all(), "seq must be 1..N"
    a4, a5 = CorrelationAgent(), DefenseAgent(df[ID_COL].tolist())
    rows = []
    for _, r in df.iterrows():
        a5.tick(r["seq"])
        p = a5.active(r["source_ip"], r["seq"])
        if p:
            rows.append({"action": "BLOCK", "active_policy_id": p["policy_id"], "a4_group_id": "",
                         "a4_member_record_ids": [], "a4_evidence": {}, "a5_triggered": False,
                         "a5_policy_id": "", "a5_reason": f"blocked by {p['policy_id']}"})
            continue
        o4 = a4.step(r)
        o5 = a5.step(r, o4)
        rows.append({"action": "ALLOW", "active_policy_id": "", **{k: v for k, v in o4.items() if k != ID_COL},
                     **{k: v for k, v in o5.items() if k != ID_COL}})
    a5.close()
    return pd.concat([df, pd.DataFrame(rows)], axis=1), a5


def write(trace: pd.DataFrame, a5: DefenseAgent) -> None:
    SUBMISSION_DIR.mkdir(parents=True, exist_ok=True)
    cls = trace[list(CLASSIFICATION.values())].set_axis(list(CLASSIFICATION), axis=1)
    pol = pd.DataFrame(a5.policies, columns=template_header("policies"))
    rep = trace[[ID_COL, "action", "active_policy_id"]]
    for name, frame in (("classification", cls), ("policies", pol), ("replay", rep)):
        assert list(frame.columns) == template_header(name), f"{name} header mismatch"
        frame.to_csv(SUBMISSION_DIR / f"{name}.csv", index=False)

    t = trace.copy()
    for c in ("a4_member_record_ids", "a4_evidence"):
        t[c] = t[c].map(json.dumps)
    t.to_parquet(REPLAY_TRACE, index=False)
    a5.save_log(POLICY_LOG)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(HIDDEN_RESULTS))
    trace, a5 = replay(pd.read_parquet(ap.parse_args().results))
    write(trace, a5)
    print(f"{len(trace)} records, {len(a5.policies)} policies -> {SUBMISSION_DIR}")
    print(trace["action"].value_counts().to_dict())


if __name__ == "__main__":
    main()
