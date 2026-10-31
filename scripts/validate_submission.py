"""Validate outputs/submission/*.csv against the templates and the Level 2 replay rules. Exit 1 on any failure.

Independent of the agents: reads only the raw hidden CSV, the templates and the submission files.
"""
import sys
from pathlib import Path

# scripts/inspect.py shadows stdlib `inspect`; drop scripts/ from path before numpy/pandas import it
_here = Path(__file__).resolve().parent
sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != _here]
sys.path.insert(0, str(_here.parent))

import pandas as pd  # noqa: E402

from src.config import CLASSES, HIDDEN_RAW, SUBMISSION_DIR, TEMPLATES_DIR  # noqa: E402

NAMES = ("classification", "policies", "replay")
fails: list[str] = []


def check(ok, msg: str) -> None:
    print(("PASS " if ok else "FAIL ") + msg)
    if not ok:
        fails.append(msg)


def main() -> None:
    hidden = pd.read_csv(HIDDEN_RAW, dtype={"record_id": str})
    hidden.columns = hidden.columns.str.strip()
    hidden = hidden.sort_values("seq", kind="stable")
    ids = hidden["record_id"].tolist()
    seq_of = dict(zip(ids, hidden["seq"]))
    ip_of = dict(zip(ids, hidden["source_ip"]))

    sub = {}
    for n in NAMES:
        tmpl = (TEMPLATES_DIR / f"{n}.csv").read_text().strip().splitlines()[0]
        head = (SUBMISSION_DIR / f"{n}.csv").read_text().splitlines()[0]
        check(head == tmpl, f"{n}.csv header == template ({head})")
        sub[n] = pd.read_csv(SUBMISSION_DIR / f"{n}.csv", dtype=str, keep_default_na=False)
    cls, pol, rep = sub["classification"], sub["policies"], sub["replay"]

    for n, df in (("classification", cls), ("replay", rep)):
        check(len(df) == len(ids) == 200, f"{n}: 200 rows ({len(df)})")
        check(df["record_id"].is_unique, f"{n}: record_ids unique")
        check(df["record_id"].tolist() == ids, f"{n}: record_ids match hidden, in seq order")
    check(cls["predicted_class"].isin(CLASSES).all(), "predicted_class in 5 classes")
    score = pd.to_numeric(cls["anomaly_score"], errors="coerce")
    check(score.notna().all() and score.between(0, 1).all(), "anomaly_score numeric in [0,1]")
    check((cls["evidence_status"] != "").all(), "evidence_status non-empty")

    # policies
    check(pol["policy_id"].is_unique, "policy_ids unique")
    check((pol["scope_type"] == "SOURCE_IP").all(), "scope_type == SOURCE_IP")
    check(pol["scope_value"].isin(set(hidden["source_ip"])).all(), "scope_value is a real source_ip")
    known = pol["activated_after_record_id"].isin(seq_of) & pol["expires_after_record_id"].isin(seq_of)
    check(known.all(), "policy record_ids exist in hidden")
    if not known.all():
        return
    act = pol["activated_after_record_id"].map(seq_of)
    exp = pol["expires_after_record_id"].map(seq_of)
    check((exp >= act).all(), "expires >= activated")
    overlap = [(a, b) for ip, g in pol.assign(a=act, e=exp).groupby("scope_value")
               for (_, a), (_, b) in zip(g.sort_values("a").iterrows(), g.sort_values("a").iloc[1:].iterrows())
               if b["a"] <= a["e"]]
    check(not overlap, f"never 2 active policies per IP ({len(overlap)} overlaps)")
    trig = rep.set_index("record_id").loc[pol["activated_after_record_id"], "action"]
    check((trig == "ALLOW").all(), "triggering records are ALLOWed")

    # replay
    check(rep["action"].isin({"ALLOW", "BLOCK"}).all(), "action in ALLOW|BLOCK")
    allow = rep[rep["action"] == "ALLOW"]
    check((allow["active_policy_id"] == "").all(), "ALLOW has empty active_policy_id")
    pol_by_id = pol.assign(a=act, e=exp).set_index("policy_id")
    bad_block, missed = [], []
    for _, r in rep.iterrows():
        s, ip = seq_of[r["record_id"]], ip_of[r["record_id"]]
        covering = pol_by_id[(pol_by_id["scope_value"] == ip) & (pol_by_id["a"] < s) & (s <= pol_by_id["e"])]
        if r["action"] == "BLOCK":
            pid = r["active_policy_id"]
            if pid not in covering.index:
                bad_block.append(r["record_id"])
        elif len(covering):
            missed.append(r["record_id"])
    check(not bad_block, f"every BLOCK cites a policy active at that seq for that source_ip ({bad_block[:5]})")
    check(not missed, f"no ALLOW while its source_ip has an active policy ({missed[:5]})")
    # a policy applies only strictly after its activation record
    early = [pid for pid, p in pol_by_id.iterrows()
             if ((rep["active_policy_id"] == pid) & (rep["record_id"].map(seq_of) <= p["a"])).any()]
    check(not early, f"no policy applies at or before its activation record ({early})")


if __name__ == "__main__":
    main()
    print(f"\n{'OK' if not fails else f'{len(fails)} FAILED'}")
    sys.exit(1 if fails else 0)
