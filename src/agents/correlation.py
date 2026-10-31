"""A4 Temporal Correlation: per source_ip, groups suspicious ALLOWed flows within the last W seq positions.

Past only: state is fed one record at a time in seq order, so a group never contains a later record.
Suspicious = final_class != BENIGN. A burst keeps its group_id while its window stays non-empty;
once the window empties, the IP's next suspicious flow opens a new group.
"""
import argparse
from collections import Counter, defaultdict, deque

import numpy as np
import pandas as pd

from src.agents.base import Agent
from src.config import A4_WINDOW, BENIGN, HIDDEN_RESULTS, ID_COL

IP_COL, SEQ_COL = "source_ip", "seq"


class CorrelationAgent(Agent):
    name = "a4_correlation"

    def __init__(self, window: int = A4_WINDOW):
        self.window = window
        self.reset()

    def reset(self) -> None:
        self.members: dict[str, deque] = defaultdict(deque)  # ip -> (seq, record_id, class, a1_conf, a2_score)
        self.group: dict[str, str] = {}
        self.n_groups = 0

    def fit(self, df: pd.DataFrame) -> "CorrelationAgent":
        return self  # rule-based; state lives only inside one replay

    def _expire(self, ip: str, seq: int) -> None:
        q = self.members[ip]
        while q and q[0][0] <= seq - self.window:
            q.popleft()
        if not q:
            self.group.pop(ip, None)

    def step(self, row) -> dict:
        """Observe one ALLOWed record (seq order) and return its A4 output."""
        ip, seq = row[IP_COL], int(row[SEQ_COL])
        self._expire(ip, seq)
        q = self.members[ip]
        assert not q or q[-1][0] < seq, f"seq order violated for {ip}: {q[-1][0]} >= {seq}"
        if row["final_class"] != BENIGN:
            if ip not in self.group:
                self.n_groups += 1
                self.group[ip] = f"G{self.n_groups:03d}"
            q.append((seq, row[ID_COL], row["final_class"], float(row["a1_conf"]), float(row["a2_score"])))
        assert all(m[0] <= seq for m in q), "A4 group contains a future record"
        return {
            ID_COL: row[ID_COL],
            "a4_group_id": self.group.get(ip, ""),
            "a4_member_record_ids": [m[1] for m in q],
            "a4_evidence": {
                "count": len(q),
                "classes": dict(Counter(m[2] for m in q)),
                "mean_a1_conf": round(float(np.mean([m[3] for m in q])), 4) if q else 0.0,
                "max_a2_score": round(float(max(m[4] for m in q)), 4) if q else 0.0,
            },
        }

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standalone run treating every record as ALLOWed (replay calls step() on ALLOWed records only)."""
        self.reset()
        order = np.argsort(df[SEQ_COL].to_numpy(), kind="stable")
        out = [None] * len(df)
        for i in order:
            out[i] = self.step(df.iloc[i])
        return pd.DataFrame(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(HIDDEN_RESULTS))
    df = pd.read_parquet(ap.parse_args().results)
    out = CorrelationAgent().predict(df)
    counts = out["a4_evidence"].map(lambda e: e["count"])
    print(f"{len(out)} rows, {out['a4_group_id'].replace('', np.nan).nunique()} groups, max count {counts.max()}")
    print(out.assign(ip=df[IP_COL], count=counts).groupby("ip")["count"].max().to_dict())


if __name__ == "__main__":
    main()
