"""Policy agent (stub): stateful per-source-IP replay policy on top of A3's per-flow verdicts.

Flows are replayed in `seq` order (row order if absent). Each source IP collects a strike for every
BLOCK verdict; once it reaches STRIKES within its last WINDOW flows, the IP is blocklisted and every
later flow from it is blocked, even ones A3 would ALLOW. Without endpoint metadata (train/eval),
the per-flow A3 policy passes through unchanged.
"""
import argparse
from collections import defaultdict, deque

import numpy as np
import pandas as pd

from src.agents.base import Agent
from src.config import EVAL_RESULTS, ID_COL, POLICY_RESULTS

STRIKES = 3
WINDOW = 20
IP_COL, SEQ_COL = "source_ip", "seq"


class PolicyAgent(Agent):
    name = "policy"

    def __init__(self, strikes: int = STRIKES, window: int = WINDOW):
        self.strikes, self.window = strikes, window

    def fit(self, df: pd.DataFrame) -> "PolicyAgent":
        return self  # rule-based; state lives only inside one replay

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """df: pipeline results (record_id, policy, optional source_ip / seq). Output keeps input order."""
        policy = df["policy"].to_numpy()
        if IP_COL not in df:
            return pd.DataFrame({ID_COL: df[ID_COL].to_numpy(), "replay_action": policy,
                                 "replay_reason": "per-flow (no endpoint metadata)", "ip_strikes": 0})

        order = np.argsort(df[SEQ_COL].to_numpy(), kind="stable") if SEQ_COL in df else np.arange(len(df))
        ips = df[IP_COL].to_numpy()
        recent: dict[str, deque] = defaultdict(lambda: deque(maxlen=self.window))
        blocked: set[str] = set()
        action = policy.copy()
        reason = np.full(len(df), "per-flow", dtype=object)
        strikes = np.zeros(len(df), dtype=np.int32)

        for i in order:
            ip = ips[i]
            if ip in blocked:
                if policy[i] != "BLOCK":
                    action[i], reason[i] = "BLOCK", "IP blocklisted"
                else:
                    reason[i] = "per-flow (IP blocklisted)"
            recent[ip].append(policy[i] == "BLOCK")
            strikes[i] = sum(recent[ip])
            if ip not in blocked and strikes[i] >= self.strikes:
                blocked.add(ip)
                reason[i] = f"per-flow; IP blocklisted ({strikes[i]} blocks in last {self.window})"

        self.blocklist_ = sorted(blocked)
        return pd.DataFrame({ID_COL: df[ID_COL].to_numpy(), "replay_action": action,
                             "replay_reason": reason, "ip_strikes": strikes})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(EVAL_RESULTS))
    ap.add_argument("--demo-ips", type=int, default=0,
                    help="eval has no IPs: assign N synthetic source IPs (hash of record_id) to exercise the replay")
    args = ap.parse_args()

    df = pd.read_parquet(args.results)
    if args.demo_ips and IP_COL not in df:
        h = pd.util.hash_pandas_object(df[ID_COL], index=False).to_numpy() % args.demo_ips
        df[IP_COL] = [f"10.0.{k // 256}.{k % 256}" for k in h]
        df[SEQ_COL] = np.arange(len(df))
    agent = PolicyAgent()
    out = agent.predict(df)
    out.to_parquet(POLICY_RESULTS, index=False)
    changed = (out["replay_action"] != df["policy"]).sum()
    print(f"{len(out)} flows, {len(getattr(agent, 'blocklist_', []))} IPs blocklisted, "
          f"{changed} flows escalated to BLOCK -> {POLICY_RESULTS}")
    print(out["replay_action"].value_counts().to_dict())


if __name__ == "__main__":
    main()
