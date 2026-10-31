"""A5 Adaptive Defense: turns A4/A3 evidence on an ALLOWed record into a SOURCE_IP block policy for LATER records.

Trigger: IP has no active policy AND (A4 count >= k OR (final_class != BENIGN and a1_conf >= conf)).
The policy covers seq+1 .. seq+TTL (capped at last record) and is identified by record_ids.
After expiry the IP needs a fresh trigger, which creates a new policy_id. Never two active per IP.
"""
import json

import pandas as pd

from src.agents.base import Agent
from src.config import A5_CONF, A5_MIN_GROUP, A5_TTL, BENIGN, ID_COL, POLICY_LOG

SCOPE = "SOURCE_IP"


class DefenseAgent(Agent):
    name = "a5_defense"

    def __init__(self, record_ids: list[str], min_group: int = A5_MIN_GROUP, conf: float = A5_CONF,
                 ttl: int = A5_TTL):
        """record_ids: hidden ids in seq order (seq = index + 1), used only to name expiry records."""
        self.ids, self.min_group, self.conf, self.ttl = list(record_ids), min_group, conf, ttl
        self.policies: list[dict] = []
        self.active_by_ip: dict[str, dict] = {}
        self.log: list[dict] = []

    def fit(self, df: pd.DataFrame) -> "DefenseAgent":
        return self  # rule-based; state lives only inside one replay

    def tick(self, seq: int) -> None:
        """Expire policies whose last covered seq is before `seq`. Call before checking each record."""
        for ip, p in list(self.active_by_ip.items()):
            if p["expires_seq"] < seq:
                del self.active_by_ip[ip]
                self.log.append({"event": "EXPIRE", "policy_id": p["policy_id"], "scope_value": ip,
                                 "seq": p["expires_seq"], "record_id": p["expires_after_record_id"]})

    def active(self, ip: str, seq: int) -> dict | None:
        p = self.active_by_ip.get(ip)
        return p if p and p["activated_seq"] < seq <= p["expires_seq"] else None

    def step(self, row, a4: dict) -> dict:
        """Called on an ALLOWed record after A4. May activate a policy that applies from seq+1."""
        ip, seq, rid = row["source_ip"], int(row["seq"]), row[ID_COL]
        count = a4["a4_evidence"]["count"]
        attack = row["final_class"] != BENIGN
        reasons = []
        if count >= self.min_group:
            reasons.append(f"A4 group {a4['a4_group_id']} count {count} >= {self.min_group}")
        if attack and float(row["a1_conf"]) >= self.conf:
            reasons.append(f"{row['final_class']} a1_conf {float(row['a1_conf']):.3f} >= {self.conf}")
        out = {ID_COL: rid, "a5_triggered": False, "a5_policy_id": "", "a5_reason": ""}
        if ip in self.active_by_ip or not reasons:
            return out

        exp_seq = min(seq + self.ttl, len(self.ids))
        p = {"policy_id": f"P{len(self.policies) + 1:03d}", "activated_after_record_id": rid,
             "scope_type": SCOPE, "scope_value": ip, "expires_after_record_id": self.ids[exp_seq - 1],
             "activated_seq": seq, "expires_seq": exp_seq}
        self.policies.append(p)
        self.active_by_ip[ip] = p
        self.log.append({"event": "ACTIVATE", "policy_id": p["policy_id"], "scope_value": ip, "seq": seq,
                         "record_id": rid, "expires_seq": exp_seq,
                         "expires_after_record_id": p["expires_after_record_id"], "reason": "; ".join(reasons),
                         "evidence": {"final_class": row["final_class"], "status": row["status"],
                                      "a1_conf": round(float(row["a1_conf"]), 4),
                                      "a2_score": round(float(row["a2_score"]), 4),
                                      "a4_group_id": a4["a4_group_id"],
                                      "a4_member_record_ids": a4["a4_member_record_ids"], **a4["a4_evidence"]}})
        return {**out, "a5_triggered": True, "a5_policy_id": p["policy_id"], "a5_reason": "; ".join(reasons)}

    def close(self) -> None:
        """End of replay: policies still active expire at their (capped) expiry record."""
        self.tick(len(self.ids) + 1)

    def save_log(self, path=POLICY_LOG) -> None:
        path.write_text(json.dumps({"params": {"min_group": self.min_group, "conf": self.conf, "ttl": self.ttl},
                                    "events": self.log}, indent=2))

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """A5 is stateful across the replay; the ordered loop lives in src.replay."""
        from src.replay import replay
        return replay(df)[[ID_COL, "a5_triggered", "a5_policy_id", "a5_reason"]]
