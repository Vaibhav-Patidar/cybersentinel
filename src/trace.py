"""Per-record evidence trace for one source IP: A1/A2 -> A3 -> A4 -> A5 -> replay action.

  python -m src.trace                      # 172.16.0.1 -> outputs/trace/trace_172.16.0.1.{md,json}
  python -m src.trace --ip 192.168.10.3
"""
import argparse
import json

import pandas as pd

from src.config import ID_COL, POLICY_LOG, REPLAY_TRACE, TRACE_DIR


def _ev(v) -> list:
    return json.loads(v) if isinstance(v, str) and v else []


def record_line(r) -> dict:
    a2_top = ", ".join(f"{f} z={z:.1f}" for f, z in _ev(r["a2_evidence"])[:2])
    a4 = json.loads(r["a4_evidence"]) if r["a4_evidence"] else {}
    return {
        "seq": int(r["seq"]), ID_COL: r[ID_COL], "dst": f'{r["destination_ip"]}:{r["destination_port"]}',
        "A1": f'{r["a1_class"]} {r["a1_conf"]:.3f}', "A2": f'{r["a2_score"]:.3f}' + (" ⚑" if r["a2_anomalous"] else ""),
        "A2 top": a2_top, "A3": f'{r["final_class"]} · {r["status"]} · {r["policy"]}',
        "A4": f'{r["a4_group_id"]} n={a4.get("count", 0)}' if r["action"] == "ALLOW" else "skipped",
        "A5": r["a5_policy_id"] or ("skipped" if r["action"] == "BLOCK" else "-"),
        "action": r["action"] + (f' ({r["active_policy_id"]})' if r["active_policy_id"] else ""),
    }


def build(ip: str) -> tuple[str, dict]:
    t = pd.read_parquet(REPLAY_TRACE)
    g = t[t["source_ip"] == ip].sort_values("seq")
    if g.empty:
        raise SystemExit(f"no records for {ip}")
    log = [e for e in json.loads(POLICY_LOG.read_text())["events"] if e["scope_value"] == ip]
    lines = [record_line(r) for _, r in g.iterrows()]
    summary = {"ip": ip, "records": len(g), "actions": g["action"].value_counts().to_dict(),
               "predicted_class": g["final_class"].value_counts().to_dict(),
               "blocked_by_class": g.loc[g["action"] == "BLOCK", "final_class"].value_counts().to_dict(),
               "policy_events": log, "records_trace": lines}

    md = [f"# Evidence trace: {ip}", "",
          f"{len(g)} records · " + " · ".join(f"{k} {v}" for k, v in summary["actions"].items()) +
          " · classes " + ", ".join(f"{k} {v}" for k, v in summary["predicted_class"].items()), "",
          "## Policy timeline", ""]
    for e in log:
        if e["event"] == "ACTIVATE":
            md.append(f'- **{e["policy_id"]} ACTIVATE** after {e["record_id"]} (seq {e["seq"]}), covers seq '
                      f'{e["seq"] + 1}–{e["expires_seq"]} (through {e["expires_after_record_id"]}). '
                      f'Trigger: {e["reason"]}. Evidence: {e["evidence"]["status"]}, a2 {e["evidence"]["a2_score"]}, '
                      f'A4 {e["evidence"]["a4_group_id"]} count {e["evidence"]["count"]}.')
        else:
            md.append(f'- **{e["policy_id"]} EXPIRE** after {e["record_id"]} (seq {e["seq"]}); IP needs a new trigger.')
    for _, r in g[g["a5_triggered"]].iterrows():
        md += ["", f'## Trigger {r["a5_policy_id"]}: {r[ID_COL]} (seq {int(r["seq"])})', "",
               f'1. **A1 Threat:** {r["a1_class"]} conf {r["a1_conf"]:.3f} (top-2 {r["a1_top2"]} {r["a1_top2_prob"]:.3f})',
               f'2. **A2 Anomaly:** score {r["a2_score"]:.3f}, anomalous={bool(r["a2_anomalous"])}, top '
               + (", ".join(f"{f} z={z:.1f}" for f, z in _ev(r["a2_evidence"])) or "-"),
               f'3. **A3 Fusion:** {r["rationale"]}',
               f'4. **A4 Correlation:** group {r["a4_group_id"] or "-"}, members {", ".join(json.loads(r["a4_member_record_ids"])) or "-"}',
               f'5. **A5 Defense:** {r["a5_reason"]} → {r["a5_policy_id"]} SOURCE_IP {ip}',
               f'6. **Replay:** {r["action"]} (the triggering flow is allowed; the policy applies from the next seq)']
    cols = list(lines[0])
    md += ["", "## Every record", "", "| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    md += ["| " + " | ".join(str(l[c]) for c in cols) + " |" for l in lines]
    return "\n".join(md) + "\n", summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="172.16.0.1")
    ip = ap.parse_args().ip
    md, summary = build(ip)
    TRACE_DIR.mkdir(parents=True, exist_ok=True)
    (TRACE_DIR / f"trace_{ip}.md").write_text(md)
    (TRACE_DIR / f"trace_{ip}.json").write_text(json.dumps(summary, indent=2, default=str))
    print("\n".join(md.splitlines()[:40]))
    print(f"... -> {TRACE_DIR / f'trace_{ip}.md'}")


if __name__ == "__main__":
    main()
