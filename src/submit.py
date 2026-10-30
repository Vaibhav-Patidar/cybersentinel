"""Level 1 submission: build the API payload from metrics.json, optionally send it.

The organiser API spec (endpoint, auth, field names) is not in the data pack yet, so the payload
schema below is PROVISIONAL. Default run is a dry run: it writes the payload and sends nothing.

  python -m src.submit                       # build + print payload only
  python -m src.submit --send                # POST to $JAI_SUBMIT_URL with $JAI_API_TOKEN
"""
import argparse
import json
import os
from datetime import datetime, timezone

import requests

from src.config import CLASSES, FUSION_CONFIG, METRICS, SUBMISSION_PAYLOAD, SUBMISSION_RESPONSE

TEAM = os.environ.get("JAI_TEAM", "CyberSentinel")
TRACK = 1


def build_payload() -> dict:
    m = json.loads(METRICS.read_text())
    fused, a1 = m["all"]["fused"], m["all"]["a1"]
    fusion = json.loads(FUSION_CONFIG.read_text()) if FUSION_CONFIG.exists() else {}
    return {
        "team": TEAM,
        "track": TRACK,
        "level": 1,
        "submitted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": "CICIDS2017 eval",
        "n_flows": m["all"]["n"],
        "metrics": {
            "accuracy": fused["accuracy"],
            "macro_f1": fused["macro_f1"],
            "per_class_f1": {c: fused["per_class_f1"][c] for c in CLASSES},
            "a1_only": {"accuracy": a1["accuracy"], "macro_f1": a1["macro_f1"]},
            "unseen_in_train_macro_f1": m["unseen_in_train"]["fused"]["macro_f1"],
            "override_count": m["all"]["override_count"],
            "a2_roc_auc": m["a2"]["roc_auc_attack_vs_benign"],
            "throughput_flows_per_sec": m.get("throughput", {}).get("flows_per_sec"),
        },
        "status_counts": m["status_counts"],
        "policy_counts": m["policy_counts"],
        "fusion_thresholds": {k: fusion.get(k) for k in ("conf_t", "top2_t", "anomaly_pct")},
        "agents": ["A1 LightGBM threat detector", "A2 IsolationForest anomaly (benign-only)",
                   "A3 rule-based evidence fusion"],
    }


def send(payload: dict) -> dict:
    url, token = os.environ.get("JAI_SUBMIT_URL"), os.environ.get("JAI_API_TOKEN")
    if not url or not token:
        raise SystemExit("set JAI_SUBMIT_URL and JAI_API_TOKEN to send")
    r = requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    resp = {"status_code": r.status_code, "body": r.text[:5000],
            "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    SUBMISSION_RESPONSE.write_text(json.dumps(resp, indent=2))
    return resp


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--send", action="store_true", help="actually POST (default: dry run)")
    args = ap.parse_args()
    payload = build_payload()
    SUBMISSION_PAYLOAD.write_text(json.dumps(payload, indent=2))
    print(json.dumps(payload, indent=2))
    print(f"payload -> {SUBMISSION_PAYLOAD}")
    if args.send:
        print(json.dumps(send(payload), indent=2))


if __name__ == "__main__":
    main()
