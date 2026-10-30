# CyberSentinel

Multi-agent offline network intrusion detection on CICIDS2017 (JAI 2026, Track 1).
Flows are classified by independent agents, their evidence is fused, and an explainable
simulated ALLOW / BLOCK / REVIEW policy is applied. Replay only, not a live firewall.

Classes: `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, `PORT_SCAN`. Primary metric: macro-F1.

## Agents
| Agent | Model | Output |
|---|---|---|
| A1 Threat Detector | LightGBM, balanced class weights, isotonic-calibrated | class, confidence, top-2, top-3 SHAP features |
| A2 Anomaly Agent | IsolationForest trained on BENIGN only (never sees attack labels) | 0-1 score, anomalous flag, top-3 robust-z features |
| A3 Evidence Fusion | Rule table over A1 + A2 | final class, status, evidence strength, policy, rationale |

## Setup
```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```
Data goes in `data/Cyber/{training,eval}/flows.parquet` (gitignored).

## Run
```
python scripts/inspect.py            # dataset inspection
python -m src.prep                   # -> data/processed/*.parquet, models/prep_stats.json
python -m src.agents.threat --train  # A1
python -m src.agents.anomaly --train # A2
python -m src.agents.fusion --tune   # A3 thresholds
python -m src.pipeline --input data/processed/eval_clean.parquet --out outputs/eval_results.parquet
python -m src.eval --results outputs/eval_results.parquet
```
All paths live in `src/config.py`.

## Data
- Train 456,737 rows, eval 114,185 rows; `record_id` + 78 numeric flow features + `label`.
- Labels: BENIGN 52.6%, DOS 21.0%, PORT_SCAN 12.6%, DDOS 12.6%, BRUTE_FORCE 1.2%.
- No inf/NaN. 3 constant + 4 duplicate columns dropped -> 71 float32 features.
- Train deduped to 432,605 rows. Eval rows are never dropped or reordered (asserted in prep).

## Status
- [x] Phase 0 Repo setup
- [x] Phase 1 Data inspection
- [x] Phase 2 Preprocessing
- [ ] Phase 3 A1 Threat Detector (training, top-2, calibration done; SHAP in progress)
- [ ] Phase 4 A2 Anomaly Agent
- [ ] Phase 5 A3 Evidence Fusion
- [ ] Phase 6 Pipeline + evaluation
- [ ] Phase 7 Final run + submission

## Early results
A1 alone on eval: accuracy 1.0000, 2 errors out of 104,390 eval rows not seen in train
(8.6% of eval rows exactly match a train row). `Destination Port` is A1's top feature,
which suggests a port shortcut; the leave-one-attack-out experiment (Phase 6) will test
generalisation beyond it.

See `Plan.md` for the task list and `docs/progress.md` for the log.
