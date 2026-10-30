# CyberSentinel — Multi-Agent Network Intrusion Detection (JAI 2026, Track 1)

Offline traffic-replay IDS on CICIDS2017 (parquet). Classify flows, fuse evidence from
independent agents, apply explainable simulated ALLOW/BLOCK policy. Not a live firewall.

Classes (exactly 5): BENIGN, BRUTE_FORCE, DOS, DDOS, PORT_SCAN
Primary metric: macro-F1 (BENIGN ~52%; BRUTE_FORCE is the minority class and decides macro-F1).
Day 1 deadline: Level 1 summary submitted via organiser API by 7:30 PM (hard cutoff 8:00).

## Stack
Python 3.11, pandas, pyarrow, numpy, scikit-learn, lightgbm, shap, joblib, matplotlib, requests.

## Layout
```
cybersentinel/
├── CLAUDE.md, AGENTS.md (copy), Plan.md, README.md, requirements.txt, .gitignore
├── data/                         # gitignored, read-only except processed/
│   ├── README.md, manifest.json  # organiser docs
│   ├── Cyber/training/flows.parquet   # 456,737 rows
│   ├── Cyber/eval/flows.parquet       # 114,185 rows (dev set)
│   ├── hidden/                   # hidden set when released
│   └── processed/                # train_clean.parquet, eval_clean.parquet
├── models/                       # gitignored
│   ├── a1_lgbm.joblib, a2_iforest.joblib
│   ├── prep_stats.json           # medians, dropped cols, feature list
│   ├── a2_baseline.json          # benign median/IQR, threshold
│   └── fusion_config.json        # tuned thresholds
├── src/
│   ├── config.py                 # paths, CLASSES, constants (single source of truth)
│   ├── prep.py
│   ├── agents/
│   │   ├── base.py               # Agent interface: fit(df), predict(df)
│   │   ├── threat.py             # A1
│   │   ├── anomaly.py            # A2
│   │   └── fusion.py             # A3
│   ├── pipeline.py
│   ├── eval.py
│   └── submit.py                 # organiser API submission
├── scripts/
│   ├── inspect.py                # dataset inspection
│   └── loao.py                   # leave-one-attack-out experiment
├── outputs/                      # gitignored
│   ├── eval_results.parquet, metrics.json, disagreement_report.json
│   └── confusion_a1.png, confusion_fused.png, reliability.png
└── docs/
    ├── progress.md, level2.md
```
All paths come from src/config.py. Never hardcode paths elsewhere.

## Commands
```
python scripts/inspect.py
python -m src.prep
python -m src.agents.threat --train
python -m src.agents.anomaly --train
python -m src.agents.fusion --tune
python -m src.pipeline --input data/processed/eval_clean.parquet --out outputs/eval_results.parquet
python -m src.eval --results outputs/eval_results.parquet
python scripts/loao.py --holdout PORT_SCAN
python -m src.submit
```

## Data + prep rules
- Columns: record_id, 78 numeric flow features, label. Labels are ALREADY the 5 classes.
- record_id: keep for joins and output, NEVER a feature.
- Train/eval have no IPs/ports/protocol/seq. Hidden set adds source_ip, destination_ip, ports,
  protocol, seq for replay policy matching. Models use ONLY the 78 flow features.
- Strip column names. inf -> NaN -> median. Medians from TRAIN only, saved in prep_stats.json.
- Drop constant and duplicate columns. Cast to float32. Feature list saved and reused.
- Dedupe TRAIN only. Never drop, reorder, or dedupe eval/hidden rows.
- eval/ is a dev set; final ranking is on hidden. Don't overfit thresholds to eval.

## Agent contract
Every agent subclasses base.Agent with fit(df) and predict(df) -> DataFrame keyed by record_id.
Output keys are frozen:

A1 Threat Detector (LightGBM, class_weight=balanced, isotonic-calibrated probs):
  a1_class, a1_conf, a1_top2, a1_top2_prob, a1_shap [[feature, value] x3]
A2 Anomaly Agent (IsolationForest trained on BENIGN rows only):
  a2_score (0-1, higher = more anomalous), a2_anomalous, a2_evidence [[feature, robust_z] x3]
  threshold = 97th pct of BENIGN scores (tunable)
A3 Evidence Fusion (rule-based):
  final_class, status, evidence_strength, policy, rationale
  status in CORROBORATED | CLASSIFIER_ONLY | ANOMALY_ONLY | CONFLICT | TIEBREAK
  evidence_strength in STRONG | MODERATE | WEAK  (STRONG = A1 SHAP and A2 evidence share a feature)
  policy in ALLOW | BLOCK | REVIEW

## Fusion table
- attack hi-conf + anomalous  -> CORROBORATED,    A1 class, BLOCK
- attack hi-conf + normal     -> CLASSIFIER_ONLY, A1 class, BLOCK
- attack lo-conf + normal     -> CONFLICT,        tuned,    ALLOW + flag
- BENIGN + normal             -> CORROBORATED,    BENIGN,   ALLOW
- BENIGN + anomalous          -> ANOMALY_ONLY,    top2 attack if prob > t else BENIGN, REVIEW/BLOCK
- lo-conf + anomalous         -> TIEBREAK,        lean attack, BLOCK
Thresholds grid-searched for macro-F1, saved in fusion_config.json.

## Eval must report
- Accuracy, macro-F1, per-class F1: A1 alone vs fused, side by side
- Confusion matrices (A1, fused), status counts, evidence_strength counts
- Override count + override accuracy (how often fusion changed A1 and was right)
- A2 ROC-AUC attack vs benign, % of each class flagged
- Throughput (flows/sec for the full pipeline)
- LOAO: A1 vs fused recall on the held-out attack class

## Hard rules
- A2 must NEVER see attack labels.
- No LLM calls per flow. Rationale is a template string.
- Never change agent output keys without updating this file.
- Train on full train set; no subsampling needed.
- Pipeline passes extra columns (ips, ports, protocol, seq) through untouched (Level 2 prep).
- Follow Plan.md: one checkbox = one commit with the given message. Tick the box in the same commit.
- Never batch multiple checkboxes into one commit. Each commit must run without breaking earlier work.
- After each commit, append 2 lines to docs/progress.md (include it in the next commit).

## Working style
- Short replies. Code over explanation.
- Edit only the files the task names. Don't scan data/, models/, outputs/.
- Show only the last 30 lines of long errors or outputs.