<div align="center">

# 🛡️ CyberSentinel

**Multi-agent network intrusion detection with explainable evidence fusion**

*JAI 2026 · Track 1 · CICIDS2017 offline traffic replay*

![Python](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)
![LightGBM](https://img.shields.io/badge/LightGBM-classifier-2E8B57)
![scikit--learn](https://img.shields.io/badge/scikit--learn-IsolationForest-F7931E?logo=scikitlearn&logoColor=white)
![Metric](https://img.shields.io/badge/primary%20metric-macro--F1-8A2BE2)

</div>

---

CyberSentinel classifies network flows into **five classes** using two independent agents:
a supervised classifier and an anomaly detector that never sees attack labels. A third agent
fuses their evidence into a final verdict, applies a simulated **ALLOW / BLOCK / REVIEW** policy,
and writes a human-readable rationale for every flow.

> Offline replay only. CyberSentinel decides what a firewall *would* do; it is not a live firewall.

| Class | Share of train |
|---|---|
| `BENIGN` | 52.6% |
| `DOS` | 21.0% |
| `DDOS` | 12.6% |
| `PORT_SCAN` | 12.6% |
| `BRUTE_FORCE` | 1.2% |

Accuracy is misleading on this class mix, so **macro-F1** is the headline metric. `BRUTE_FORCE`,
the smallest class, decides it.

## 🧭 Architecture

```mermaid
flowchart LR
    A[(Flow parquet)] --> P[Prep<br/>clean · impute · 71 features]
    P --> A1[🎯 A1 Threat Detector<br/>LightGBM, calibrated]
    P --> A2[🔍 A2 Anomaly Agent<br/>IsolationForest on BENIGN only]
    A1 -- class · confidence · top-2 --> F{⚖️ A3 Evidence Fusion}
    A2 -- score · flag · robust-z --> F
    F --> V[Final class<br/>status · evidence strength]
    V --> POL[🚦 Policy<br/>ALLOW · BLOCK · REVIEW]
    POL --> R[(Results +<br/>rationale per flow)]
```

### The agents

| | Agent | Model | Emits |
|---|---|---|---|
| 🎯 | **A1 Threat Detector** | LightGBM, balanced class weights, isotonic calibration | `a1_class`, `a1_conf`, `a1_top2`, `a1_top2_prob`, `a1_shap` |
| 🔍 | **A2 Anomaly Agent** | IsolationForest fitted on BENIGN traffic only | `a2_score` (0-1), `a2_anomalous`, `a2_evidence` (top-3 robust-z) |
| ⚖️ | **A3 Evidence Fusion** | Transparent rule table | `final_class`, `status`, `evidence_strength`, `policy`, `rationale` |

A2 learns only what normal traffic looks like, so it can flag attacks A1 was never trained on.
When the agents disagree, A3 says so explicitly instead of hiding it.

## ⚖️ How fusion decides

```mermaid
flowchart TD
    S([Flow]) --> Q1{A1 says<br/>attack?}
    Q1 -- yes --> Q2{A1 confident?<br/>conf ≥ 0.8}
    Q1 -- no --> Q5{A2 anomalous?}

    Q2 -- yes --> Q3{A2 anomalous?}
    Q2 -- no --> Q4{A2 anomalous?}

    Q3 -- yes --> C1[✅ CORROBORATED<br/>A1 class · BLOCK]
    Q3 -- no --> C2[🎯 CLASSIFIER_ONLY<br/>A1 class · BLOCK]
    Q4 -- no --> C3[⚠️ CONFLICT<br/>A1 class · ALLOW + flag]
    Q4 -- yes --> C6[🔀 TIEBREAK<br/>lean attack · BLOCK]

    Q5 -- no --> C4[✅ CORROBORATED<br/>BENIGN · ALLOW]
    Q5 -- yes --> Q6{A1 confident?}
    Q6 -- yes --> C5[🔍 ANOMALY_ONLY<br/>top-2 attack if p > 0.3 → BLOCK<br/>else BENIGN → REVIEW]
    Q6 -- no --> C6
```

Each verdict carries an **evidence strength**:
`STRONG` when A1's and A2's top features overlap, `MODERATE` when the agents corroborate each other,
and `WEAK` otherwise.

Example rationale:

```text
CLASSIFIER_ONLY: A1 says DOS (0.97), A2 normal (score 0.412, top Flow Duration) -> DOS, BLOCK
```

## 🧹 Data pipeline

```mermaid
flowchart LR
    T[(train<br/>456,737 rows)] --> S1[Strip column names]
    E[(eval<br/>114,185 rows)] --> S1
    S1 --> S2[inf → NaN → train median]
    S2 --> S3[Drop 3 constant +<br/>4 duplicate columns]
    S3 --> S4[float32 · 71 features]
    S4 --> D{Split?}
    D -- train --> DD[Dedupe → 432,605 rows]
    D -- eval --> NC[No drops, no reorder<br/>asserted every run]
```

All statistics (medians, dropped columns, feature list) come from **train only** and are saved to
`models/prep_stats.json`, so eval and the hidden set are cleaned exactly the same way.
Endpoint metadata on the hidden set (IPs, ports, protocol, seq) passes straight through for the
policy and is never used as a model feature.

## 🚀 Quickstart

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Put the organiser data in `data/Cyber/{training,eval}/flows.parquet`, then:

```bash
python scripts/inspect.py              # dataset health check
python -m src.prep                     # clean -> data/processed/
python -m src.agents.threat --train    # train + save A1
python -m src.agents.anomaly --train   # train + save A2
python -m src.pipeline --input data/processed/eval_clean.parquet --out outputs/eval_results.parquet
python -m src.eval --results outputs/eval_results.parquet   # -> outputs/metrics.json
```

## 📁 Project layout

```text
cybersentinel/
├── src/
│   ├── config.py          # every path and constant
│   ├── prep.py            # cleaning, train-only stats
│   ├── agents/
│   │   ├── base.py        # Agent interface: fit / predict / save / load
│   │   ├── threat.py      # 🎯 A1
│   │   ├── anomaly.py     # 🔍 A2
│   │   └── fusion.py      # ⚖️ A3
│   ├── pipeline.py        # A1 + A2 → A3, end to end
│   └── eval.py            # A1-only vs fused metrics
├── scripts/inspect.py     # dataset inspection
├── models/                # saved agents + stats (gitignored)
└── outputs/               # results + metrics (gitignored)
```

## 🔬 Findings so far

- **A1 is near-perfect on eval** (accuracy 1.0000), and stays that way on eval rows that never appear in train.
  CICIDS2017 is known to be highly separable.
- **`Destination Port` is A1's strongest feature**, a likely shortcut. A leave-one-attack-out
  experiment will test how the system copes with an attack type it has never seen.
- **A2 separates attacks from benign traffic** (ROC-AUC 0.897) without ever seeing an attack label,
  but at the strict 97th-percentile threshold it flags few attacks, so most fusion decisions lean on A1.

---

<div align="center">
<sub>Built for JAI 2026 · Track 1</sub>
</div>
