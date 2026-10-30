# CyberSentinel — Day 1 Plan (Level 1)

Submit by 7:30 PM (hard cutoff 8:00). One commit per checkbox. Commit message given for each.
Rule: every commit must run without breaking what came before. Push after every commit.

---

## Phase 0 | Repo Setup (4:10–4:25)
- [x] `chore: init repo with README, .gitignore, requirements.txt`
- [x] `docs: add CLAUDE.md, AGENTS.md, Plan.md`
- [x] `chore: scaffold folder structure (src, scripts, docs, outputs)`
- [x] `feat(config): add paths, CLASSES and constants in src/config.py`
- [x] `feat(agents): add base Agent interface with fit/predict`

## Phase 1 | Data Inspection (4:25–4:35)
- [x] `feat(scripts): add inspect.py for shape, labels, inf/NaN, dupes, constant cols`
- [x] `docs: record dataset inspection findings in progress.md`

## Phase 2 | Preprocessing (4:35–5:00)
- [x] `feat(prep): load train/eval parquet and strip column names`
- [x] `feat(prep): replace inf with NaN and impute train medians`
- [x] `feat(prep): drop constant and duplicate columns, cast float32`
- [x] `feat(prep): dedupe train only, save processed parquet + prep_stats.json`
- [x] `test(prep): assert eval row count and record_id order unchanged`

## Phase 3 | A1 Threat Detector (5:00–5:40)
- [x] `feat(a1): train LightGBM multiclass with balanced class weights`
- [x] `feat(a1): predict class, confidence, top-2 class and prob`
- [x] `feat(a1): add isotonic calibration of probabilities`
- [x] `feat(a1): add top-3 SHAP features per flow` (fallback used, see fix commit)
- [ ] `feat(a1): save model and report baseline accuracy + macro-F1`

## Phase 4 | A2 Anomaly Agent (5:00–5:40, parallel with Phase 3)
- [x] `feat(a2): train IsolationForest on BENIGN rows only`
- [x] `feat(a2): normalise anomaly score to 0-1 and set 97th pct threshold`
- [x] `feat(a2): add robust-z feature evidence (top-3) from benign baseline`
- [x] `feat(a2): save model + baseline, report ROC-AUC and per-class flag rate`

## Phase 5 | A3 Evidence Fusion (5:40–6:15)
- [ ] `feat(a3): implement fusion decision table with status labels`
- [ ] `feat(a3): add evidence_strength from A1/A2 feature overlap`
- [ ] `feat(a3): map status to ALLOW/BLOCK/REVIEW policy`
- [ ] `feat(a3): add templated per-flow rationale`
- [ ] `feat(a3): grid-search thresholds for macro-F1, save fusion_config.json`

## Phase 6 | Pipeline + Evaluation (6:15–6:45)
- [ ] `feat(pipeline): run A1 + A2 + A3 end to end, pass extra columns through`
- [ ] `feat(eval): accuracy, macro-F1, per-class F1 for A1 vs fused`
- [ ] `feat(eval): confusion matrices, status and evidence counts`
- [ ] `feat(eval): override count/accuracy, A2 AUC, throughput`
- [ ] `feat(scripts): add leave-one-attack-out experiment (loao.py)`

## Phase 7 | Final Run + Submission (6:45–7:30)
- [ ] `chore: run final pipeline on official eval, save outputs/metrics.json`
- [ ] `feat(submit): build API payload from metrics.json`
- [ ] `chore: submit Level 1 results, save API response`
- [ ] `docs: add Level 1 results summary to README`

Level 2 briefing runs 6:00–8:00. Notes go in docs/level2.md:
- [ ] `docs: add Level 2 briefing notes`

---

## Fallbacks (commit as `fix:` if used)
- A1 slow -> fewer trees
- SHAP slow -> LightGBM feature_importances_ per flow
- A2 weak -> robust-z max as anomaly score
- Tuning late -> default thresholds (conf 0.8, 97 pct)

## Overnight (after 8 PM)
- [ ] `feat(policy): stateful per-IP policy agent stub for replay`
- [ ] `feat(dashboard): agent graph, verdict log, metrics visuals`
- [ ] `docs: PPT assets (architecture diagram, charts)`