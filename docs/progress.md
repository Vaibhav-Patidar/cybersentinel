# Progress
- 10:42 Phase 0: repo init, docs, scaffold done.
  Next: config.py and base Agent.
- 10:42 config.py: all paths, CLASSES, RANDOM_STATE, ID/LABEL cols.
  Next: base Agent.
- 10:42 base.Agent: abstract fit/predict, joblib save/load.
  Phase 0 done. Next: Phase 1 inspect.py.
- 11:18 inspect.py: shape/labels/inf/NaN/const/dup cols+rows; ~9s on train+eval.
  Note: scripts/inspect.py shadows stdlib inspect; script strips its dir from sys.path.

## Dataset inspection (scripts/inspect.py)
- train 456,737 x 80, eval 114,185 x 80 (record_id + 78 numeric features + label). All features numeric.
- Labels identical ratios in both: BENIGN 52.55%, DOS 21.02%, PORT_SCAN 12.61%, DDOS 12.61%, BRUTE_FORCE 1.21% (5,537 train / 1,384 eval).
- inf: 0, NaN: 0 in both (keep inf->NaN->median step anyway for hidden set).
- Constant (3): Fwd URG Flags, Bwd URG Flags, URG Flag Count.
- Duplicate cols (beyond constants): Average Packet Size==Packet Length Mean, Avg Fwd Segment Size==Fwd Packet Length Mean,
  Avg Bwd Segment Size==Bwd Packet Length Mean, Fwd Header Length_duplicated_0==Fwd Header Length -> 78 - 7 = 71 features.
- Duplicate rows: train 24,132 (5.3%), eval 2,273; no feature-dup with conflicting labels. record_id unique in both.
- Decided: decisions from train only; same 7 cols dropped on eval/hidden.
- 11:18 Phase 1 done: findings recorded above.
  Next: Phase 2 prep.
- 11:25 prep: load() reads parquet + strips column names.
  Next: inf->NaN + train medians.
- 11:26 prep: fit_stats (train medians) + transform (inf->NaN->median).
  Next: drop const/dup cols, float32.
- 11:26 prep: constant/duplicate cols found on train, dropped everywhere; float32.
  Next: dedupe train, save parquet + prep_stats.json.
- 11:26 prep: train deduped on features+label; saves train/eval_clean.parquet + prep_stats.json.
  Next: eval row-count/order test.
- 11:27 prep: check_eval asserts rows/record_id order/labels unchanged; runs every prep.
  Phase 2 done: 432,605 train / 114,185 eval, 71 float32 features. Next: Phase 3 A1.
- 11:30 a1: ThreatDetector(Agent) LightGBM 300 trees, class_weight=balanced; 45s on full train.
  Next: predict conf + top-2.
- 11:31 a1: predict -> record_id, a1_class, a1_conf, a1_top2, a1_top2_prob.
  Raw LGBM probs saturate near 1.0 -> calibration next.
- 11:34 a1: one-vs-rest isotonic on 15% stratified train holdout; top-2 ties broken by raw probs.
  Eval acc 1.0000 (2 errors on unseen rows, no id overlap); ECE ~0 both ways. Destination Port = top feature.
- 12:11 a1: TreeSHAP too slow on loaded box (load ~11; ~1.5ms/row). Fallback: gain importance x capped robust z, top-3 per flow, 2.4s on eval.
  Model cut to 100 trees/31 leaves; eval acc still 1.0000. Next: save model + baseline report.
- 12:13 a2: IF(100) on 229,647 BENIGN train rows, threshold 0.5653; eval AUC 0.897.
  Flag rate: BENIGN 2.8%, DOS 4.0%, BF 0.07%, DDOS 0.03%, PS 0%. Time-boxed: 4 A2 boxes in 1 commit.
- 12:13 a3: CLAUDE.md fusion table, fixed conf=0.8, top2 switch t=0.3, anomaly = A2 97pct flag. No grid search.
  CONFLICT keeps A1 class (ALLOW+flag). STRONG impossible while a1_shap=[].
- 12:15 a1: saved models/a1_lgbm.joblib (trained once, 206s); --no-shap sets a1_shap=[].
  Eval acc 1.0000 calibrated and raw. Loaded from disk from here on.
- 12:16 pipeline: loads saved A1/A2, fuses, writes outputs/eval_results.parquet; 12,803 flows/s.
  Status: CORROBORATED 59,283, CLASSIFIER_ONLY 53,217, ANOMALY_ONLY 1,685.
- 12:16 eval: macro-F1 A1 0.999983 = fused 0.999983 (all); 0.999974 both on 104,390 unseen rows.
  0 overrides: all 1,685 ANOMALY_ONLY flows stayed BENIGN (top-2 prob 0 < 0.3). Fusion adds nothing on eval yet.
- 12:20 fix: models were pickled as __main__.ThreatDetector/AnomalyAgent; --train now imports real module.
  Existing models re-saved under src.agents.* (no retrain).
- 12:21 a3 --tune: 150 configs (conf_t x top2_t x anomaly pct) on train cal slice (64,891 rows), never eval. 35s.
  Flat: all 150 give macro-F1 1.0 -> tie-break keeps defaults 0.8/0.3/97pct. Pipeline loads fusion_config.json.
- 12:22 eval: confusion_a1.png / confusion_fused.png + matrices in metrics.json; status & evidence counts per class.
  Only errors: 2 PORT_SCAN -> BENIGN. A2 corroborates 960/24,000 DOS, ~0 of other attacks.
- 12:23 eval: override_accuracy added; pipeline writes pipeline_stats.json, eval folds it into metrics.json.
  Throughput 26,334 flows/s (no-shap). A2 AUC 0.897. Overrides still 0.
- 12:23 loao: unseen-class detect rate A1/fused: BF 0.0/0.0, DOS 0.0003/0.0003, DDOS 0.621/0.621, PS 0.0006/0.0006.
  A2 flags 4% of unseen DOS (-> REVIEW), ~0 else. Fusion does not rescue unseen attacks. A1 now handles absent classes.
