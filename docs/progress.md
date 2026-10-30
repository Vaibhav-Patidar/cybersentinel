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
