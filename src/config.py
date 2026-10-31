"""Paths, classes and constants. Single source of truth."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# data
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "Cyber"
TRAIN_RAW = RAW_DIR / "training" / "flows.parquet"
EVAL_RAW = RAW_DIR / "eval" / "flows.parquet"
HIDDEN_DIR = DATA_DIR / "hidden"
HIDDEN_RAW = HIDDEN_DIR / "Cyber" / "hidden" / "records.csv"
TEMPLATES_DIR = DATA_DIR / "templates"
PROCESSED_DIR = DATA_DIR / "processed"
TRAIN_CLEAN = PROCESSED_DIR / "train_clean.parquet"
EVAL_CLEAN = PROCESSED_DIR / "eval_clean.parquet"
HIDDEN_CLEAN = PROCESSED_DIR / "hidden_clean.parquet"

# models
MODELS_DIR = ROOT / "models"
A1_MODEL = MODELS_DIR / "a1_lgbm.joblib"
A2_MODEL = MODELS_DIR / "a2_iforest.joblib"
PREP_STATS = MODELS_DIR / "prep_stats.json"
A2_BASELINE = MODELS_DIR / "a2_baseline.json"
FUSION_CONFIG = MODELS_DIR / "fusion_config.json"

# outputs
OUTPUTS_DIR = ROOT / "outputs"
EVAL_RESULTS = OUTPUTS_DIR / "eval_results.parquet"
METRICS = OUTPUTS_DIR / "metrics.json"
PIPELINE_STATS = OUTPUTS_DIR / "pipeline_stats.json"
DISAGREEMENT_REPORT = OUTPUTS_DIR / "disagreement_report.json"
CONFUSION_A1_PNG = OUTPUTS_DIR / "confusion_a1.png"
CONFUSION_FUSED_PNG = OUTPUTS_DIR / "confusion_fused.png"
RELIABILITY_PNG = OUTPUTS_DIR / "reliability.png"
SUBMISSION_PAYLOAD = OUTPUTS_DIR / "submission_payload.json"
SUBMISSION_RESPONSE = OUTPUTS_DIR / "submission_response.json"
DASHBOARD_HTML = OUTPUTS_DIR / "dashboard.html"
PPT_DIR = OUTPUTS_DIR / "ppt"
POLICY_RESULTS = OUTPUTS_DIR / "policy_results.parquet"
HIDDEN_RESULTS = OUTPUTS_DIR / "hidden_results.parquet"

# docs
DOCS_DIR = ROOT / "docs"
PROGRESS = DOCS_DIR / "progress.md"
LEVEL2 = DOCS_DIR / "level2.md"

CLASSES = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]
BENIGN = "BENIGN"
RANDOM_STATE = 42
ID_COL = "record_id"
LABEL_COL = "label"

# Level 2 replay
A4_WINDOW = 20  # A4: past seq positions kept per source_ip
A5_MIN_GROUP = 2   # A5 trigger: A4 group count >= k
A5_CONF = 0.95     # A5 trigger: single attack flow with a1_conf >= this
A5_TTL = 50        # A5 policy lifetime in seq positions (capped at last record)
POLICY_LOG = OUTPUTS_DIR / "policy_log.json"
REPLAY_TRACE = OUTPUTS_DIR / "replay_trace.parquet"
SUBMISSION_DIR = OUTPUTS_DIR / "submission"
