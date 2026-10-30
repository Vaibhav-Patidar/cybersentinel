"""Cleaning: train stats fitted once, applied identically to eval/hidden."""
import numpy as np
import pandas as pd

from src.config import EVAL_RAW, ID_COL, LABEL_COL, TRAIN_RAW

# hidden set adds these for replay; passed through untouched, never features
PASSTHROUGH = ["source_ip", "destination_ip", "source_port", "destination_port", "protocol", "seq"]


def load(path) -> pd.DataFrame:
    df = pd.read_parquet(path)
    df.columns = df.columns.str.strip()
    return df


def raw_features(df: pd.DataFrame) -> list[str]:
    skip = {ID_COL, LABEL_COL, *PASSTHROUGH}
    return [c for c in df.columns if c not in skip and pd.api.types.is_numeric_dtype(df[c])]


def fit_stats(train: pd.DataFrame) -> dict:
    feats = raw_features(train)
    x = train[feats].replace([np.inf, -np.inf], np.nan)
    return {"raw_features": feats, "medians": x.median().fillna(0).astype(float).to_dict()}


def transform(df: pd.DataFrame, stats: dict) -> pd.DataFrame:
    feats = stats["raw_features"]
    missing = set(feats) - set(df.columns)
    if missing:
        raise KeyError(f"missing features: {sorted(missing)}")
    out = df.copy()
    out[feats] = out[feats].replace([np.inf, -np.inf], np.nan).fillna(stats["medians"])
    return out


def main() -> None:
    train, ev = load(TRAIN_RAW), load(EVAL_RAW)
    stats = fit_stats(train)
    train, ev = transform(train, stats), transform(ev, stats)
    for name, df in (("train", train), ("eval", ev)):
        n_nan = int(df[stats["raw_features"]].isna().sum().sum())
        print(f"{name}: {df.shape}, NaN after impute={n_nan}")


if __name__ == "__main__":
    main()
