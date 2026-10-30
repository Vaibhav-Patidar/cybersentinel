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
    medians = x.median().fillna(0).astype(float)
    x = x.fillna(medians)

    constant = [c for c in feats if x[c].nunique() <= 1]
    seen, duplicate = {}, []
    for c in feats:
        if c in constant:
            continue
        h = pd.util.hash_pandas_object(x[c], index=False).sum()
        if h in seen and x[c].equals(x[seen[h]]):
            duplicate.append(c)
        else:
            seen.setdefault(h, c)
    dropped = set(constant) | set(duplicate)
    return {
        "raw_features": feats,
        "medians": medians.to_dict(),
        "constant": constant,
        "duplicate": duplicate,
        "features": [c for c in feats if c not in dropped],
    }


def transform(df: pd.DataFrame, stats: dict) -> pd.DataFrame:
    feats = stats["raw_features"]
    missing = set(feats) - set(df.columns)
    if missing:
        raise KeyError(f"missing features: {sorted(missing)}")
    x = df[feats].replace([np.inf, -np.inf], np.nan).fillna(stats["medians"])
    x = x[stats["features"]].astype(np.float32)
    keep = [c for c in df.columns if c in (ID_COL, *PASSTHROUGH)]
    tail = [LABEL_COL] if LABEL_COL in df else []
    return pd.concat([df[keep], x, df[tail]], axis=1)


def main() -> None:
    train, ev = load(TRAIN_RAW), load(EVAL_RAW)
    stats = fit_stats(train)
    train, ev = transform(train, stats), transform(ev, stats)
    print(f"constant: {stats['constant']}\nduplicate: {stats['duplicate']}")
    for name, df in (("train", train), ("eval", ev)):
        x = df[stats["features"]]
        print(f"{name}: {df.shape}, features={x.shape[1]}, NaN={int(x.isna().sum().sum())}, "
              f"dtypes={set(map(str, x.dtypes))}")


if __name__ == "__main__":
    main()
