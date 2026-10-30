"""Cleaning: train stats fitted once, applied identically to eval/hidden."""
import pandas as pd

from src.config import EVAL_RAW, ID_COL, LABEL_COL, TRAIN_RAW


def load(path) -> pd.DataFrame:
    df = pd.read_parquet(path)
    df.columns = df.columns.str.strip()
    return df


def main() -> None:
    train, ev = load(TRAIN_RAW), load(EVAL_RAW)
    for name, df in (("train", train), ("eval", ev)):
        print(f"{name}: {df.shape}, id={ID_COL in df}, label={LABEL_COL in df}")


if __name__ == "__main__":
    main()
