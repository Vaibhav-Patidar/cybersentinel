"""Dataset inspection: shape, labels, inf/NaN, dupes, constant cols."""
import sys
from pathlib import Path

# this file shadows stdlib `inspect`; drop scripts/ from path before numpy/pandas import it
_here = Path(__file__).resolve().parent
sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != _here]
sys.modules.pop("inspect", None)
sys.path.insert(0, str(_here.parent))

import numpy as np
import pandas as pd

from src.config import EVAL_RAW, ID_COL, LABEL_COL, TRAIN_RAW


def inspect(name: str, path: Path) -> None:
    df = pd.read_parquet(path)
    df.columns = df.columns.str.strip()
    print(f"\n=== {name}: {path.relative_to(path.parents[3])} ===")
    print(f"shape: {df.shape}")

    if LABEL_COL in df:
        vc = df[LABEL_COL].value_counts()
        print("labels:")
        for k, v in vc.items():
            print(f"  {k:<12} {v:>8}  {v / len(df):6.2%}")

    feats = df.drop(columns=[c for c in (ID_COL, LABEL_COL) if c in df])
    num = feats.select_dtypes(include="number")
    other = [c for c in feats.columns if c not in num.columns]
    print(f"numeric features: {num.shape[1]}  non-numeric: {other}")

    inf = np.isinf(num.to_numpy(dtype="float64")).sum(axis=0)
    nan = num.isna().sum().to_numpy()
    print(f"inf cells: {inf.sum()} in {(inf > 0).sum()} cols {list(num.columns[inf > 0])}")
    print(f"NaN cells: {nan.sum()} in {(nan > 0).sum()} cols {list(num.columns[nan > 0])}")

    const = [c for c in num.columns if num[c].nunique(dropna=False) <= 1]
    print(f"constant cols ({len(const)}): {const}")

    seen, dup_cols = {}, []
    for c in num.columns:
        h = pd.util.hash_pandas_object(num[c], index=False).sum()
        if h in seen and num[c].equals(num[seen[h]]):
            dup_cols.append(f"{c}=={seen[h]}")
        else:
            seen.setdefault(h, c)
    print(f"duplicate cols ({len(dup_cols)}): {dup_cols}")

    if ID_COL in df:
        print(f"record_id unique: {df[ID_COL].is_unique}")
    print(f"duplicate rows (features+label): {df.drop(columns=[ID_COL], errors='ignore').duplicated().sum()}")
    print(f"duplicate rows (features only): {feats.duplicated().sum()}")


if __name__ == "__main__":
    inspect("train", TRAIN_RAW)
    inspect("eval", EVAL_RAW)
