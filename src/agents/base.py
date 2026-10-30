"""Agent interface: fit(df), predict(df) -> DataFrame keyed by record_id."""
from abc import ABC, abstractmethod
from pathlib import Path

import joblib
import pandas as pd


class Agent(ABC):
    name: str = "agent"

    @abstractmethod
    def fit(self, df: pd.DataFrame) -> "Agent":
        ...

    @abstractmethod
    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """Return one row per input row, same order, with record_id + agent keys."""
        ...

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @classmethod
    def load(cls, path: str | Path) -> "Agent":
        obj = joblib.load(path)
        if not isinstance(obj, cls):
            raise TypeError(f"{path} holds {type(obj).__name__}, expected {cls.__name__}")
        return obj
