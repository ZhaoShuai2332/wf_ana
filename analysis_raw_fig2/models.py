from __future__ import annotations

from dataclasses import dataclass

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import LinearSVC


SUPPORTED_MODELS = (
    "logistic_regression",
    "random_forest",
    "linear_svm",
    "knn",
    "xgboost",
)


@dataclass
class OptionalModelUnavailable(Exception):
    model_name: str
    reason: str

    def __str__(self) -> str:
        return f"{self.model_name} is unavailable: {self.reason}"


def build_model(
    model_name: str,
    seed: int,
    n_estimators: int = 300,
    max_depth: int | None = None,
):
    if model_name == "logistic_regression":
        return LogisticRegression(
            max_iter=2000,
            random_state=seed,
            class_weight="balanced",
        )
    if model_name == "random_forest":
        return RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=seed,
            n_jobs=-1,
            class_weight="balanced_subsample",
        )
    if model_name == "linear_svm":
        return LinearSVC(
            random_state=seed,
            class_weight="balanced",
            max_iter=5000,
        )
    if model_name == "knn":
        return KNeighborsClassifier(n_neighbors=5)
    if model_name == "xgboost":
        try:
            from xgboost import XGBClassifier
        except ImportError as exc:
            raise OptionalModelUnavailable("xgboost", str(exc)) from exc
        return XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth if max_depth is not None else 6,
            random_state=seed,
            eval_metric="mlogloss",
            n_jobs=-1,
        )
    raise ValueError(
        f"unknown model '{model_name}'. Supported models: {', '.join(SUPPORTED_MODELS)}"
    )
