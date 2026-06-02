from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from analysis_raw_fig2.flow_tensor_builder import transform_train_test
from analysis_raw_fig2.models import OptionalModelUnavailable, build_model


@dataclass
class SplitDefinition:
    seed: int
    train_idx: np.ndarray
    test_idx: np.ndarray


@dataclass
class EvaluationResult:
    metrics: dict[str, float]
    confusion: pd.DataFrame


def sha256_text(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def prepare_group_split_column(metadata_df: pd.DataFrame, group_split_by: str | None) -> str | None:
    if not group_split_by:
        return None
    if group_split_by == "url":
        if "url_sha256" in metadata_df.columns:
            return "url_sha256"
        if "url" in metadata_df.columns:
            metadata_df["url_sha256"] = metadata_df["url"].map(sha256_text)
            return "url_sha256"
    if group_split_by in metadata_df.columns:
        return group_split_by
    raise ValueError(f"--group-split-by column not found in metadata: {group_split_by}")


def _validate_labels_for_split(labels: pd.Series) -> None:
    counts = labels.value_counts()
    if len(counts) < 2:
        raise ValueError("At least two label classes are required for classification.")
    too_small = counts[counts < 2]
    if not too_small.empty:
        details = ", ".join(f"{label}={count}" for label, count in too_small.items())
        raise ValueError(f"Each class needs at least two visits for splitting: {details}")


def _validate_no_leakage(
    metadata_df: pd.DataFrame,
    train_idx: np.ndarray,
    test_idx: np.ndarray,
    group_col: str | None,
) -> None:
    train_visits = set(metadata_df.iloc[train_idx]["visit_id"].astype(str))
    test_visits = set(metadata_df.iloc[test_idx]["visit_id"].astype(str))
    overlap = train_visits & test_visits
    if overlap:
        sample = sorted(overlap)[:5]
        raise ValueError(f"visit_id leakage across train/test: {sample}")

    if group_col:
        train_groups = set(metadata_df.iloc[train_idx][group_col].astype(str))
        test_groups = set(metadata_df.iloc[test_idx][group_col].astype(str))
        group_overlap = train_groups & test_groups
        if group_overlap:
            sample = sorted(group_overlap)[:5]
            raise ValueError(f"{group_col} leakage across train/test: {sample}")


def build_split(
    metadata_df: pd.DataFrame,
    seed: int,
    test_size: float,
    group_col: str | None = None,
) -> SplitDefinition:
    positions = np.arange(len(metadata_df))
    if metadata_df["visit_id"].duplicated().any():
        duplicates = metadata_df.loc[
            metadata_df["visit_id"].duplicated(), "visit_id"
        ].astype(str)
        raise ValueError(f"duplicate visit_id values would risk leakage: {duplicates.head().tolist()}")

    split_values = None
    if "split_group" in metadata_df.columns:
        split_values = metadata_df["split_group"].astype(str).str.lower()
        if {"train", "test"}.issubset(set(split_values)):
            train_idx = positions[(split_values == "train").to_numpy()]
            test_idx = positions[(split_values == "test").to_numpy()]
            if len(train_idx) == 0 or len(test_idx) == 0:
                raise ValueError("manifest split_group must include non-empty train and test.")
            _validate_no_leakage(metadata_df, train_idx, test_idx, group_col)
            return SplitDefinition(seed=seed, train_idx=train_idx, test_idx=test_idx)

    labels = metadata_df["label"].astype(str)
    _validate_labels_for_split(labels)

    if group_col:
        grouped = (
            metadata_df.assign(_label=labels)
            .groupby(group_col, dropna=False)["_label"]
            .agg(lambda values: values.value_counts().idxmax())
            .reset_index()
        )
        _validate_labels_for_split(grouped["_label"].astype(str))
        train_groups, test_groups = train_test_split(
            grouped[group_col].astype(str).to_numpy(),
            test_size=test_size,
            random_state=seed,
            stratify=grouped["_label"].astype(str).to_numpy(),
        )
        train_group_set = set(train_groups)
        test_group_set = set(test_groups)
        train_idx = positions[
            metadata_df[group_col].astype(str).isin(train_group_set)
        ].to_numpy()
        test_idx = positions[
            metadata_df[group_col].astype(str).isin(test_group_set)
        ].to_numpy()
    else:
        indices = positions
        train_idx, test_idx = train_test_split(
            indices,
            test_size=test_size,
            random_state=seed,
            stratify=labels.to_numpy(),
        )

    _validate_no_leakage(metadata_df, train_idx, test_idx, group_col)
    return SplitDefinition(seed=seed, train_idx=np.asarray(train_idx), test_idx=np.asarray(test_idx))


def write_split_files(
    metadata_df: pd.DataFrame,
    split: SplitDefinition,
    out_dir: Path,
    group_col: str | None = None,
    allow_sensitive_metadata_output: bool = False,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    def sanitize(df: pd.DataFrame) -> pd.DataFrame:
        keep = ["visit_id", "label", "pcap_path"]
        for optional in ["split_group", "content_id", "url_sha256", group_col]:
            if optional and optional in df.columns and optional not in keep:
                keep.append(optional)
        if allow_sensitive_metadata_output and "url" in df.columns and "url" not in keep:
            keep.append("url")
        return df.loc[:, [col for col in keep if col in df.columns]]

    sanitize(metadata_df.iloc[split.train_idx]).to_csv(
        out_dir / f"seed_{split.seed}_train.csv", index=False
    )
    sanitize(metadata_df.iloc[split.test_idx]).to_csv(
        out_dir / f"seed_{split.seed}_test.csv", index=False
    )


def evaluate_once(
    X: np.ndarray,
    labels: np.ndarray,
    train_idx: np.ndarray,
    test_idx: np.ndarray,
    feature_names: list[str],
    log_transform: list[str],
    scaler_name: str,
    model_name: str,
    seed: int,
    n_estimators: int,
    max_depth: int | None,
) -> EvaluationResult:
    encoder = LabelEncoder()
    y_all = encoder.fit_transform(labels.astype(str))
    y_train = y_all[train_idx]
    y_test = y_all[test_idx]

    train_classes = set(y_train.tolist())
    test_classes = set(y_test.tolist())
    if not test_classes.issubset(train_classes):
        missing = sorted(test_classes - train_classes)
        names = encoder.inverse_transform(missing)
        raise ValueError(f"test contains labels absent from train: {names.tolist()}")

    X_train, X_test = transform_train_test(
        X[train_idx],
        X[test_idx],
        feature_names=feature_names,
        log_transform=log_transform,
        scaler_name=scaler_name,
    )

    model = build_model(
        model_name,
        seed=seed,
        n_estimators=n_estimators,
        max_depth=max_depth,
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "macro_f1": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(
            f1_score(y_test, y_pred, average="weighted", zero_division=0)
        ),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, y_pred)),
    }
    matrix = confusion_matrix(
        y_test,
        y_pred,
        labels=np.arange(len(encoder.classes_)),
    )
    confusion = pd.DataFrame(
        matrix,
        index=encoder.classes_,
        columns=encoder.classes_,
    )
    return EvaluationResult(metrics=metrics, confusion=confusion)


def metrics_to_long_rows(
    metrics: dict[str, float],
    seed: int,
    ablation_type: str,
    k: int,
    model_name: str,
    train_size: int,
    test_size: int,
    num_classes: int,
    top_m_flows: int,
    max_events: int,
    feature_names: list[str],
    scaler_name: str,
    log_transform: list[str],
    tail_shift_left: bool,
) -> list[dict[str, Any]]:
    rows = []
    for metric, value in metrics.items():
        rows.append(
            {
                "seed": seed,
                "ablation_type": ablation_type,
                "k": k,
                "model": model_name,
                "metric": metric,
                "value": value,
                "train_size": train_size,
                "test_size": test_size,
                "num_classes": num_classes,
                "top_m_flows": top_m_flows,
                "max_events": max_events,
                "feature_names": ";".join(feature_names),
                "scaler": scaler_name,
                "log_transform": ";".join(log_transform),
                "tail_shift_left": bool(tail_shift_left),
            }
        )
    return rows


def summarize_results(results_long: pd.DataFrame) -> pd.DataFrame:
    if results_long.empty:
        return pd.DataFrame()
    return (
        results_long.groupby(["ablation_type", "k", "model", "metric"])["value"]
        .agg(["mean", "std", "min", "max", "count"])
        .reset_index()
        .rename(columns={"count": "num_seeds"})
    )


def write_confusion_matrix(confusion: pd.DataFrame, out_dir: Path, name: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    confusion.to_csv(out_dir / name)


def is_optional_model_unavailable(exc: BaseException) -> bool:
    return isinstance(exc, OptionalModelUnavailable)
