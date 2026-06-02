from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def _metric_label(metric: str) -> str:
    return {
        "accuracy": "Accuracy",
        "macro_f1": "Macro-F1",
        "weighted_f1": "Weighted-F1",
        "balanced_accuracy": "Balanced Accuracy",
    }.get(metric, metric)


def plot_fhead_ftail_metric(
    results_long: pd.DataFrame,
    metric: str,
    model_name: str,
    out_dir: Path,
    dataset_name: str,
    top_m_flows: int,
    max_events: int,
) -> list[Path]:
    plot_df = results_long[
        (results_long["metric"] == metric) & (results_long["model"] == model_name)
    ].copy()
    if plot_df.empty:
        return []

    full_values = plot_df[plot_df["ablation_type"] == "full"]["value"].astype(float)
    full_mean = float(full_values.mean()) if not full_values.empty else np.nan

    fig, ax = plt.subplots(figsize=(8.5, 5.0))
    for ablation_type, label, marker in [
        ("fhead", "Fhead(k)", "o"),
        ("ftail", "Ftail(k)", "s"),
    ]:
        local = plot_df[plot_df["ablation_type"] == ablation_type]
        if local.empty:
            continue
        summary = (
            local.groupby("k")["value"]
            .agg(["mean", "std", "count"])
            .reset_index()
            .sort_values("k")
        )
        stderr = summary["std"].fillna(0.0) / np.sqrt(summary["count"].clip(lower=1))
        ax.errorbar(
            summary["k"],
            summary["mean"],
            yerr=stderr,
            marker=marker,
            capsize=3,
            linewidth=1.8,
            label=label,
        )

    if not np.isnan(full_mean):
        ax.axhline(
            full_mean,
            linestyle="--",
            color="black",
            linewidth=1.2,
            label="Full baseline",
        )

    ylabel = _metric_label(metric)
    ax.set_xlabel("k: number of leading temporal events / clumps")
    ax.set_ylabel(ylabel)
    ax.set_title(
        f"{dataset_name} | {model_name} | Top-M flows={top_m_flows}, max events={max_events}"
    )
    ax.grid(True, linestyle=":", linewidth=0.8, alpha=0.8)
    ax.legend()
    if metric in {"accuracy", "macro_f1", "weighted_f1", "balanced_accuracy"}:
        ax.set_ylim(0.0, 1.0)
    fig.tight_layout()

    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / f"fhead_ftail_{metric}"
    png = base.with_suffix(".png")
    pdf = base.with_suffix(".pdf")
    fig.savefig(png, dpi=220)
    fig.savefig(pdf)
    plt.close(fig)
    return [png, pdf]


def plot_default_metrics(
    results_long: pd.DataFrame,
    model_name: str,
    out_dir: Path,
    dataset_name: str,
    top_m_flows: int,
    max_events: int,
) -> list[Path]:
    paths: list[Path] = []
    for metric in ["accuracy", "macro_f1"]:
        paths.extend(
            plot_fhead_ftail_metric(
                results_long=results_long,
                metric=metric,
                model_name=model_name,
                out_dir=out_dir,
                dataset_name=dataset_name,
                top_m_flows=top_m_flows,
                max_events=max_events,
            )
        )
    return paths
