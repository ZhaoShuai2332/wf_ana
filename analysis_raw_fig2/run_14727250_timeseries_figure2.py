from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
import traceback
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from tqdm.auto import tqdm

from analysis_raw_fig2.config import DEFAULT_FEATURE_NAMES, repo_root
from analysis_raw_fig2.pcap_loader import parse_one_pcap, write_errors, ParseFailure


@dataclass
class Figure2Row:
    site: str
    visit_id: str
    pcap_path: str
    selected_flow_id: str
    selection_reason: str
    position_count: int
    units: list[dict[str, float]]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "14727250 Figure-2-style violin plot using the original repository "
            "process_pcap().temporal_stats_per_flow() TimeSeries clumps."
        )
    )
    parser.add_argument("--input", type=Path, default=Path("14727250"))
    parser.add_argument("--out-dir", type=Path, default=Path("outputs/14727250_timeseries_figure2"))
    parser.add_argument("--features-cache", type=Path, default=None)
    parser.add_argument("--reuse-features", action="store_true")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument(
        "--flow-selector",
        choices=("target-largest", "target-first", "largest", "first"),
        default="target-largest",
    )
    parser.add_argument(
        "--target-domain-mode",
        choices=("exact", "exact-or-subdomain"),
        default="exact-or-subdomain",
    )
    parser.add_argument("--sequence-width", type=int, default=20)
    parser.add_argument("--window-size", type=int, default=20)
    parser.add_argument("--min-samples-per-site", type=int, default=5)
    parser.add_argument("--max-folds", type=int, default=5)
    parser.add_argument(
        "--critical-threshold",
        type=float,
        default=0.02,
        help=(
            "Critical-window tolerance below full macro-F1. The window starts "
            "where Fhead reaches this target and ends where Ftail drops below it."
        ),
    )
    parser.add_argument("--model", choices=("logistic_regression", "random_forest"), default="logistic_regression")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--site-limit", type=int, default=0)
    parser.add_argument("--max-visits-per-site", type=int, default=0)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--num-workers", type=int, default=0)
    parser.add_argument("--no-progress", action="store_true")
    parser.add_argument("--workspace", type=Path, default=None)
    return parser.parse_args()


def infer_site_visit(path: Path) -> tuple[str, str, str]:
    stem = path.stem
    result_group = ""
    for parent in path.parents:
        if re.fullmatch(r"result_\d+_\d+", parent.name):
            result_group = parent.name
            break
    site = stem.replace("_", ".")
    visit_id = f"{result_group}/{stem}" if result_group else stem
    return site, visit_id, stem


def collect_pcaps(input_dir: Path, args: argparse.Namespace) -> list[Path]:
    files = sorted(input_dir.rglob("*.pcap")) + sorted(input_dir.rglob("*.pcapng"))
    rows = []
    for path in files:
        site, visit_id, _stem = infer_site_visit(path)
        rows.append((site, visit_id, path))
    if args.site_limit:
        selected_sites = sorted({site for site, _visit, _path in rows})[: args.site_limit]
        rows = [row for row in rows if row[0] in set(selected_sites)]
    if args.max_visits_per_site:
        counts: dict[str, int] = {}
        kept = []
        for site, visit_id, path in rows:
            count = counts.get(site, 0)
            if count >= args.max_visits_per_site:
                continue
            kept.append((site, visit_id, path))
            counts[site] = count + 1
        rows = kept
    if args.limit:
        rows = rows[: args.limit]
    return [path for _site, _visit, path in rows]


def domain_matches(candidate: str, target: str, mode: str) -> bool:
    candidate = candidate.strip().strip(".").lower()
    target = target.strip().strip(".").lower()
    if not candidate or not target:
        return False
    if candidate == target:
        return True
    return mode == "exact-or-subdomain" and candidate.endswith("." + target)


def load_target_ips(pcap_path: Path, stem: str, site: str, mode: str) -> set[str]:
    domain_ip_file = pcap_path.parent.parent / "domain_ip" / f"{stem}.csv"
    if not domain_ip_file.exists():
        return set()
    target_ips: set[str] = set()
    with domain_ip_file.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if len(row) < 2:
                continue
            domain = row[0]
            if not domain_matches(domain, site, mode):
                continue
            for value in row[1:]:
                value = value.strip()
                if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", value):
                    target_ips.add(value)
    return target_ips


def flow_score(flow_id: str, temporal: pd.DataFrame) -> tuple[float, int]:
    group = temporal[temporal["id"].astype(str) == str(flow_id)]
    total_bytes = float(pd.to_numeric(group["length"], errors="coerce").fillna(0).sum())
    return total_bytes, int(len(group))


def select_flow(
    static: pd.DataFrame,
    temporal: pd.DataFrame,
    target_ips: set[str],
    selector: str,
) -> tuple[str | None, str]:
    if static.empty or temporal.empty or "id" not in static.columns:
        return None, "missing_flow_metadata"
    candidates = static.copy()
    candidates["id"] = candidates["id"].astype(str)
    temporal_ids = set(temporal["id"].astype(str))
    candidates = candidates[candidates["id"].isin(temporal_ids)].copy()
    if candidates.empty:
        return None, "no_temporal_flow"

    if target_ips:
        ip_cols = [col for col in ["source_ip", "destination_ip"] if col in candidates.columns]
        target_mask = pd.Series(False, index=candidates.index)
        for col in ip_cols:
            target_mask = target_mask | candidates[col].astype(str).isin(target_ips)
        target_candidates = candidates[target_mask].copy()
    else:
        target_candidates = pd.DataFrame()

    if selector.startswith("target-") and not target_candidates.empty:
        candidates = target_candidates
        prefix = "target"
    elif selector.startswith("target-"):
        prefix = "fallback"
    else:
        prefix = "all"

    if selector.endswith("first"):
        if "timestamp" in candidates.columns:
            ordered = candidates.sort_values("timestamp", kind="stable")
        else:
            ordered = candidates
        return str(ordered.iloc[0]["id"]), f"{prefix}_first"

    scored = []
    for _, row in candidates.iterrows():
        bytes_total, event_count = flow_score(str(row["id"]), temporal)
        scored.append((bytes_total, event_count, str(row["id"])))
    if not scored:
        return None, "no_scored_flow"
    scored.sort(key=lambda item: (-item[0], -item[1], item[2]))
    return scored[0][2], f"{prefix}_largest"


def units_from_temporal(flow_temporal: pd.DataFrame) -> list[dict[str, float]]:
    units = []
    for pos, row in flow_temporal.reset_index(drop=True).iterrows():
        unit = {"position": int(pos)}
        for feature in DEFAULT_FEATURE_NAMES:
            unit[feature] = float(row.get(feature, 0.0))
        units.append(unit)
    return units


def parse_one_14727250(path: Path, args: argparse.Namespace) -> tuple[Figure2Row | None, ParseFailure | None]:
    site, visit_id, stem = infer_site_visit(path)
    try:
        target_ips = load_target_ips(path, stem, site, args.target_domain_mode)
        workspace = args.workspace if args.workspace is not None else args.out_dir / "workspace"
        static, temporal = parse_one_pcap(
            path,
            buffer_tcp=True,
            with_dns=True,
            with_certificates=False,
            workspace=workspace,
        )
        selected_flow_id, reason = select_flow(static, temporal, target_ips, args.flow_selector)
        if selected_flow_id is None:
            raise RuntimeError(reason)
        flow_temporal = temporal[temporal["id"].astype(str) == selected_flow_id]
        units = units_from_temporal(flow_temporal)
        if not units:
            raise RuntimeError("selected_flow_has_no_timeseries_clumps")
        row = Figure2Row(
            site=site,
            visit_id=visit_id,
            pcap_path=str(path),
            selected_flow_id=selected_flow_id,
            selection_reason=reason,
            position_count=len(units),
            units=units,
        )
        return row, None
    except BaseException as exc:
        return None, ParseFailure(
            visit_id=visit_id,
            pcap_path=str(path),
            error_type=type(exc).__name__,
            error_message=str(exc),
            traceback_short="".join(traceback.format_exception(type(exc), exc, exc.__traceback__, limit=4)),
        )


def resolve_workers(requested: int, n: int) -> int:
    if requested < 0:
        raise ValueError("--num-workers must be >= 0")
    if requested == 0:
        import os

        return min(max(1, min(4, (os.cpu_count() or 2) - 1)), max(1, n))
    return min(requested, max(1, n))


def extract_rows(args: argparse.Namespace) -> tuple[list[Figure2Row], list[ParseFailure]]:
    pcaps = collect_pcaps(args.input, args)
    workers = resolve_workers(args.num_workers, len(pcaps))
    print(f"PCAP files: {len(pcaps)}; workers: {workers}")
    rows: list[Figure2Row] = []
    failures: list[ParseFailure] = []
    if workers <= 1:
        iterator = tqdm(pcaps, desc="Parsing TimeSeries pcaps", unit="pcap", disable=args.no_progress)
        for path in iterator:
            row, failure = parse_one_14727250(path, args)
            if row is not None:
                rows.append(row)
            if failure is not None:
                failures.append(failure)
    else:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(parse_one_14727250, path, args): path for path in pcaps}
            iterator = tqdm(as_completed(futures), total=len(futures), desc="Parsing TimeSeries pcaps", unit="pcap", disable=args.no_progress)
            for future in iterator:
                row, failure = future.result()
                if row is not None:
                    rows.append(row)
                if failure is not None:
                    failures.append(failure)
    rows.sort(key=lambda item: (item.site, item.visit_id))
    failures.sort(key=lambda item: item.visit_id)
    return rows, failures


def rows_to_df(rows: list[Figure2Row]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "site": row.site,
                "visit_id": row.visit_id,
                "pcap_path": row.pcap_path,
                "selected_flow_id": row.selected_flow_id,
                "selection_reason": row.selection_reason,
                "position_count": row.position_count,
                "units_json": json.dumps(row.units, ensure_ascii=False),
            }
            for row in rows
        ]
    )


def df_to_rows(df: pd.DataFrame) -> list[Figure2Row]:
    rows = []
    for item in df.to_dict(orient="records"):
        rows.append(
            Figure2Row(
                site=str(item["site"]),
                visit_id=str(item["visit_id"]),
                pcap_path=str(item["pcap_path"]),
                selected_flow_id=str(item["selected_flow_id"]),
                selection_reason=str(item["selection_reason"]),
                position_count=int(item["position_count"]),
                units=json.loads(item["units_json"]),
            )
        )
    return rows


def unit_channels(unit: dict[str, Any]) -> np.ndarray:
    values = []
    for feature in DEFAULT_FEATURE_NAMES:
        raw = float(unit.get(feature, 0.0))
        if feature in {"relative_timestamp", "duration", "length", "pkt_count"}:
            raw = np.log1p(max(0.0, raw))
        values.append(raw)
    return np.asarray(values, dtype=float)


def masked_matrix(rows: list[Figure2Row], mode: str, position: int, sequence_width: int) -> np.ndarray:
    dim = len(DEFAULT_FEATURE_NAMES)
    X = np.zeros((len(rows), sequence_width * dim), dtype=float)
    for row_idx, row in enumerate(rows):
        units = row.units
        if mode == "full":
            selected = units[:sequence_width]
        elif mode == "head":
            selected = units[: position + 1]
        elif mode == "tail":
            selected = units[position:]
        else:
            raise ValueError(f"unknown mask mode: {mode}")
        selected = selected[:sequence_width]
        if selected:
            flat = np.concatenate([unit_channels(unit) for unit in selected])
            X[row_idx, : len(flat)] = flat
    return X


def build_model(name: str, seed: int):
    if name == "logistic_regression":
        return make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=5000, class_weight="balanced", random_state=seed),
        )
    if name == "random_forest":
        return RandomForestClassifier(
            n_estimators=350,
            max_features="sqrt",
            class_weight="balanced_subsample",
            random_state=seed,
            n_jobs=-1,
        )
    raise ValueError(f"unknown model: {name}")


def make_cv(rows: list[Figure2Row], max_folds: int) -> tuple[np.ndarray, np.ndarray, np.ndarray, list[tuple[np.ndarray, np.ndarray]]]:
    labels = np.asarray([row.site for row in rows], dtype=object)
    groups = np.asarray([row.visit_id for row in rows], dtype=object)
    encoder = LabelEncoder()
    y = encoder.fit_transform(labels)
    counts = pd.Series(labels).value_counts()
    min_count = int(counts.min())
    if len(counts) < 2:
        raise ValueError("At least two sites/classes are required.")
    if min_count < 2:
        raise ValueError(f"Each site needs at least two visits; minimum is {min_count}.")
    folds = min(max_folds, min_count)
    splitter = StratifiedKFold(n_splits=folds, shuffle=True, random_state=0)
    return labels, y, groups, list(splitter.split(np.zeros(len(rows)), y))


def evaluate_mask(
    rows: list[Figure2Row],
    mode: str,
    position: int,
    splits: list[tuple[np.ndarray, np.ndarray]],
    labels: np.ndarray,
    y: np.ndarray,
    args: argparse.Namespace,
) -> tuple[dict[str, float], pd.DataFrame]:
    X = masked_matrix(rows, mode, position, args.sequence_width)
    accs = []
    macro_f1s = []
    per_site_records = []
    classes = np.unique(y)
    label_names = np.asarray(LabelEncoder().fit(labels).classes_)
    for fold, (train_idx, test_idx) in enumerate(splits):
        model = build_model(args.model, args.seed + fold)
        model.fit(X[train_idx], y[train_idx])
        pred = model.predict(X[test_idx])
        accs.append(accuracy_score(y[test_idx], pred))
        macro_f1s.append(f1_score(y[test_idx], pred, average="macro", zero_division=0))
        _p, _r, f1s, _s = precision_recall_fscore_support(
            y[test_idx],
            pred,
            labels=classes,
            zero_division=0,
        )
        for class_id, f1_value in zip(classes, f1s):
            per_site_records.append(
                {
                    "fold": fold,
                    "site": label_names[class_id],
                    "f1": float(f1_value),
                    "mode": mode,
                    "position": position,
                }
            )
    return (
        {
            "accuracy": float(np.mean(accs)),
            "macro_f1": float(np.mean(macro_f1s)),
        },
        pd.DataFrame(per_site_records),
    )


def stage_name(position: int) -> str:
    if position == 0:
        return "Client Hello"
    if position == 1:
        return "Server Hello"
    if position % 2 == 0:
        return "Client Req."
    return "Server Resp."


def axis_label(position: int, window_size: int) -> str:
    if position < 8:
        return f"P{position}"
    if position == window_size - 1:
        return f"P{position}"
    if position % 4 == 0:
        return f"P{position}"
    return ""


def infer_critical_window(metrics: pd.DataFrame, threshold: float) -> dict[str, Any]:
    full = metrics[(metrics["mode"] == "full") & (metrics["position"] == -1)]
    if full.empty:
        return {
            "full_macro_f1": np.nan,
            "target_macro_f1": np.nan,
            "threshold": threshold,
            "head_start_position": "",
            "tail_drop_position": "",
            "critical_start_position": "",
            "critical_end_position": "",
            "critical_window": "",
            "method": "missing_full_baseline",
        }
    full_f1 = float(full["macro_f1"].iloc[0])
    target = max(0.0, full_f1 - threshold)

    head = metrics[metrics["mode"] == "head"].sort_values("position")
    tail = metrics[metrics["mode"] == "tail"].sort_values("position")
    head_hits = head[head["macro_f1"] >= target]
    tail_drops = tail[tail["macro_f1"] < target]

    head_start = int(head_hits["position"].iloc[0]) if not head_hits.empty else ""
    tail_drop = int(tail_drops["position"].iloc[0]) if not tail_drops.empty else ""

    if head_start != "" and tail_drop != "":
        start = min(head_start, tail_drop)
        end = max(head_start, tail_drop)
    elif head_start != "":
        start = end = head_start
    elif tail_drop != "":
        start = end = tail_drop
    else:
        start = end = ""

    return {
        "full_macro_f1": full_f1,
        "target_macro_f1": target,
        "threshold": threshold,
        "head_start_position": head_start,
        "tail_drop_position": tail_drop,
        "critical_start_position": start,
        "critical_end_position": end,
        "critical_window": f"P{start}-P{end}" if start != "" and end != "" else "",
        "method": "head_reaches_full_minus_threshold_and_tail_drops_below_it",
    }


def write_violin(per_site: pd.DataFrame, metrics: pd.DataFrame, args: argparse.Namespace) -> None:
    plots_dir = args.out_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    positions = list(range(args.window_size))
    fig, axes = plt.subplots(
        2,
        1,
        figsize=(max(10, args.window_size * 0.75), 7.2),
        sharex=True,
        constrained_layout=True,
        gridspec_kw={"height_ratios": [1, 1], "hspace": 0.08},
    )
    tail_ax, head_ax = axes

    full_values = per_site[per_site["mode"] == "full"]["f1"].astype(float).to_numpy()
    if len(full_values):
        violin = tail_ax.violinplot(
            [full_values],
            positions=[-1],
            widths=0.42,
            showmeans=True,
            showextrema=False,
        )
        for body in violin["bodies"]:
            body.set_facecolor("#d62728")
            body.set_edgecolor("black")
            body.set_alpha(0.65)
        violin["cmeans"].set_color("black")

    for ax, mode, color, lane_title in [
        (tail_ax, "tail", "#ff7f0e", "Ftail(i): keep TimeSeries clumps Pi..end"),
        (head_ax, "head", "#1f77b4", "Fhead(i): keep TimeSeries clumps P0..Pi"),
    ]:
        data = []
        xs = []
        for pos in positions:
            values = per_site[(per_site["mode"] == mode) & (per_site["position"] == pos)]["f1"].astype(float).to_numpy()
            if len(values):
                data.append(values)
                xs.append(pos + 1)
        if data:
            violin = ax.violinplot(data, positions=xs, widths=0.42, showmeans=True, showextrema=False)
            for body in violin["bodies"]:
                body.set_facecolor(color)
                body.set_edgecolor("black")
                body.set_alpha(0.55)
            violin["cmeans"].set_color("black")
        ax.text(
            0.01,
            0.92,
            lane_title,
            transform=ax.transAxes,
            ha="left",
            va="top",
            fontsize=10,
            bbox={"facecolor": "white", "edgecolor": "none", "alpha": 0.75, "pad": 2},
        )

    full_mean = metrics[(metrics["mode"] == "full") & (metrics["position"] == -1)]["macro_f1"]
    if not full_mean.empty:
        for ax in axes:
            ax.axhline(
                float(full_mean.iloc[0]),
                linestyle="--",
                color="black",
                linewidth=1.0,
                label="Full macro-F1",
            )

    critical = infer_critical_window(metrics, args.critical_threshold)
    start = critical["critical_start_position"]
    end = critical["critical_end_position"]
    if start != "" and end != "":
        shade_left = start + 0.5
        shade_right = end + 1.5
        for ax in axes:
            ax.axvspan(shade_left, shade_right, color="0.75", alpha=0.28, zorder=0)
            ax.axvline(shade_left, color="#b22222", linestyle="--", linewidth=1.2)
            ax.axvline(shade_right, color="#b22222", linestyle="--", linewidth=1.2)
        tail_ax.text(
            0.99,
            0.92,
            f"Critical window: {critical['critical_window']}",
            transform=tail_ax.transAxes,
            ha="right",
            va="top",
            fontsize=10,
            bbox={"facecolor": "white", "edgecolor": "#b22222", "alpha": 0.85, "pad": 3},
        )

    tail_ax.set_xlim(-1.6, args.window_size + 0.6)
    tail_ax.set_xticks([-1] + [pos + 1 for pos in positions])
    tail_ax.set_xticklabels(
        ["Full\nData"] + [axis_label(pos, args.window_size) for pos in positions],
        rotation=0,
        ha="center",
    )
    head_ax.set_xlabel(
        "P0: Client Hello | P1: Server Hello | P2/P4/P6: Client Req. | "
        "P3/P5/P7: Server Resp. | later ticks are abbreviated"
    )
    for ax in axes:
        ax.set_ylabel("Per-site F1")
        ax.set_ylim(0, 1.02)
        ax.grid(True, axis="y", linestyle=":", alpha=0.7)
    tail_ax.set_title(
        "14727250 Figure-2-style TimeSeries clump analysis\n"
        f"process_pcap().temporal_stats_per_flow(), model={args.model}"
    )
    tail_ax.legend(loc="lower right")
    fig.savefig(plots_dir / "figure2_timeseries_clumps.png", dpi=220)
    fig.savefig(plots_dir / "figure2_timeseries_clumps.pdf")
    plt.close(fig)


def write_report(
    args: argparse.Namespace,
    rows: list[Figure2Row],
    failures: list[ParseFailure],
    critical: dict[str, Any],
) -> None:
    report = [
        "# 14727250 TimeSeries Figure-2-style Result",
        "",
        "This run uses the original repository parser path:",
        "",
        "`process_pcap() -> FlowSession.temporal_stats_per_flow() -> TimeSeries clumps`",
        "",
        "The plot is Figure-2-style, not a numeric reproduction of the paper.",
        "The x-axis labels are protocol-stage-inspired names; without ground-truth protocol-stage annotations, they should be interpreted conservatively.",
        "",
        f"- parsed visits: {len(rows)}",
        f"- parse failures: {len(failures)}",
        f"- model: `{args.model}`",
        f"- flow selector: `{args.flow_selector}`",
        f"- sequence width: `{args.sequence_width}`",
        f"- window size: `{args.window_size}`",
        f"- critical threshold: `{args.critical_threshold}`",
        f"- inferred critical window: `{critical.get('critical_window', '')}`",
        "",
        "Outputs:",
        "",
        "- `features/timeseries_selected_flow_features.csv`",
        "- `metrics/figure2_metrics.csv`",
        "- `metrics/figure2_per_site_f1.csv`",
        "- `metrics/critical_window_summary.csv`",
        "- `plots/figure2_timeseries_clumps.png`",
        "- `plots/figure2_timeseries_clumps.pdf`",
    ]
    (args.out_dir / "README.md").write_text("\n".join(report), encoding="utf-8")


def main() -> None:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    features_path = args.features_cache or args.out_dir / "features" / "timeseries_selected_flow_features.csv"
    features_path.parent.mkdir(parents=True, exist_ok=True)

    if args.reuse_features:
        rows = df_to_rows(pd.read_csv(features_path))
        failures: list[ParseFailure] = []
    else:
        rows, failures = extract_rows(args)
        rows_to_df(rows).to_csv(features_path, index=False, encoding="utf-8-sig")
        write_errors(failures, args.out_dir / "errors.csv")

    if not rows:
        raise RuntimeError("No valid rows extracted.")

    counts = pd.Series([row.site for row in rows]).value_counts()
    keep_sites = set(counts[counts >= args.min_samples_per_site].index)
    eval_rows = [row for row in rows if row.site in keep_sites]
    if len(eval_rows) < len(rows):
        print(f"Filtered sites by min samples: {len(rows)} -> {len(eval_rows)} visits")

    labels, y, _groups, splits = make_cv(eval_rows, args.max_folds)
    metric_records = []
    per_site_frames = []
    masks = [("full", -1)] + [(mode, pos) for pos in range(args.window_size) for mode in ("tail", "head")]
    iterator = tqdm(masks, desc="Evaluating Figure-2 masks", unit="mask", disable=args.no_progress)
    for mode, position in iterator:
        metrics, per_site = evaluate_mask(eval_rows, mode, position, splits, labels, y, args)
        metric_records.append({"mode": mode, "position": position, **metrics})
        per_site_frames.append(per_site)

    metrics_df = pd.DataFrame(metric_records)
    per_site_df = pd.concat(per_site_frames, ignore_index=True)
    critical = infer_critical_window(metrics_df, args.critical_threshold)
    metrics_dir = args.out_dir / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=True)
    metrics_df.to_csv(metrics_dir / "figure2_metrics.csv", index=False, encoding="utf-8-sig")
    per_site_df.to_csv(metrics_dir / "figure2_per_site_f1.csv", index=False, encoding="utf-8-sig")
    pd.DataFrame([critical]).to_csv(
        metrics_dir / "critical_window_summary.csv",
        index=False,
        encoding="utf-8-sig",
    )
    write_violin(per_site_df, metrics_df, args)
    write_report(args, rows, failures, critical)
    print(f"Plot: {args.out_dir / 'plots' / 'figure2_timeseries_clumps.png'}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
