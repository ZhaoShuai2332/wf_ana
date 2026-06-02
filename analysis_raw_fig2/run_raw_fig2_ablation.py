from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any

import numpy as np
import pandas as pd

from analysis_raw_fig2.ablation import apply_fhead, apply_ftail
from analysis_raw_fig2.config import (
    DEFAULT_LOG_TRANSFORM,
    PROCESSED_H123_ERROR,
    ensure_output_dirs,
    get_git_commit,
    set_random_seed,
    setup_logging,
    write_json,
)
from analysis_raw_fig2.evaluator import (
    build_split,
    evaluate_once,
    metrics_to_long_rows,
    prepare_group_split_column,
    summarize_results,
    write_confusion_matrix,
    write_split_files,
)
from analysis_raw_fig2.flow_tensor_builder import (
    build_visit_tensors,
    load_tensor_cache,
    resolve_feature_names,
    save_tensor_cache,
    stack_visit_tensors,
)
from analysis_raw_fig2.models import OptionalModelUnavailable, SUPPORTED_MODELS
from analysis_raw_fig2.pcap_loader import (
    load_manifest,
    parse_visits,
    scan_pcap_dir,
    write_errors,
)
from analysis_raw_fig2.plotter import plot_default_metrics


RESULT_COLUMNS = [
    "seed",
    "ablation_type",
    "k",
    "model",
    "metric",
    "value",
    "train_size",
    "test_size",
    "num_classes",
    "top_m_flows",
    "max_events",
    "feature_names",
    "scaler",
    "log_transform",
    "tail_shift_left",
]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Raw-PCAP protocol-level Figure-2-style Fhead/Ftail ablation. "
            "This script expects raw pcap files, not processed H123 CSV features."
        )
    )
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--manifest", type=Path, help="CSV with visit_id, pcap_path, label.")
    inputs.add_argument("--pcap-dir", type=Path, help="Directory containing raw .pcap/.pcapng files.")
    parser.add_argument("--label-col", default="label", help="Label column in manifest CSV.")
    parser.add_argument(
        "--label-from",
        choices=("parent_dir", "filename"),
        default="parent_dir",
        help="Directory scan label source.",
    )
    parser.add_argument("--out-dir", type=Path, default=Path("outputs/raw_fig2_ablation"))
    parser.add_argument("--dataset-name", default="raw_pcap")

    parser.add_argument("--top-m-flows", type=int, default=8)
    parser.add_argument("--max-events", type=int, default=64)
    parser.add_argument(
        "--flow-rank-by",
        choices=("bytes_total", "packet_cnt", "start_time"),
        default="bytes_total",
    )
    parser.add_argument("--feature-set", choices=("default",), default="default")

    parser.add_argument(
        "--model",
        choices=SUPPORTED_MODELS,
        default="random_forest",
        help="Traditional ML baseline model.",
    )
    parser.add_argument("--seed", type=int, default=0, help="Deprecated alias; use --seeds.")
    parser.add_argument("--seeds", type=int, nargs="+", default=None)
    parser.add_argument("--n-estimators", type=int, default=300)
    parser.add_argument("--max-depth", default="none")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--group-split-by", default=None, help="Optional metadata group column, e.g. content_id or url.")

    parser.add_argument(
        "--k-list",
        type=int,
        nargs="+",
        default=[1, 2, 3, 4, 5, 8, 16, 32, 64],
    )
    parser.add_argument("--tail-shift-left", action="store_true")
    parser.add_argument(
        "--scaler",
        choices=("standard", "robust", "none"),
        default="standard",
    )
    parser.add_argument(
        "--log-transform",
        nargs="*",
        default=list(DEFAULT_LOG_TRANSFORM),
        help="Feature names to transform with log1p before scaler fit.",
    )

    parser.add_argument("--use-cache", action="store_true")
    parser.add_argument("--overwrite-cache", action="store_true")
    parser.add_argument(
        "--num-workers",
        type=int,
        default=0,
        help=(
            "Number of parallel pcap parsing workers. "
            "Use 0 for a conservative auto setting; use 1 for serial parsing."
        ),
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable tqdm progress bars during pcap parsing and tensor construction.",
    )
    parser.add_argument("--workspace", type=Path, default=None)

    parser.add_argument("--no-buffer-tcp", action="store_true")
    parser.add_argument("--no-dns", action="store_true")
    parser.add_argument("--with-certificates", action="store_true")
    parser.add_argument(
        "--allow-sensitive-metadata-output",
        action="store_true",
        help="Allow raw URL metadata in split/cache CSVs. Default writes only url_sha256.",
    )
    return parser.parse_args(argv)


def _parse_max_depth(value: str) -> int | None:
    if str(value).lower() in {"none", "null", ""}:
        return None
    parsed = int(value)
    if parsed <= 0:
        raise ValueError("--max-depth must be positive or none.")
    return parsed


def _resolve_num_workers(requested_workers: int, num_visits: int) -> int:
    if requested_workers < 0:
        raise ValueError("--num-workers must be >= 0.")
    if requested_workers == 0:
        cpu_count = os.cpu_count() or 1
        # Each worker launches TShark and can use substantial memory. Keep the
        # automatic setting conservative; users can still request more.
        auto_workers = max(1, min(4, cpu_count - 1 if cpu_count > 1 else 1))
        return min(auto_workers, max(1, num_visits))
    return min(requested_workers, max(1, num_visits))


def _sanitize_metadata_for_output(
    metadata_df: pd.DataFrame,
    allow_sensitive_metadata_output: bool,
) -> pd.DataFrame:
    out = metadata_df.copy()
    if "url" in out.columns:
        from analysis_raw_fig2.evaluator import sha256_text

        if "url_sha256" not in out.columns:
            out["url_sha256"] = out["url"].map(sha256_text)
        if not allow_sensitive_metadata_output:
            out = out.drop(columns=["url"])
    return out


def _selected_event_counts(metadata_df: pd.DataFrame) -> list[int]:
    counts: list[int] = []
    if "selected_event_counts" not in metadata_df.columns:
        return counts
    for raw_value in metadata_df["selected_event_counts"].dropna():
        if isinstance(raw_value, str):
            try:
                value = json.loads(raw_value)
            except json.JSONDecodeError:
                continue
        else:
            value = raw_value
        if isinstance(value, list):
            counts.extend(int(item) for item in value)
    return counts


def _write_dataset_summary(
    out_dir: Path,
    metadata_df: pd.DataFrame,
    X: np.ndarray,
    feature_names: list[str],
    flow_rank_by: str,
    num_parsed_failed: int,
) -> None:
    event_counts = _selected_event_counts(metadata_df)
    flow_counts = (
        pd.to_numeric(metadata_df.get("num_flows_total"), errors="coerce")
        if "num_flows_total" in metadata_df.columns
        else pd.Series(dtype=float)
    )
    summary = {
        "num_visits": int(len(metadata_df)),
        "num_classes": int(metadata_df["label"].nunique()),
        "class_distribution": metadata_df["label"].astype(str).value_counts().to_dict(),
        "num_parsed_success": int(len(metadata_df)),
        "num_parsed_failed": int(num_parsed_failed),
        "top_m_flows": int(X.shape[1]),
        "max_events": int(X.shape[2]),
        "feature_names": feature_names,
        "flow_rank_by": flow_rank_by,
        "mean_num_flows_per_visit": (
            float(flow_counts.mean()) if not flow_counts.empty else None
        ),
        "mean_num_events_per_flow": (
            float(np.mean(event_counts)) if event_counts else None
        ),
    }
    write_json(out_dir / "dataset_summary.json", summary)


def _save_config(args: argparse.Namespace, out_dir: Path) -> None:
    payload: dict[str, Any] = {
        "args": vars(args),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": get_git_commit(),
    }
    write_json(out_dir / "config.json", payload)


def _load_or_build_cache(
    args: argparse.Namespace,
    feature_names: list[str],
    logger,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, pd.DataFrame, int]:
    cache_tensor = args.out_dir / "cache" / "visit_tensors.npz"
    cache_metadata = args.out_dir / "cache" / "visit_metadata.csv"
    if args.use_cache and not args.overwrite_cache:
        logger.info("Loading visit-level tensor cache.")
        X, flow_mask, event_mask, metadata_df = load_tensor_cache(args.out_dir)
        return X, flow_mask, event_mask, metadata_df, 0

    if args.manifest:
        visits = load_manifest(args.manifest, label_col=args.label_col)
    else:
        visits = scan_pcap_dir(args.pcap_dir, label_from=args.label_from)

    logger.info("Input visits: %d", len(visits))
    resolved_workers = _resolve_num_workers(args.num_workers, len(visits))
    logger.info("Using pcap parse workers: %d", resolved_workers)
    workspace = args.workspace if args.workspace is not None else args.out_dir / "workspace"
    parsed, failures = parse_visits(
        visits,
        buffer_tcp=not args.no_buffer_tcp,
        with_dns=not args.no_dns,
        with_certificates=args.with_certificates,
        workspace=workspace,
        num_workers=resolved_workers,
        show_progress=not args.no_progress,
    )
    write_errors(failures, args.out_dir / "errors.csv")
    logger.info("Parsed success=%d failed=%d", len(parsed), len(failures))
    if failures:
        logger.warning("PCAP parse failures were written to %s", args.out_dir / "errors.csv")
    if not parsed:
        raise RuntimeError("No valid raw pcap visits were parsed.")

    tensors = build_visit_tensors(
        parsed,
        top_m_flows=args.top_m_flows,
        max_events=args.max_events,
        flow_rank_by=args.flow_rank_by,
        feature_names=feature_names,
        show_progress=not args.no_progress,
    )
    X, flow_mask, event_mask, metadata_df = stack_visit_tensors(tensors)
    metadata_df = _sanitize_metadata_for_output(
        metadata_df,
        allow_sensitive_metadata_output=args.allow_sensitive_metadata_output,
    )
    if args.overwrite_cache or not (cache_tensor.exists() and cache_metadata.exists()):
        save_tensor_cache(args.out_dir, X, flow_mask, event_mask, metadata_df)
        logger.info("Saved visit-level tensor cache.")
    return X, flow_mask, event_mask, metadata_df, len(failures)


def _evaluate_all(
    args: argparse.Namespace,
    X: np.ndarray,
    metadata_df: pd.DataFrame,
    feature_names: list[str],
    logger,
) -> pd.DataFrame:
    max_depth = _parse_max_depth(args.max_depth)
    seeds = args.seeds if args.seeds is not None else [args.seed]
    labels = metadata_df["label"].astype(str).to_numpy()
    group_col = prepare_group_split_column(metadata_df, args.group_split_by)
    if group_col:
        logger.info("Using group split column: %s", group_col)

    all_rows: list[dict[str, Any]] = []
    num_classes = int(metadata_df["label"].nunique())
    for seed in seeds:
        set_random_seed(seed)
        split = build_split(
            metadata_df,
            seed=seed,
            test_size=args.test_size,
            group_col=group_col,
        )
        write_split_files(
            metadata_df,
            split,
            args.out_dir / "splits",
            group_col=group_col,
            allow_sensitive_metadata_output=args.allow_sensitive_metadata_output,
        )
        logger.info(
            "Seed %d split: train=%d test=%d",
            seed,
            len(split.train_idx),
            len(split.test_idx),
        )

        evaluations = [("full", -1, X)]
        for k in args.k_list:
            if k <= 0:
                raise ValueError("all --k-list values must be positive.")
            if k > X.shape[2]:
                logger.warning(
                    "k=%d exceeds max_events=%d; Fhead is full and Ftail is all-zero.",
                    k,
                    X.shape[2],
                )
            evaluations.append(("fhead", k, apply_fhead(X, k)))
            evaluations.append(("ftail", k, apply_ftail(X, k, args.tail_shift_left)))

        for ablation_type, k, X_eval in evaluations:
            if ablation_type != "full" and np.count_nonzero(X_eval) == 0:
                logger.warning("%s(k=%d) produced an all-zero input.", ablation_type, k)
            try:
                result = evaluate_once(
                    X_eval,
                    labels=labels,
                    train_idx=split.train_idx,
                    test_idx=split.test_idx,
                    feature_names=feature_names,
                    log_transform=args.log_transform,
                    scaler_name=args.scaler,
                    model_name=args.model,
                    seed=seed,
                    n_estimators=args.n_estimators,
                    max_depth=max_depth,
                )
            except OptionalModelUnavailable as exc:
                logger.warning("%s", exc)
                return pd.DataFrame(all_rows, columns=RESULT_COLUMNS)

            all_rows.extend(
                metrics_to_long_rows(
                    result.metrics,
                    seed=seed,
                    ablation_type=ablation_type,
                    k=k,
                    model_name=args.model,
                    train_size=len(split.train_idx),
                    test_size=len(split.test_idx),
                    num_classes=num_classes,
                    top_m_flows=args.top_m_flows,
                    max_events=args.max_events,
                    feature_names=feature_names,
                    scaler_name=args.scaler,
                    log_transform=args.log_transform,
                    tail_shift_left=args.tail_shift_left,
                )
            )
            if ablation_type == "full":
                confusion_name = f"confusion_seed_{seed}_full.csv"
            else:
                confusion_name = f"confusion_seed_{seed}_{ablation_type}_k_{k}.csv"
            write_confusion_matrix(
                result.confusion,
                args.out_dir / "confusion_matrices",
                confusion_name,
            )

    return pd.DataFrame(all_rows, columns=RESULT_COLUMNS)


def run(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    ensure_output_dirs(args.out_dir)
    logger = setup_logging(args.out_dir)
    _save_config(args, args.out_dir)

    feature_names = resolve_feature_names(args.feature_set)
    X, _flow_mask, _event_mask, metadata_df, num_failed = _load_or_build_cache(
        args,
        feature_names=feature_names,
        logger=logger,
    )
    metadata_df = _sanitize_metadata_for_output(
        metadata_df,
        allow_sensitive_metadata_output=args.allow_sensitive_metadata_output,
    )
    if "label" not in metadata_df.columns or "visit_id" not in metadata_df.columns:
        raise ValueError("visit metadata cache must contain visit_id and label columns.")
    _write_dataset_summary(
        args.out_dir,
        metadata_df,
        X,
        feature_names=feature_names,
        flow_rank_by=args.flow_rank_by,
        num_parsed_failed=num_failed,
    )
    logger.info(
        "Visit tensor shape: N=%d M=%d K=%d F=%d",
        X.shape[0],
        X.shape[1],
        X.shape[2],
        X.shape[3],
    )

    results_long = _evaluate_all(args, X, metadata_df, feature_names, logger)
    results_long.to_csv(args.out_dir / "results_long.csv", index=False)
    results_summary = summarize_results(results_long)
    results_summary.to_csv(args.out_dir / "results_summary.csv", index=False)
    plot_paths = plot_default_metrics(
        results_long,
        model_name=args.model,
        out_dir=args.out_dir / "plots",
        dataset_name=args.dataset_name,
        top_m_flows=args.top_m_flows,
        max_events=args.max_events,
    )
    logger.info("Wrote results_long.csv and results_summary.csv")
    for path in plot_paths:
        logger.info("Wrote plot: %s", path)


def main() -> None:
    try:
        run()
    except ValueError as exc:
        if str(exc) == PROCESSED_H123_ERROR:
            print(PROCESSED_H123_ERROR, file=sys.stderr)
            raise SystemExit(2) from exc
        raise


if __name__ == "__main__":
    main()
