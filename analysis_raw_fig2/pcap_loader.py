from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
import re
import sys
import traceback
from typing import Any, Iterable

import pandas as pd
from tqdm.auto import tqdm

from analysis_raw_fig2.config import (
    PROCESSED_H123_ERROR,
    RAW_PCAP_SUFFIXES,
    repo_root,
)


REQUIRED_MANIFEST_COLUMNS = {"visit_id", "pcap_path"}


@dataclass
class VisitInput:
    visit_id: str
    pcap_path: Path
    label: str
    metadata: dict[str, Any]


@dataclass
class VisitParseResult:
    visit_id: str
    label: str
    pcap_path: str
    flow_static_df: pd.DataFrame
    flow_temporal_df: pd.DataFrame
    metadata: dict[str, Any]


@dataclass
class ParseFailure:
    visit_id: str
    pcap_path: str
    error_type: str
    error_message: str
    traceback_short: str


def _looks_like_processed_csv(path: Path) -> bool:
    if path.suffix.lower() != ".csv":
        return False
    lowered_parts = [part.lower() for part in path.parts]
    return (
        "features_h123" in lowered_parts
        or bool(re.match(r"result_.*\.csv$", path.name.lower()))
    )


def _assert_raw_pcap_path(path: Path) -> None:
    if path.suffix.lower() not in RAW_PCAP_SUFFIXES:
        raise ValueError(PROCESSED_H123_ERROR)


def _format_traceback(exc: BaseException) -> str:
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__, limit=4))


def _import_process_pcap():
    def silence_crawler_debug_logger() -> None:
        try:
            import tls_crawler.logger as crawler_log

            crawler_log.remove()
        except BaseException:
            pass

    try:
        from tls_crawler.processing import process_pcap

        silence_crawler_debug_logger()
        return process_pcap
    except ImportError:
        crawler_src = repo_root() / "crawlers" / "src"
        if crawler_src.exists() and str(crawler_src) not in sys.path:
            sys.path.insert(0, str(crawler_src))
        try:
            from tls_crawler.processing import process_pcap

            silence_crawler_debug_logger()
            return process_pcap
        except ImportError as exc:
            raise ImportError(
                "Could not import tls_crawler.processing.process_pcap. "
                "Install the crawlers package and project dependencies, or set "
                f"PYTHONPATH to include {crawler_src}. Original import error: {exc}"
            ) from exc


def load_manifest(manifest_path: Path, label_col: str = "label") -> list[VisitInput]:
    manifest_path = Path(manifest_path)
    if _looks_like_processed_csv(manifest_path):
        raise ValueError(PROCESSED_H123_ERROR)
    if manifest_path.suffix.lower() != ".csv":
        raise ValueError("--manifest must point to a CSV manifest with raw pcap paths.")

    df = pd.read_csv(manifest_path)
    required = set(REQUIRED_MANIFEST_COLUMNS) | {label_col}
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(PROCESSED_H123_ERROR)

    visits: list[VisitInput] = []
    base_dir = manifest_path.parent
    for row in df.to_dict(orient="records"):
        raw_pcap_path = Path(str(row["pcap_path"]))
        pcap_path = raw_pcap_path if raw_pcap_path.is_absolute() else base_dir / raw_pcap_path
        _assert_raw_pcap_path(pcap_path)
        metadata = {key: value for key, value in row.items() if key != label_col}
        visits.append(
            VisitInput(
                visit_id=str(row["visit_id"]),
                pcap_path=pcap_path,
                label=str(row[label_col]),
                metadata=metadata,
            )
        )
    return visits


def _label_from_filename(path: Path) -> str:
    stem = path.stem
    match = re.match(r"(.+?)_[0-9]+$", stem)
    if match:
        return match.group(1)
    return stem.split("_")[0]


def scan_pcap_dir(pcap_dir: Path, label_from: str) -> list[VisitInput]:
    pcap_dir = Path(pcap_dir)
    if pcap_dir.is_file() and pcap_dir.suffix.lower() == ".csv":
        raise ValueError(PROCESSED_H123_ERROR)
    if not pcap_dir.exists():
        raise FileNotFoundError(f"pcap directory does not exist: {pcap_dir}")
    if not pcap_dir.is_dir():
        _assert_raw_pcap_path(pcap_dir)
        paths = [pcap_dir]
    else:
        paths = sorted(
            path
            for path in pcap_dir.rglob("*")
            if path.is_file() and path.suffix.lower() in RAW_PCAP_SUFFIXES
        )

    if not paths:
        csv_files = list(pcap_dir.rglob("*.csv")) if pcap_dir.is_dir() else []
        if csv_files:
            raise ValueError(PROCESSED_H123_ERROR)
        raise FileNotFoundError(f"no raw pcap files found under: {pcap_dir}")

    visits: list[VisitInput] = []
    for path in paths:
        if label_from == "parent_dir":
            label = path.parent.name
        elif label_from == "filename":
            label = _label_from_filename(path)
        else:
            raise ValueError("--label-from must be parent_dir or filename.")
        try:
            visit_id = str(path.relative_to(pcap_dir).with_suffix(""))
        except ValueError:
            visit_id = path.stem
        visits.append(
            VisitInput(
                visit_id=visit_id.replace("\\", "/"),
                pcap_path=path,
                label=label,
                metadata={"visit_id": visit_id, "pcap_path": str(path)},
            )
        )
    return visits


def parse_one_pcap(
    pcap_path: Path,
    buffer_tcp: bool = True,
    with_dns: bool = True,
    with_certificates: bool = False,
    workspace: Path = Path("workspace"),
) -> tuple[pd.DataFrame, pd.DataFrame]:
    process_pcap = _import_process_pcap()
    pcap_path = Path(pcap_path)
    _assert_raw_pcap_path(pcap_path)

    session = process_pcap(
        pcap_path,
        workspace=workspace,
        with_certificates=with_certificates,
        with_dns=with_dns,
        buffer_tcp=buffer_tcp,
    )
    flow_static_df, flow_temporal_df = session.temporal_stats_per_flow()
    return flow_static_df, flow_temporal_df


def parse_visit(
    visit: VisitInput,
    buffer_tcp: bool = True,
    with_dns: bool = True,
    with_certificates: bool = False,
    workspace: Path = Path("workspace"),
) -> tuple[VisitParseResult | None, ParseFailure | None]:
    try:
        flow_static_df, flow_temporal_df = parse_one_pcap(
            visit.pcap_path,
            buffer_tcp=buffer_tcp,
            with_dns=with_dns,
            with_certificates=with_certificates,
            workspace=workspace,
        )
        if flow_static_df.empty or flow_temporal_df.empty:
            raise RuntimeError("pcap produced no valid flow temporal data")
        result = VisitParseResult(
            visit_id=visit.visit_id,
            label=visit.label,
            pcap_path=str(visit.pcap_path),
            flow_static_df=flow_static_df,
            flow_temporal_df=flow_temporal_df,
            metadata=dict(visit.metadata),
        )
        return result, None
    except BaseException as exc:
        failure = ParseFailure(
            visit_id=visit.visit_id,
            pcap_path=str(visit.pcap_path),
            error_type=type(exc).__name__,
            error_message=str(exc),
            traceback_short=_format_traceback(exc),
        )
        return None, failure


def parse_visits(
    visits: Iterable[VisitInput],
    buffer_tcp: bool = True,
    with_dns: bool = True,
    with_certificates: bool = False,
    workspace: Path = Path("workspace"),
    num_workers: int = 1,
    show_progress: bool = True,
) -> tuple[list[VisitParseResult], list[ParseFailure]]:
    visit_list = list(visits)
    if num_workers <= 1:
        results: list[VisitParseResult] = []
        failures: list[ParseFailure] = []
        iterator = tqdm(
            visit_list,
            total=len(visit_list),
            desc="Parsing raw pcaps",
            unit="visit",
            disable=not show_progress,
        )
        for visit in iterator:
            result, failure = parse_visit(
                visit,
                buffer_tcp=buffer_tcp,
                with_dns=with_dns,
                with_certificates=with_certificates,
                workspace=workspace,
            )
            if result is not None:
                results.append(result)
            if failure is not None:
                failures.append(failure)
        return results, failures

    results = []
    failures = []
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = {
            executor.submit(
                parse_visit,
                visit,
                buffer_tcp,
                with_dns,
                with_certificates,
                workspace,
            ): visit
            for visit in visit_list
        }
        iterator = tqdm(
            as_completed(futures),
            total=len(futures),
            desc="Parsing raw pcaps",
            unit="visit",
            disable=not show_progress,
        )
        for future in iterator:
            result, failure = future.result()
            if result is not None:
                results.append(result)
            if failure is not None:
                failures.append(failure)
    results.sort(key=lambda item: item.visit_id)
    failures.sort(key=lambda item: item.visit_id)
    return results, failures


def write_errors(errors: list[ParseFailure], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [error.__dict__ for error in errors]
    pd.DataFrame(
        rows,
        columns=[
            "visit_id",
            "pcap_path",
            "error_type",
            "error_message",
            "traceback_short",
        ],
    ).to_csv(path, index=False)
