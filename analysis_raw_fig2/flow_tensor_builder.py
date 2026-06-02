from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler, StandardScaler
from tqdm.auto import tqdm

from analysis_raw_fig2.config import DEFAULT_FEATURE_NAMES
from analysis_raw_fig2.pcap_loader import VisitParseResult


@dataclass
class VisitTensor:
    visit_id: str
    label: str
    pcap_path: str
    X_visit: np.ndarray
    flow_mask: np.ndarray
    event_mask: np.ndarray
    metadata: dict[str, Any]


def resolve_feature_names(feature_set: str) -> list[str]:
    if feature_set != "default":
        raise ValueError(
            "Only feature-set 'default' is implemented for raw Figure-2-style "
            "analysis. The default set is TimeSeries relative_timestamp, "
            "duration, length, pkt_count, direction."
        )
    return list(DEFAULT_FEATURE_NAMES)


def _first_present(row: pd.Series, names: Iterable[str]) -> float | None:
    for name in names:
        if name in row and pd.notna(row[name]):
            return float(row[name])
    return None


def _rank_flow_records(
    flow_static_df: pd.DataFrame,
    flow_temporal_df: pd.DataFrame,
    flow_rank_by: str,
) -> list[dict[str, Any]]:
    if "id" not in flow_temporal_df.columns:
        raise ValueError("flow_temporal_df must contain an 'id' flow identifier column.")

    static_by_id: dict[str, pd.Series] = {}
    if not flow_static_df.empty and "id" in flow_static_df.columns:
        for _, row in flow_static_df.iterrows():
            static_by_id[str(row["id"])] = row

    records: list[dict[str, Any]] = []
    for order, (flow_id, temporal_group) in enumerate(
        flow_temporal_df.groupby("id", sort=False)
    ):
        static_row = static_by_id.get(str(flow_id))
        total_length = float(pd.to_numeric(temporal_group.get("length"), errors="coerce").sum())
        total_packets = float(
            pd.to_numeric(temporal_group.get("pkt_count"), errors="coerce").sum()
        )
        packet_cnt = total_packets if total_packets > 0 else float(len(temporal_group))
        bytes_total = total_length
        start_time = float(order)

        if static_row is not None:
            direct_total = _first_present(static_row, ["bytes_total", "total_bytes"])
            if direct_total is not None:
                bytes_total = direct_total
            else:
                sent = _first_present(static_row, ["bytes_sent", "flow_bytes_sent"])
                received = _first_present(
                    static_row, ["bytes_received", "flow_bytes_received"]
                )
                if sent is not None and received is not None:
                    bytes_total = sent + received
            static_packet_cnt = _first_present(static_row, ["packet_cnt", "packets"])
            if static_packet_cnt is not None:
                packet_cnt = static_packet_cnt
            static_start = _first_present(static_row, ["start_time", "timestamp"])
            if static_start is not None:
                start_time = static_start

        records.append(
            {
                "flow_id": str(flow_id),
                "order": order,
                "bytes_total": bytes_total,
                "packet_cnt": packet_cnt,
                "event_count": int(len(temporal_group)),
                "start_time": start_time,
            }
        )

    if flow_rank_by == "bytes_total":
        return sorted(records, key=lambda item: (-item["bytes_total"], item["order"]))
    if flow_rank_by == "packet_cnt":
        return sorted(records, key=lambda item: (-item["packet_cnt"], item["order"]))
    if flow_rank_by == "start_time":
        return sorted(records, key=lambda item: (item["start_time"], item["order"]))
    raise ValueError("--flow-rank-by must be bytes_total, packet_cnt, or start_time.")


def build_visit_tensor(
    flow_static_df: pd.DataFrame,
    flow_temporal_df: pd.DataFrame,
    top_m_flows: int = 8,
    max_events: int = 64,
    flow_rank_by: str = "bytes_total",
    feature_names: list[str] | None = None,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[str, Any]]:
    feature_names = list(feature_names or DEFAULT_FEATURE_NAMES)
    missing = sorted(set(feature_names + ["id"]) - set(flow_temporal_df.columns))
    if missing:
        raise ValueError(f"flow_temporal_df is missing required columns: {missing}")
    if top_m_flows <= 0:
        raise ValueError("top_m_flows must be positive.")
    if max_events <= 0:
        raise ValueError("max_events must be positive.")

    ranked = _rank_flow_records(flow_static_df, flow_temporal_df, flow_rank_by)
    selected = ranked[:top_m_flows]
    groups = {
        str(flow_id): group.reset_index(drop=True)
        for flow_id, group in flow_temporal_df.groupby("id", sort=False)
    }

    F = len(feature_names)
    X_visit = np.zeros((top_m_flows, max_events, F), dtype=np.float32)
    flow_mask = np.zeros(top_m_flows, dtype=np.float32)
    event_mask = np.zeros((top_m_flows, max_events), dtype=np.float32)
    selected_flow_ids: list[str] = []
    selected_event_counts: list[int] = []

    for flow_pos, record in enumerate(selected):
        flow_id = record["flow_id"]
        group = groups[flow_id]
        values = group.loc[:, feature_names].apply(pd.to_numeric, errors="coerce")
        values = values.replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(
            dtype=np.float32
        )
        event_count = min(max_events, values.shape[0])
        if event_count == 0:
            continue
        X_visit[flow_pos, :event_count, :] = values[:event_count, :]
        flow_mask[flow_pos] = 1
        event_mask[flow_pos, :event_count] = 1
        selected_flow_ids.append(flow_id)
        selected_event_counts.append(int(values.shape[0]))

    metadata = {
        "num_flows_total": int(len(ranked)),
        "num_flows_selected": int(len(selected_flow_ids)),
        "selected_flow_ids": selected_flow_ids,
        "selected_event_counts": selected_event_counts,
        "feature_names": feature_names,
        "flow_rank_by": flow_rank_by,
    }
    return X_visit, flow_mask, event_mask, metadata


def build_visit_tensors(
    parsed_visits: Iterable[VisitParseResult],
    top_m_flows: int,
    max_events: int,
    flow_rank_by: str,
    feature_names: list[str],
    show_progress: bool = True,
) -> list[VisitTensor]:
    tensors: list[VisitTensor] = []
    parsed_list = list(parsed_visits)
    iterator = tqdm(
        parsed_list,
        total=len(parsed_list),
        desc="Building visit tensors",
        unit="visit",
        disable=not show_progress,
    )
    for parsed in iterator:
        X_visit, flow_mask, event_mask, tensor_metadata = build_visit_tensor(
            parsed.flow_static_df,
            parsed.flow_temporal_df,
            top_m_flows=top_m_flows,
            max_events=max_events,
            flow_rank_by=flow_rank_by,
            feature_names=feature_names,
        )
        metadata = dict(parsed.metadata)
        metadata.update(tensor_metadata)
        tensors.append(
            VisitTensor(
                visit_id=parsed.visit_id,
                label=parsed.label,
                pcap_path=parsed.pcap_path,
                X_visit=X_visit,
                flow_mask=flow_mask,
                event_mask=event_mask,
                metadata=metadata,
            )
        )
    return tensors


def stack_visit_tensors(
    tensors: list[VisitTensor],
) -> tuple[np.ndarray, np.ndarray, np.ndarray, pd.DataFrame]:
    if not tensors:
        raise ValueError("no visit tensors available")
    X = np.stack([item.X_visit for item in tensors], axis=0)
    flow_mask = np.stack([item.flow_mask for item in tensors], axis=0)
    event_mask = np.stack([item.event_mask for item in tensors], axis=0)

    rows = []
    for item in tensors:
        row = {
            "visit_id": item.visit_id,
            "label": item.label,
            "pcap_path": item.pcap_path,
        }
        for key, value in item.metadata.items():
            if key in row:
                continue
            if isinstance(value, (list, dict)):
                row[key] = json.dumps(value, ensure_ascii=False)
            else:
                row[key] = value
        rows.append(row)
    return X, flow_mask, event_mask, pd.DataFrame(rows)


def apply_log_transform(
    X: np.ndarray,
    feature_names: list[str],
    log_transform: list[str],
) -> np.ndarray:
    out = np.array(X, copy=True)
    requested = set(log_transform)
    for feature_idx, feature_name in enumerate(feature_names):
        if feature_name not in requested:
            continue
        values = out[..., feature_idx]
        out[..., feature_idx] = np.log1p(np.maximum(values, 0.0))
    return out


def flatten_for_baseline(X: np.ndarray) -> np.ndarray:
    if X.ndim != 4:
        raise ValueError(f"Expected X shape [N, M, K, F], got {X.shape}.")
    return X.reshape(X.shape[0], -1)


def make_scaler(name: str):
    if name == "none":
        return None
    if name == "standard":
        return StandardScaler()
    if name == "robust":
        return RobustScaler()
    raise ValueError("--scaler must be none, standard, or robust.")


def transform_train_test(
    X_train: np.ndarray,
    X_test: np.ndarray,
    feature_names: list[str],
    log_transform: list[str],
    scaler_name: str,
) -> tuple[np.ndarray, np.ndarray]:
    X_train_work = apply_log_transform(X_train, feature_names, log_transform)
    X_test_work = apply_log_transform(X_test, feature_names, log_transform)
    X_train_flat = flatten_for_baseline(X_train_work)
    X_test_flat = flatten_for_baseline(X_test_work)

    scaler = make_scaler(scaler_name)
    if scaler is None:
        return X_train_flat, X_test_flat
    X_train_scaled = scaler.fit_transform(X_train_flat)
    X_test_scaled = scaler.transform(X_test_flat)
    return X_train_scaled, X_test_scaled


def save_tensor_cache(
    out_dir: Path,
    X: np.ndarray,
    flow_mask: np.ndarray,
    event_mask: np.ndarray,
    metadata_df: pd.DataFrame,
) -> None:
    cache_dir = out_dir / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        cache_dir / "visit_tensors.npz",
        X=X,
        flow_mask=flow_mask,
        event_mask=event_mask,
    )
    metadata_df.to_csv(cache_dir / "visit_metadata.csv", index=False)


def load_tensor_cache(out_dir: Path) -> tuple[np.ndarray, np.ndarray, np.ndarray, pd.DataFrame]:
    cache_dir = out_dir / "cache"
    tensor_path = cache_dir / "visit_tensors.npz"
    metadata_path = cache_dir / "visit_metadata.csv"
    if not tensor_path.exists() or not metadata_path.exists():
        raise FileNotFoundError("cache files are missing; rerun without --use-cache")
    with np.load(tensor_path, allow_pickle=False) as data:
        X = data["X"]
        flow_mask = data["flow_mask"]
        event_mask = data["event_mask"]
    metadata_df = pd.read_csv(metadata_path)
    return X, flow_mask, event_mask, metadata_df
