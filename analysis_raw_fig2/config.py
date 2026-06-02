from __future__ import annotations

import json
import logging
from pathlib import Path
import random
import subprocess
from typing import Any

import numpy as np


DEFAULT_FEATURE_NAMES = [
    "relative_timestamp",
    "duration",
    "length",
    "pkt_count",
    "direction",
]

DEFAULT_LOG_TRANSFORM = [
    "length",
    "pkt_count",
    "duration",
    "relative_timestamp",
]

PROCESSED_H123_ERROR = (
    "This script expects raw pcap files for protocol-level Figure-2-style "
    "analysis. Processed H123 features should use a separate feature-position "
    "ablation script."
)

RAW_PCAP_SUFFIXES = {".pcap", ".pcapng"}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def ensure_output_dirs(out_dir: Path) -> None:
    for child in [
        out_dir,
        out_dir / "cache",
        out_dir / "confusion_matrices",
        out_dir / "plots",
        out_dir / "splits",
        out_dir / "logs",
    ]:
        child.mkdir(parents=True, exist_ok=True)


def get_git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root(),
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


class WarningOnlyFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno == logging.WARNING


def setup_logging(out_dir: Path) -> logging.Logger:
    logger = logging.getLogger("analysis_raw_fig2")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    run_handler = logging.FileHandler(out_dir / "logs" / "run.log", encoding="utf-8")
    run_handler.setLevel(logging.INFO)
    run_handler.setFormatter(formatter)
    logger.addHandler(run_handler)

    warning_handler = logging.FileHandler(
        out_dir / "logs" / "warnings.log", encoding="utf-8"
    )
    warning_handler.setLevel(logging.WARNING)
    warning_handler.addFilter(WarningOnlyFilter())
    warning_handler.setFormatter(formatter)
    logger.addHandler(warning_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(stream_handler)
    return logger


def set_random_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)


def json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, np.integer):
        return int(value)
    if isinstance(value, np.floating):
        return float(value)
    if isinstance(value, np.ndarray):
        return value.tolist()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=json_default),
        encoding="utf-8",
    )
