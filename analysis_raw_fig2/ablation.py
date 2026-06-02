from __future__ import annotations

import numpy as np


def _validate_input(X: np.ndarray, k: int) -> None:
    if X.ndim != 4:
        raise ValueError(f"Expected X shape [N, M, K, F], got {X.shape}.")
    if k <= 0:
        raise ValueError("k must be positive for Fhead/Ftail ablation.")


def apply_fhead(X: np.ndarray, k: int) -> np.ndarray:
    """Keep only the first k temporal events in each flow."""

    _validate_input(X, k)
    out = np.array(X, copy=True)
    K = X.shape[2]
    if k >= K:
        return out
    out[:, :, k:, :] = 0
    return out


def apply_ftail(X: np.ndarray, k: int, tail_shift_left: bool = False) -> np.ndarray:
    """Remove or mask the first k temporal events in each flow."""

    _validate_input(X, k)
    out = np.array(X, copy=True)
    K = X.shape[2]
    if k >= K:
        out[:, :, :, :] = 0
        return out

    if tail_shift_left:
        shifted = np.zeros_like(out)
        shifted[:, :, : K - k, :] = out[:, :, k:, :]
        return shifted

    out[:, :, :k, :] = 0
    return out
