"""Bounded retries for transient LLM failures.

Retries are deliberately narrow: rate limits, server faults, timeouts, and
connection resets. Authentication, validation, and schema errors fail fast and
fall back to the deterministic path with an honest outcome.
"""

from __future__ import annotations

import random
import time
from typing import Any, Callable, Optional, TypeVar

import config

T = TypeVar("T")

_TRANSIENT_STATUSES = frozenset({408, 409, 425, 429, 500, 502, 503, 504})
_TRANSIENT_NAMES = frozenset({
    "APIConnectionError",
    "APITimeoutError",
    "ConnectError",
    "ConnectionError",
    "ConnectionResetError",
    "InternalServerError",
    "RateLimitError",
    "ReadTimeout",
    "ServiceUnavailableError",
    "Timeout",
    "TimeoutError",
})


def _status_code(exc: BaseException) -> Optional[int]:
    for candidate in (
        getattr(exc, "status_code", None),
        getattr(getattr(exc, "response", None), "status_code", None),
        getattr(exc, "code", None),
    ):
        try:
            if candidate is not None:
                return int(candidate)
        except (TypeError, ValueError):
            continue
    return None


def is_transient(exc: BaseException) -> bool:
    status = _status_code(exc)
    if status is not None:
        return status in _TRANSIENT_STATUSES
    for klass in type(exc).__mro__:
        if klass.__name__ in _TRANSIENT_NAMES:
            return True
    return isinstance(exc, (TimeoutError, ConnectionError, OSError)) and not isinstance(exc, (ValueError, TypeError))


def invoke_with_retry(
    fn: Callable[[], T],
    *,
    attempts: Optional[int] = None,
    base_delay: Optional[float] = None,
    max_delay: float = 20.0,
    sleep: Callable[[float], Any] = time.sleep,
) -> T:
    """Run ``fn`` with exponential backoff for transient errors only.

    Raises the final exception unchanged so callers can fall back explicitly.
    """
    total = attempts or config.LLM_MAX_ATTEMPTS
    delay = base_delay if base_delay is not None else config.LLM_BACKOFF_BASE_SECONDS
    total = max(1, int(total))
    delay = max(0.0, float(delay))
    last: Optional[BaseException] = None
    for index in range(total):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - re-raised or deliberately classified
            last = exc
            if index >= total - 1 or not is_transient(exc):
                raise
            wait = min(max_delay, delay * (2 ** index)) + random.uniform(0, 0.25)
            try:
                sleep(wait)
            except Exception:
                raise exc
    if last is not None:
        raise last
    raise RuntimeError("retry helper exhausted without an exception")
