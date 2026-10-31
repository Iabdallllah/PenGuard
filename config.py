"""Centralized, typed-ish configuration for the Mirsad/PenGuard control plane.

All security-relevant environment reads live here so deployment behavior is
auditable in one place. Nothing here logs secret values.
"""

from __future__ import annotations

import os
from typing import List, Optional


VERSION = os.getenv("PENGUARD_VERSION", "2.5.0")

# The old hard-coded credential is treated as compromised forever.
_LEGACY_DEFAULT_KEYS = frozenset({"penguard-dev-token-2026"})
# Local-development fallback only. Never used when PENGUARD_ENV=production or
# when PENGUARD_DEMO=1; production always requires a real rotated key.
DEVELOPMENT_FALLBACK_KEY = "dev-local-penguard-key-change-me"


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name).lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on", "y")


def _env_int(name: str, default: Optional[int]) -> Optional[int]:
    raw = _env(name)
    if not raw:
        return default
    try:
        value = int(raw)
        return value if value > 0 else default
    except ValueError:
        return default


def _env_float(name: str, default: Optional[float]) -> Optional[float]:
    raw = _env(name)
    if not raw:
        return default
    try:
        value = float(raw)
        return value if value > 0 else default
    except ValueError:
        return default


def _split_csv(raw: str) -> List[str]:
    return [item.strip().rstrip("/") for item in raw.split(",") if item.strip()]


# ── Environment / demo mode ─────────────────────────────────────────────────
ENV_NAME = _env("PENGUARD_ENV").lower()
DEMO_MODE = _env_bool("PENGUARD_DEMO", False)
_DEPLOYED = bool(_env("RAILWAY_ENVIRONMENT") or _env("RAILWAY_PROJECT_ID") or _env("VERCEL"))
PRODUCTION = (ENV_NAME in ("production", "prod")) or (not ENV_NAME and _DEPLOYED)
MODE = "production" if PRODUCTION else "development"

# ── Authentication ──────────────────────────────────────────────────────────
_API_KEY_ENV = _env("PENGUARD_API_KEY")
if _API_KEY_ENV and _API_KEY_ENV in _LEGACY_DEFAULT_KEYS:
    raise RuntimeError(
        "PENGUARD_API_KEY is still the compromised development default. "
        "Rotate it before starting the service."
    )
API_KEY: Optional[str] = _API_KEY_ENV or (
    None if (PRODUCTION or DEMO_MODE) else DEVELOPMENT_FALLBACK_KEY
)
API_KEY_HEADER = "X-API-Key"
# Mutations are protected whenever a key is configured. Demo mode may disable
# auth; production always requires a real rotated key (validated at startup).
AUTH_ENABLED = bool(API_KEY) and not (DEMO_MODE and not _API_KEY_ENV)
READ_AUTH_REQUIRED = bool(PRODUCTION and AUTH_ENABLED and not DEMO_MODE)
AUTH_MODE = "demo" if DEMO_MODE else ("key" if AUTH_ENABLED else "open-development")


def validate_startup_config() -> List[str]:
    """Fail closed on unsafe production auth; return non-fatal warnings.

    Called from FastAPI startup. Tests can call it directly with a patched
    environment without importing the app under a production environment.
    """
    warnings: List[str] = []
    if PRODUCTION and not DEMO_MODE and not _API_KEY_ENV:
        raise RuntimeError(
            "Production requires PENGUARD_API_KEY. Refusing to start with open "
            "mutating endpoints. Set PENGUARD_DEMO=1 only for an intentional public demo."
        )
    if _API_KEY_ENV and len(_API_KEY_ENV) < 16 and PRODUCTION:
        raise RuntimeError("Production PENGUARD_API_KEY must be at least 16 characters.")
    if PRODUCTION and DEMO_MODE and not _API_KEY_ENV:
        warnings.append("Production is running in explicit demo mode without an API key.")
    if AUTH_ENABLED and not READ_AUTH_REQUIRED and PRODUCTION:
        warnings.append("Sensitive reads are open because PENGUARD_DEMO=1.")
    return warnings


# ── CORS ────────────────────────────────────────────────────────────────────
_RAW_ORIGINS = _env("PENGUARD_ALLOWED_ORIGINS")
if _RAW_ORIGINS:
    ALLOWED_ORIGINS = _split_csv(_RAW_ORIGINS)
elif PRODUCTION:
    # Same-origin dashboard traffic goes through the server-side BFF and needs
    # no CORS exception. Cross-origin use must be explicit.
    ALLOWED_ORIGINS = []
else:
    ALLOWED_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]

# ── Target / sandbox ────────────────────────────────────────────────────────
TARGET_URL = _env("TARGET_URL")
TARGET_PORT = _env("TARGET_PORT", "8001")
SANDBOX_DEFAULT_URL = (TARGET_URL.rstrip("/") if TARGET_URL else f"http://127.0.0.1:{TARGET_PORT}")
ALLOW_PRIVATE_TARGETS = _env_bool("PENGUARD_ALLOW_PRIVATE_TARGETS", False)
ALLOW_NONSTANDARD_PORTS = _env_bool("PENGUARD_ALLOW_NONSTANDARD_PORTS", False)
TARGET_DNS_TIMEOUT_SECONDS = _env_float("PENGUARD_TARGET_DNS_TIMEOUT_SECONDS", 3.0) or 3.0

# ── Execution reliability / budget ──────────────────────────────────────────
EPISODE_TIMEOUT_SECONDS = _env_float("PENGUARD_EPISODE_TIMEOUT_SECONDS", 300.0) or 300.0
LLM_TIMEOUT_SECONDS = _env_float("PENGUARD_LLM_TIMEOUT_SECONDS", 30.0) or 30.0
LLM_MAX_ATTEMPTS = _env_int("PENGUARD_LLM_MAX_ATTEMPTS", 3) or 3
LLM_BACKOFF_BASE_SECONDS = _env_float("PENGUARD_LLM_BACKOFF_BASE_SECONDS", 1.0) or 1.0
TARGET_HTTP_TIMEOUT_SECONDS = _env_float("PENGUARD_TARGET_HTTP_TIMEOUT_SECONDS", 5.0) or 5.0
SANDBOX_CONTROL_TIMEOUT_SECONDS = _env_float("PENGUARD_SANDBOX_CONTROL_TIMEOUT_SECONDS", 3.0) or 3.0
MAX_TOKENS_PER_EPISODE = _env_int("PENGUARD_MAX_TOKENS_PER_EPISODE", None)
MAX_COST_USD_PER_EPISODE = _env_float("PENGUARD_MAX_COST_USD_PER_EPISODE", None)
PRICE_PER_1K_IN_USD = _env_float("PENGUARD_PRICE_PER_1K_IN_USD", None)
PRICE_PER_1K_OUT_USD = _env_float("PENGUARD_PRICE_PER_1K_OUT_USD", None)

# ── Optional Markdown vector skills (validated; off by default) ─────────────
VECTOR_SKILLS_ENABLED = _env_bool("PENGUARD_VECTOR_SKILLS", False)
VECTOR_SKILLS_DIR = _env("PENGUARD_VECTOR_SKILLS_DIR") or "skills/vectors"

# ── Integrations ────────────────────────────────────────────────────────────
GITHUB_TARGET_REPO = _env("GITHUB_TARGET_REPO")
WEBHOOK_URL = _env("PENGUARD_WEBHOOK_URL")
