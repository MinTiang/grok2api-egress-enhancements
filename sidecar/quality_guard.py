#!/usr/bin/env python3
"""Active and passive quality guard for grok2api egress nodes.

The guard calls a scoped internal API, quarantines suspect nodes without
deleting bindings, and restores only nodes it disabled. Configuration and the
scoped internal credential are provided by grok2api through a private
bootstrap file. The implementation uses only Python's standard library.

Local extension (rank scheduler): EWMA first-token ranking over healthy nodes
with optional weighted auto-account reassignment via admin API (dry-run by
default). Ranking knobs come from env only and are not part of runtime-config.
"""

from __future__ import annotations

import argparse
import dataclasses
import fcntl
import json
import os
import random
import signal
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


RUNTIME_CONFIG_FIELDS = {
    "enabled",
    "mode",
    "active_interval_seconds",
    "passive_poll_seconds",
    "soft_tps",
    "hard_tps",
    "consecutive_soft",
    "consecutive_errors",
    "quarantine_seconds",
    "min_healthy_nodes",
}

ACCOUNT_DEGRADE_WINDOW_SECONDS = 24 * 60 * 60
ACCOUNT_DEGRADE_MUTE_AFTER = 3
DEFAULT_FORCE_ACCOUNT_SWITCH_SECONDS = 120


BOOTSTRAP_VERSION = 1
BOOTSTRAP_FILE = Path("/var/lib/grok2api-quality-guard/bootstrap.json")
INTERNAL_API_PREFIX = "/api/internal/v1/quality-guard"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    raw = os.getenv(name)
    try:
        value = int(str(raw).strip()) if raw is not None and str(raw).strip() else default
    except ValueError:
        value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def _env_float(name: str, default: float, minimum: float | None = None, maximum: float | None = None) -> float:
    raw = os.getenv(name)
    try:
        value = float(str(raw).strip()) if raw is not None and str(raw).strip() else default
    except ValueError:
        value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def load_rank_config() -> dict[str, Any]:
    """Env-only ranking knobs (not part of g2a runtime-config schema)."""
    floor_share = _env_float("RANK_FLOOR_SHARE", 0.03, 0.0, 0.2)
    max_share = _env_float("RANK_MAX_SHARE", 0.18, 0.05, 1.0)
    if max_share < floor_share:
        max_share = max(floor_share, 0.18)
    admin_password = os.getenv("GROK2API_ADMIN_PASSWORD", "") or ""
    password_file = (os.getenv("GROK2API_ADMIN_PASSWORD_FILE") or "").strip()
    if password_file:
        try:
            admin_password = Path(password_file).read_text(encoding="utf-8").rstrip("\r\n")
        except OSError:
            pass
    return {
        "enabled": _env_bool("RANK_SCHEDULER_ENABLED", False),
        "dry_run": _env_bool("RANK_DRY_RUN", True),
        "interval_seconds": _env_int("RANK_INTERVAL_SECONDS", 120, 30, 86400),
        "ewma_alpha": _env_float("RANK_EWMA_ALPHA", 0.3, 0.05, 1.0),
        "floor_share": floor_share,
        "max_share": max_share,
        "max_moves": _env_int("RANK_MAX_MOVES", 30, 0, 5000),
        "max_move_pct": _env_float("RANK_MAX_MOVE_PCT", 5.0, 0.0, 100.0),
        "min_samples": _env_int("RANK_MIN_SAMPLES", 3, 1, 100),
        "admin_username": (os.getenv("GROK2API_ADMIN_USERNAME") or "").strip(),
        "admin_password": admin_password,
    }


class GuardDisabled(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class Config:
    base_url: str
    internal_token: str
    model: str
    node_ids: tuple[str, ...]
    mode: str
    active_interval_seconds: int
    passive_poll_seconds: int
    passive_page_size: int
    passive_max_pages: int
    jitter_seconds: int
    request_timeout_seconds: int
    soft_tps: float
    hard_tps: float
    consecutive_soft: int
    consecutive_errors: int
    quarantine_seconds: int
    no_account_backoff_seconds: int
    min_healthy_nodes: int
    max_output_tokens: int
    fail_closed: bool
    enabled: bool
    quarantine_enabled: bool
    min_generation_ms: int
    rotation_url: str
    rotation_token: str
    rotation_timeout_seconds: int
    rotatable_node_ids: tuple[str, ...]
    prompt: str
    expected: str
    state_file: Path
    lock_file: Path
    runtime_config_file: Path

    @classmethod
    def from_bootstrap(cls, path: Path = BOOTSTRAP_FILE) -> "Config":
        try:
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except FileNotFoundError as exc:
            raise ValueError("quality guard bootstrap file is missing; restart grok2api") from exc
        except (OSError, ValueError) as exc:
            raise ValueError(f"cannot read quality guard bootstrap: {type(exc).__name__}") from exc
        if not isinstance(payload, dict) or payload.get("version") != BOOTSTRAP_VERSION:
            raise ValueError("unsupported quality guard bootstrap")
        if not payload.get("enabled"):
            raise GuardDisabled("qualityGuard.enabled is false in config.yaml")
        values = payload.get("config")
        if not isinstance(values, dict):
            raise ValueError("quality guard bootstrap config is missing")
        token = str(payload.get("internal_token") or "").strip()
        node_ids = tuple(dict.fromkeys(str(value).strip() for value in values.get("node_ids", []) if str(value).strip()))
        rotatable_node_ids = tuple(dict.fromkeys(str(value).strip() for value in values.get("rotatable_node_ids", []) if str(value).strip()))
        config = cls(
            # Prefer compose service DNS; allow override for host-network / custom topologies.
            base_url=(os.environ.get("GROK2API_BASE_URL") or "http://grok2api:8000").strip() or "http://grok2api:8000",
            internal_token=token,
            model=str(values.get("model") or "").strip(),
            node_ids=node_ids,
            mode=str(values.get("mode") or "").strip().lower(),
            active_interval_seconds=int(values.get("active_interval_seconds") or 0),
            passive_poll_seconds=int(values.get("passive_poll_seconds") or 0),
            passive_page_size=200,
            passive_max_pages=10,
            jitter_seconds=30,
            request_timeout_seconds=120,
            soft_tps=float(values.get("soft_tps") or 0),
            hard_tps=float(values.get("hard_tps") or 0),
            consecutive_soft=int(values.get("consecutive_soft") or 0),
            consecutive_errors=int(values.get("consecutive_errors") or 0),
            quarantine_seconds=int(values.get("quarantine_seconds") or 0),
            no_account_backoff_seconds=int(values.get("no_account_backoff_seconds") or 0),
            min_healthy_nodes=int(values.get("min_healthy_nodes") or 0),
            max_output_tokens=int(values.get("max_output_tokens") or 0),
            fail_closed=bool(values.get("fail_closed")),
            enabled=True,
            quarantine_enabled=_env_bool("QUALITY_GUARD_QUARANTINE_ENABLED", True),
            min_generation_ms=int(values.get("min_generation_ms") or 0),
            rotation_url=str(values.get("rotation_url") or "").strip(),
            rotation_token=str(values.get("rotation_token") or ""),
            rotation_timeout_seconds=int(values.get("rotation_timeout_seconds") or 0),
            rotatable_node_ids=rotatable_node_ids,
            prompt=str(values.get("prompt") or "").strip(),
            expected=str(values.get("expected") or "").strip(),
            state_file=Path("/var/lib/grok2api-quality-guard/state.json"),
            lock_file=Path("/var/lib/grok2api-quality-guard/guard.lock"),
            runtime_config_file=Path("/var/lib/grok2api-quality-guard/runtime-config.json"),
        )
        config.validate()
        return config

    def validate(self) -> None:
        parsed = urllib.parse.urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("GROK2API_BASE_URL must be an absolute HTTP(S) URL")
        if not self.internal_token:
            raise ValueError("quality guard bootstrap internal token is missing")
        if not self.model or not self.prompt or not self.expected:
            raise ValueError("model, prompt, and expected marker must not be empty")
        if self.mode not in {"active", "passive", "hybrid"}:
            raise ValueError("qualityGuard.mode must be active, passive, or hybrid")
        if self.soft_tps >= self.hard_tps:
            raise ValueError("qualityGuard.softTPS must be lower than qualityGuard.hardTPS")
        if self.active_interval_seconds > 86400:
            raise ValueError("qualityGuard.activeInterval must not exceed 24 hours")
        if self.passive_poll_seconds > 300:
            raise ValueError("qualityGuard.passivePollInterval must not exceed 5 minutes")
        if self.soft_tps > 10000 or self.hard_tps > 10000:
            raise ValueError("quality guard Token/s thresholds must not exceed 10000")
        if self.consecutive_soft > 20 or self.consecutive_errors > 20:
            raise ValueError("quality guard consecutive strike limits must not exceed 20")
        if self.quarantine_seconds > 86400:
            raise ValueError("qualityGuard.quarantineDuration must not exceed 24 hours")
        if self.no_account_backoff_seconds > 86400:
            raise ValueError("qualityGuard.noAccountBackoff must not exceed 24 hours")
        if self.min_healthy_nodes < 1 or (self.node_ids and self.min_healthy_nodes > len(self.node_ids)):
            raise ValueError("qualityGuard.minimumHealthyNodes must fit the configured node count")
        if self.min_generation_ms > self.request_timeout_seconds * 1000:
            raise ValueError("qualityGuard.minimumGenerationWindow must fit the request timeout")
        if self.rotation_url:
            rotation_url = urllib.parse.urlparse(self.rotation_url)
            if rotation_url.scheme not in {"http", "https"} or not rotation_url.netloc:
                raise ValueError("qualityGuard.rotationURL must be an absolute HTTP(S) URL")
        elif self.rotatable_node_ids:
            raise ValueError("qualityGuard.rotationURL is required when rotatableNodeIDs are configured")
        if any(not value.isdigit() or int(value) < 1 for value in self.rotatable_node_ids):
            raise ValueError("qualityGuard.rotatableNodeIDs must contain positive integers")
        if self.passive_page_size > 2000:
            raise ValueError("internal passive page size must not exceed 2000")


def load_runtime_config(base: Config, path: Path) -> Config:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError:
        return base
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read runtime quality guard config: {type(exc).__name__}") from exc
    if not isinstance(value, dict) or value.get("version") != 1 or not isinstance(value.get("settings"), dict):
        raise ValueError("unsupported runtime quality guard config")
    settings = value["settings"]
    unknown = set(settings) - RUNTIME_CONFIG_FIELDS
    if unknown:
        raise ValueError("runtime quality guard config contains unknown fields")
    # Runtime files written before the plugin toggle existed stay enabled.
    settings = dict(settings)
    settings.setdefault("enabled", True)
    if set(settings) != RUNTIME_CONFIG_FIELDS:
        raise ValueError("runtime quality guard config is incomplete")
    if not isinstance(settings["mode"], str):
        raise ValueError("runtime quality guard mode must be a string")
    if not isinstance(settings["enabled"], bool):
        raise ValueError("runtime quality guard enabled field is invalid")
    integer_fields = RUNTIME_CONFIG_FIELDS - {"enabled", "mode", "soft_tps", "hard_tps"}
    if any(isinstance(settings[name], bool) or not isinstance(settings[name], int) for name in integer_fields):
        raise ValueError("runtime quality guard integer field is invalid")
    if any(isinstance(settings[name], bool) or not isinstance(settings[name], (int, float)) for name in {"soft_tps", "hard_tps"}):
        raise ValueError("runtime quality guard threshold is invalid")
    config = dataclasses.replace(base, **settings)
    config.validate()
    return config


class RuntimeConfigReloader:
    def __init__(self, base: Config):
        self.base = base
        self.current = base
        self.signature: tuple[int, int] | None = None
        self.missing = False

    def reload(self, force: bool = False) -> tuple[Config, bool, Exception | None]:
        try:
            stat_result = self.base.runtime_config_file.stat()
            signature = (stat_result.st_mtime_ns, stat_result.st_size)
            missing = False
        except FileNotFoundError:
            signature = None
            missing = True
        except OSError as exc:
            return self.current, False, exc
        if not force and signature == self.signature and missing == self.missing:
            return self.current, False, None
        self.signature = signature
        self.missing = missing
        try:
            candidate = self.base if missing else load_runtime_config(self.base, self.base.runtime_config_file)
        except ValueError as exc:
            return self.current, True, exc
        changed = candidate != self.current
        self.current = candidate
        return candidate, changed or force, None


class ApiError(RuntimeError):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"HTTP {status} {code}: {message}")
        self.status = status
        self.code = code


class ApiClient:
    def __init__(self, config: Config):
        self.config = config
        self.ssl_context = ssl.create_default_context()

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        headers["Authorization"] = f"Bearer {self.config.internal_token}"
        request = urllib.request.Request(self.config.base_url + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.config.request_timeout_seconds, context=self.ssl_context) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8", "replace"))
            except (ValueError, OSError):
                payload = {}
            error = payload.get("error") or {}
            raise ApiError(exc.code, str(error.get("code", "request_failed")), str(error.get("message", "request failed"))) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"request failed: {type(exc).__name__}") from exc
        return payload.get("data", payload)

    def list_nodes(self) -> list[dict[str, Any]]:
        page_size = 2000
        items: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        page = 1
        while True:
            query = urllib.parse.urlencode({"page": page, "pageSize": page_size, "scope": "grok_build"})
            payload = self._request("GET", f"{INTERNAL_API_PREFIX}/egress-nodes?{query}")
            batch = list(payload.get("items") or [])
            total = max(0, int(payload.get("total") or 0))
            added = 0
            for node in batch:
                node_id = str(node.get("id") or "")
                if not node_id or node_id in seen_ids:
                    continue
                seen_ids.add(node_id)
                items.append(node)
                added += 1
            if len(items) >= total or (total == 0 and len(batch) < page_size):
                return items
            if not batch or added == 0:
                raise RuntimeError(f"egress node pagination stopped at {len(items)} of {total}")
            page += 1

    def fixed_fallback_node_ids(self) -> set[str]:
        payload = self._request("GET", f"{INTERNAL_API_PREFIX}/egress-operations")
        result: set[str] = set()
        for fallback in (payload.get("fallbacks") or {}).values():
            if not isinstance(fallback, dict) or fallback.get("mode") != "fixed":
                continue
            node_id = str(fallback.get("nodeId") or "")
            if node_id:
                result.add(node_id)
        return result

    def quality_test(self, node_id: str) -> dict[str, Any]:
        return self._request("POST", f"{INTERNAL_API_PREFIX}/egress-nodes/{node_id}/quality-test")

    def connectivity_test(self, node_id: str) -> dict[str, Any]:
        return self._request("POST", f"{INTERNAL_API_PREFIX}/egress-nodes/{node_id}/test")

    def list_audits(self, cursor: str = "") -> dict[str, Any]:
        query = {
            "pagination": "cursor",
            "pageSize": self.config.passive_page_size,
            "period": "24h",
        }
        if cursor:
            query["cursor"] = cursor
        return self._request("GET", f"{INTERNAL_API_PREFIX}/request-audits?{urllib.parse.urlencode(query)}")

    def find_audit_account_id(self, request_id: str) -> str:
        """Resolve the account used by a just-finished quality probe."""
        request_id = str(request_id or "").strip()
        if not request_id:
            return ""
        page = self.list_audits()
        for item in list(page.get("items") or []):
            item_request_id = str(item.get("requestId") or "").strip()
            item_id = str(item.get("id") or "").strip()
            if request_id not in {item_request_id, item_id}:
                continue
            account_id = str(item.get("accountId") or "").strip()
            if account_id.isdigit() and int(account_id) > 0:
                return account_id
            return ""
        return ""

    def set_enabled(self, node_id: str, enabled: bool) -> int:
        result = self._request("PATCH", f"{INTERNAL_API_PREFIX}/egress-nodes/batch", {"ids": [node_id], "enabled": enabled})
        return int(result.get("updated") or 0)

    def rotate_node(self, node_id: str, old_exit_ip: str = "") -> dict[str, Any]:
        if not self.config.rotation_url:
            raise RuntimeError("rotation endpoint is not configured")
        rotation_url = self.config.rotation_url
        if str(node_id) in {"48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58"}:
            rotation_url = os.environ.get("KOOKEey_ROTATION_URL", "http://127.0.0.1:19100/rotate")
        data = json.dumps({"nodeId": node_id, "oldExitIp": old_exit_ip}, separators=(",", ":")).encode()
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.config.rotation_token:
            headers["Authorization"] = f"Bearer {self.config.rotation_token}"
        request = urllib.request.Request(rotation_url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.config.rotation_timeout_seconds,
                context=self.ssl_context,
            ) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8", "replace"))
            except (ValueError, OSError):
                payload = {}
            raise RuntimeError(f"rotation failed: HTTP {exc.code} {payload.get('error', 'request failed')}") from exc
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise RuntimeError(f"rotation failed: {type(exc).__name__}") from exc
        if not isinstance(payload, dict) or not bool(payload.get("changed")):
            raise RuntimeError("rotation did not confirm an exit IP change")
        return payload



class AdminApiClient:
    """Optional admin API used only for weighted account reassignment."""

    def __init__(self, base_url: str, username: str, password: str, timeout_seconds: int, ssl_context: ssl.SSLContext):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout_seconds = timeout_seconds
        self.ssl_context = ssl_context
        self.token = ""

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None, retry_auth: bool = True) -> Any:
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds, context=self.ssl_context) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8", "replace"))
            except (ValueError, OSError):
                payload = {}
            if exc.code == 401 and retry_auth and path != "/api/admin/v1/auth/login":
                self.login()
                return self._request(method, path, body, retry_auth=False)
            error = payload.get("error") or {}
            raise ApiError(exc.code, str(error.get("code", "request_failed")), str(error.get("message", "request failed"))) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"admin request failed: {type(exc).__name__}") from exc
        return payload.get("data", payload)

    def login(self) -> None:
        data = self._request(
            "POST",
            "/api/admin/v1/auth/login",
            {"username": self.username, "password": self.password},
            retry_auth=False,
        )
        token = ""
        if isinstance(data, dict):
            token = str(data.get("token") or data.get("accessToken") or "")
            tokens = data.get("tokens")
            if not token and isinstance(tokens, dict):
                token = str(tokens.get("accessToken") or tokens.get("token") or "")
            if not token and isinstance(data.get("session"), dict):
                token = str(data["session"].get("token") or data["session"].get("accessToken") or "")
        if not token:
            raise RuntimeError("admin login did not return a token")
        self.token = token

    def list_auto_account_ids_by_node(self, provider: str = "grok_build", limit: int = 20000) -> dict[str, list[str]]:
        by_node: dict[str, list[str]] = {}
        page = 1
        total_seen = 0
        while page <= 200 and total_seen < limit:
            query = urllib.parse.urlencode({"page": page, "pageSize": 100, "provider": provider})
            data = self._request("GET", f"/api/admin/v1/accounts?{query}")
            items = list(data.get("items") or [])
            if not items:
                break
            for item in items:
                total_seen += 1
                mode = str(item.get("egressAssignmentMode") or item.get("egressBindMode") or item.get("bindMode") or item.get("mode") or "auto").lower()
                if mode in {"manual", "sticky", "fixed"}:
                    continue
                node_id = str(item.get("egressNodeId") or "")
                aid = item.get("id")
                if not node_id or aid is None:
                    continue
                by_node.setdefault(node_id, []).append(str(aid))
            if len(items) < 100:
                break
            page += 1
        return by_node

    def assign_accounts(self, node_id: str, account_ids: list[str], mode: str = "auto", provider: str = "grok_build") -> dict[str, Any]:
        if not account_ids:
            return {"assigned": 0}
        return self._request(
            "POST",
            f"/api/admin/v1/egress-nodes/{node_id}/accounts",
            {"provider": provider, "ids": account_ids, "mode": mode},
        )

    def set_accounts_enabled(self, account_ids: list[str], enabled: bool, provider: str = "grok_build") -> int:
        if not account_ids:
            return 0
        result = self._request(
            "PATCH",
            "/api/admin/v1/accounts/batch",
            {"ids": account_ids, "enabled": enabled, "provider": provider},
        )
        return int(result.get("updated") or 0)


def classify_result(result: dict[str, Any], config: Config) -> tuple[str, str]:
    if not bool(result.get("expectedMatched")):
        return "soft", "expected_marker_missing"
    output_tokens = int(result.get("outputTokens") or result.get("visibleTokens") or 0)
    speed_value = result.get("outputTokensPerSecond")
    if speed_value is None:
        # Rolling upgrades may still expose panel-equivalent TPS under the legacy name.
        speed_value = result.get("visibleTokensPerSecond")
    speed = float(speed_value or 0.0)
    generation_ms = int(result.get("generationMs") or 0)
    if generation_ms <= 0:
        generation_ms = max(0, int(result.get("durationMs") or 0) - int(result.get("firstTokenMs") or 0))
    if output_tokens < 32:
        return "soft", "insufficient_output_tokens"
    reasoning_tokens = max(0, int(result.get("reasoningTokens") or result.get("reasoning_tokens") or 0))
    if output_tokens >= 64 and reasoning_tokens <= 0:
        return "hard", "missing_thinking"
    if config.fail_closed and generation_ms < config.min_generation_ms and speed >= config.soft_tps:
        return "hard", "buffered_burst"
    if config.fail_closed and generation_ms < config.min_generation_ms:
        return "soft", "insufficient_generation_window"
    if speed >= config.hard_tps:
        return "hard", "hard_tps"
    if speed >= config.soft_tps:
        return "soft", "soft_tps"
    return "healthy", "within_threshold"


def classify_audit(value: dict[str, Any], config: Config) -> tuple[str, str, float, int]:
    if value.get("provider") != "grok_build" or not bool(value.get("streaming")):
        return "ignored", "not_build_stream", 0.0, 0
    status = int(value.get("statusCode") or 0)
    if status < 200 or status >= 300 or value.get("errorCode"):
        return "ignored", "unsuccessful", 0.0, 0
    first_token_ms = value.get("firstTokenMs")
    if first_token_ms is None:
        return "ignored", "missing_first_token", 0.0, 0
    generation_ms = int(value.get("durationMs") or 0) - int(first_token_ms)
    output_tokens = max(0, int(value.get("outputTokens") or 0))
    if generation_ms <= 0 or output_tokens < 32:
        return "ignored", "insufficient_output_tokens", 0.0, output_tokens
    speed = float(output_tokens) * 1000 / float(generation_ms)
    reasoning_tokens = max(0, int(value.get("reasoningTokens") or 0))
    if output_tokens >= 32 and reasoning_tokens <= 0:
        return "hard", "missing_thinking", speed, output_tokens
    if config.fail_closed and generation_ms < config.min_generation_ms and speed >= config.soft_tps:
        return "hard", "buffered_burst", speed, output_tokens
    if speed >= config.hard_tps:
        return "hard", "hard_tps", speed, output_tokens
    if speed >= config.soft_tps:
        return "soft", "soft_tps", speed, output_tokens
    return "healthy", "within_threshold", speed, output_tokens


def default_node_state() -> dict[str, Any]:
    return {
        "active_soft_strikes": 0,
        "passive_soft_strikes": 0,
        "error_strikes": 0,
        "quarantined_until": 0.0,
        "disabled_by_guard": False,
        "last_reason": "",
        "last_probe_at": 0.0,
        "last_observed_at": 0.0,
        "last_source": "",
        "last_classification": "",
        "last_output_tps": 0.0,
        "last_output_tokens": 0,
        "last_first_token_ms": 0,
        "last_duration_ms": 0,
        "last_rotation_at": 0.0,
        "last_rotation_exit_ip": "",
        "rotation_failures": 0,
        "last_no_account_log_at": 0.0,
        "ewma_first_token_ms": 0.0,
        "ewma_samples": 0,
        "rank_score": 0.0,
        "rank_position": 0,
        "target_share": 0.0,
        "target_accounts": 0,
        "last_rank_at": 0.0,
        "quarantine_source": "",
        "passive_degrade_repeats": 0,
    }


def default_statistics() -> dict[str, Any]:
    return {
        "started_at": time.time(),
        "active": {"total": 0, "healthy": 0, "soft": 0, "hard": 0, "errors": 0, "output_tokens": 0},
        "passive": {"total": 0, "healthy": 0, "soft": 0, "hard": 0, "errors": 0, "output_tokens": 0},
        "actions": {"quarantined": 0, "restored": 0, "suppressed": 0},
    }


def ensure_statistics(state: dict[str, Any]) -> dict[str, Any]:
    defaults = default_statistics()
    statistics = state.setdefault("statistics", {})
    if not isinstance(statistics, dict):
        raise RuntimeError("invalid quality guard statistics")
    statistics.setdefault("started_at", defaults["started_at"])
    for group_name in ("active", "passive", "actions"):
        group = statistics.setdefault(group_name, {})
        if not isinstance(group, dict):
            raise RuntimeError("invalid quality guard statistics")
        if group_name in {"active", "passive"}:
            legacy_tokens = int(group.pop("visible_tokens", 0))
            group.setdefault("output_tokens", legacy_tokens)
        for field, default in defaults[group_name].items():
            group.setdefault(field, default)
            if isinstance(group[field], bool) or not isinstance(group[field], int) or group[field] < 0:
                raise RuntimeError("invalid quality guard statistics")
    return statistics


def load_state(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError:
        return {
            "version": 1,
            "nodes": {},
            "passive_initialized": False,
            "seen_audit_ids": [],
            "ranking": {"last_run_at": 0.0, "dry_run": True, "last_table": [], "last_moves": []},
        }
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"cannot read state file: {type(exc).__name__}") from exc
    if value.get("version") != 1 or not isinstance(value.get("nodes"), dict):
        raise RuntimeError("unsupported state file format")
    value.setdefault("passive_initialized", False)
    value.setdefault("seen_audit_ids", [])
    value.setdefault("degrade_accounts", {})
    if "last_active_cycle_at" not in value:
        value["last_active_cycle_at"] = max(
            (float(node.get("last_probe_at", 0.0)) for node in value["nodes"].values()),
            default=0.0,
        )
    if not isinstance(value["seen_audit_ids"], list):
        raise RuntimeError("invalid passive audit state")
    if not isinstance(value["degrade_accounts"], dict):
        raise RuntimeError("invalid degraded account state")
    ensure_statistics(value)
    return value


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(state, handle, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def append_state_event(state: dict[str, Any], event: str, **fields: Any) -> None:
    events = state.setdefault("recent_events", [])
    events.append({"ts": time.time(), "event": event, **fields})
    del events[:-100]


def log_event(event: str, **fields: Any) -> None:
    payload = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **fields}
    print(json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")), flush=True)


class Guard:
    def __init__(self, config: Config, api: ApiClient):
        self.config = config
        self.api = api
        self.state = load_state(config.state_file)
        ensure_statistics(self.state)
        self.rank = load_rank_config()
        ranking = self.state.setdefault("ranking", {})
        if not isinstance(ranking, dict):
            ranking = {}
            self.state["ranking"] = ranking
        ranking.setdefault("last_run_at", 0.0)
        ranking.setdefault("dry_run", True)
        ranking.setdefault("last_table", [])
        ranking.setdefault("last_moves", [])
        self._admin: AdminApiClient | None = None
        self._resolved_node_ids: list[str] = []
        self._update_guard_metadata()
        self._save()

    def _bump_statistic(self, group: str, field: str, amount: int = 1) -> None:
        statistics = ensure_statistics(self.state)
        statistics[group][field] = int(statistics[group][field]) + amount

    def _update_guard_metadata(self) -> None:
        self.state["updated_at"] = time.time()
        self.state["guard"] = {
            "mode": self.config.mode,
            "model": self.config.model,
            "node_ids": list(self.config.node_ids) if self.config.node_ids else self._resolved_node_ids,
            "active_interval_seconds": self.config.active_interval_seconds,
            "passive_poll_seconds": self.config.passive_poll_seconds,
            "soft_tps": self.config.soft_tps,
            "hard_tps": self.config.hard_tps,
            "consecutive_soft": self.config.consecutive_soft,
            "consecutive_errors": self.config.consecutive_errors,
            "quarantine_seconds": self.config.quarantine_seconds,
            "no_account_backoff_seconds": self.config.no_account_backoff_seconds,
            "min_healthy_nodes": self.config.min_healthy_nodes,
            "max_output_tokens": self.config.max_output_tokens,
            "fail_closed": self.config.fail_closed,
            "enabled": self.config.enabled,
            "min_generation_ms": self.config.min_generation_ms,
            "rotatable_node_ids": list(self.config.rotatable_node_ids),
            "prompt": self.config.prompt,
            "expected": self.config.expected,
        }

    def _save(self) -> None:
        self._update_guard_metadata()
        save_state(self.config.state_file, self.state)

    def _state_for(self, node_id: str) -> dict[str, Any]:
        nodes = self.state.setdefault("nodes", {})
        current = nodes.setdefault(node_id, default_node_state())
        legacy_strikes = int(current.pop("soft_strikes", 0))
        current.setdefault("active_soft_strikes", legacy_strikes)
        current.setdefault("passive_soft_strikes", 0)
        current.setdefault("last_output_tps", float(current.pop("last_visible_tps", 0.0)))
        current.setdefault("last_output_tokens", int(current.pop("last_visible_tokens", 0)))
        for key, value in default_node_state().items():
            current.setdefault(key, value)
        return current

    def _track_degraded_account(self, audit_value: dict[str, Any], reason: str, now: float) -> None:
        """Mute an account after repeated real-traffic degradation events."""
        account_id = str(audit_value.get("accountId") or "").strip()
        if not account_id.isdigit() or int(account_id) < 1:
            return
        accounts = self.state.setdefault("degrade_accounts", {})
        entry = accounts.setdefault(account_id, {})
        if not isinstance(entry, dict):
            entry = {}
            accounts[account_id] = entry
        cutoff = now - ACCOUNT_DEGRADE_WINDOW_SECONDS
        hits = [float(value) for value in entry.get("hits", []) if isinstance(value, (int, float)) and float(value) >= cutoff]
        hits.append(now)
        entry["hits"] = hits
        entry["last_reason"] = reason
        entry["last_at"] = now
        if len(hits) < ACCOUNT_DEGRADE_MUTE_AFTER or float(entry.get("muted_at") or 0) > 0:
            return
        admin = self._admin_client()
        if admin is None:
            log_event("account_auto_mute_skipped", account_id=account_id, reason="no_admin_credentials", hits=len(hits))
            return
        try:
            updated = admin.set_accounts_enabled([account_id], False)
        except Exception as exc:
            log_event("account_auto_mute_failed", account_id=account_id, reason=reason, hits=len(hits), error_type=type(exc).__name__)
            return
        entry["muted_at"] = now
        entry["muted_reason"] = reason
        entry["muted_updated"] = updated
        append_state_event(self.state, "account_auto_muted", account_id=account_id, reason=reason, hits=len(hits))
        log_event("account_auto_muted", account_id=account_id, reason=reason, hits=len(hits), updated=updated)

    @staticmethod
    def _force_account_switch_enabled() -> bool:
        return _env_bool("QUALITY_GUARD_FORCE_ACCOUNT_SWITCH_ENABLED", True)

    @staticmethod
    def _force_account_switch_seconds() -> int:
        return _env_int(
            "QUALITY_GUARD_FORCE_ACCOUNT_SWITCH_SECONDS",
            DEFAULT_FORCE_ACCOUNT_SWITCH_SECONDS,
            30,
            900,
        )

    def _force_account_switch(self, audit_value: dict[str, Any], reason: str, now: float) -> None:
        """Temporarily remove a degraded account so the next turn selects another one."""
        if not self._force_account_switch_enabled():
            return
        account_id = str(audit_value.get("accountId") or "").strip()
        if not account_id.isdigit() or int(account_id) < 1:
            return
        accounts = self.state.setdefault("degrade_accounts", {})
        entry = accounts.setdefault(account_id, {})
        if not isinstance(entry, dict):
            entry = {}
            accounts[account_id] = entry
        if float(entry.get("muted_at") or 0) > 0:
            return
        hold_seconds = self._force_account_switch_seconds()
        current_until = float(entry.get("forced_switch_until") or 0)
        if current_until > now:
            entry["forced_switch_until"] = max(current_until, now + hold_seconds)
            return
        admin = self._admin_client()
        if admin is None:
            log_event("account_force_switch_skipped", account_id=account_id, reason=reason, error_type="no_admin_credentials")
            return
        try:
            updated = admin.set_accounts_enabled([account_id], False)
        except Exception as exc:
            log_event("account_force_switch_failed", account_id=account_id, reason=reason, error_type=type(exc).__name__)
            return
        entry["forced_switch_until"] = now + hold_seconds
        entry["forced_switch_reason"] = reason
        entry["forced_switch_updated"] = updated
        append_state_event(self.state, "account_force_switched", account_id=account_id, reason=reason, hold_seconds=hold_seconds)
        log_event("account_force_switched", account_id=account_id, reason=reason, hold_seconds=hold_seconds, updated=updated)

    def _force_probe_account_switch(self, result: dict[str, Any], reason: str, now: float) -> None:
        request_id = str(result.get("requestId") or "").strip()
        if not request_id:
            return
        try:
            account_id = self.api.find_audit_account_id(request_id)
        except Exception as exc:
            log_event("probe_account_lookup_failed", request_id=request_id, reason=reason, error_type=type(exc).__name__)
            return
        if not account_id:
            log_event("probe_account_switch_skipped", request_id=request_id, reason=reason, error_type="account_not_found")
            return
        self._force_account_switch({"accountId": account_id}, reason, now)

    def _restore_forced_account_switches(self, now: float) -> None:
        accounts = self.state.get("degrade_accounts") or {}
        if not isinstance(accounts, dict):
            return
        expired = [
            (str(account_id), entry)
            for account_id, entry in accounts.items()
            if isinstance(entry, dict)
            and float(entry.get("forced_switch_until") or 0) > 0
            and float(entry.get("forced_switch_until") or 0) <= now
        ]
        if not expired:
            return
        admin = self._admin_client()
        if admin is None:
            return
        for account_id, entry in expired:
            if float(entry.get("muted_at") or 0) > 0:
                entry.pop("forced_switch_until", None)
                continue
            try:
                updated = admin.set_accounts_enabled([account_id], True)
            except Exception as exc:
                log_event("account_force_switch_restore_failed", account_id=account_id, error_type=type(exc).__name__)
                continue
            entry.pop("forced_switch_until", None)
            append_state_event(self.state, "account_force_switch_restored", account_id=account_id)
            log_event("account_force_switch_restored", account_id=account_id, updated=updated)

    def release_guard_owned_nodes(self) -> None:
        """Release only nodes disabled by this guard when the plugin is off."""
        try:
            nodes = {str(node.get("id") or ""): node for node in self.api.list_nodes()}
        except Exception as exc:
            log_event("guard_disable_release_failed", error_type=type(exc).__name__)
            return
        for node_id, state in (self.state.get("nodes") or {}).items():
            if not isinstance(state, dict) or not state.get("disabled_by_guard"):
                continue
            node = nodes.get(str(node_id))
            if node is None:
                continue
            try:
                updated = self.api.set_enabled(str(node_id), True)
            except Exception as exc:
                log_event("guard_disable_release_failed", node_id=node_id, node_name=node.get("name"), error_type=type(exc).__name__)
                continue
            if updated != 1:
                log_event("guard_disable_release_not_applied", node_id=node_id, node_name=node.get("name"), updated=updated)
                continue
            state.update({"active_soft_strikes": 0, "passive_soft_strikes": 0, "error_strikes": 0,
                          "quarantined_until": 0.0, "disabled_by_guard": False, "last_reason": "", "quarantine_source": ""})
            append_state_event(self.state, "guard_disabled_node_released", node_id=node_id, node_name=node.get("name"))
            log_event("guard_disabled_node_released", node_id=node_id, node_name=node.get("name"))
        self._save()

    def _defer_no_account(self, state: dict[str, Any], node: dict[str, Any], now: float, event: str, **fields: Any) -> None:
        state["last_probe_at"] = now
        state["last_reason"] = "probe_no_account"
        state["quarantined_until"] = max(
            float(state.get("quarantined_until", 0.0)),
            now + self.config.no_account_backoff_seconds,
        )
        last_logged = float(state.get("last_no_account_log_at", 0.0))
        if last_logged <= 0 or now - last_logged >= self.config.no_account_backoff_seconds:
            state["last_no_account_log_at"] = now
            log_event(event, node_id=str(node["id"]), node_name=node.get("name"), reason="probe_no_account", **fields)

    def _eligible_nodes(self, nodes: list[dict[str, Any]], protected_node_ids: set[str]) -> list[dict[str, Any]]:
        configured = set(self.config.node_ids)
        state_nodes = self.state.get("nodes") or {}
        result = []
        for node in nodes:
            node_id = str(node.get("id") or "")
            if not node_id or not node.get("proxyConfigured"):
                continue
            tracked_quarantine = bool((state_nodes.get(node_id) or {}).get("disabled_by_guard"))
            if node_id in protected_node_ids and not tracked_quarantine:
                continue
            # A node removed from the configured set while quarantined remains
            # managed until it has passed recovery. Otherwise configuration
            # changes could strand a guard-owned disabled node forever.
            if configured and node_id not in configured and not tracked_quarantine:
                continue
            if node.get("enabled") or tracked_quarantine:
                result.append(node)
        return result

    def _can_quarantine(self, nodes: list[dict[str, Any]], node_id: str) -> bool:
        enabled = sum(1 for node in nodes if bool(node.get("enabled")))
        target_enabled = any(str(node.get("id")) == node_id and bool(node.get("enabled")) for node in nodes)
        if self.config.fail_closed:
            return target_enabled
        return target_enabled and enabled - 1 >= self.config.min_healthy_nodes

    def _should_rotate(self, node_id: str, reason: str) -> bool:
        return (
            bool(self.config.rotation_url)
            and node_id in set(self.config.rotatable_node_ids)
            and reason in {
                "hard_tps", "soft_tps", "buffered_burst", "missing_thinking", "expected_marker_missing",
                "insufficient_output_tokens", "insufficient_generation_window", "probe_errors",
                "recovery_probe_error", "rotation_error",
            }
        )

    @staticmethod
    def _probe_account_unavailable(exc: Exception) -> bool:
        return isinstance(exc, ApiError) and exc.code == "egressQualityProbeNoAccount"

    def _quarantine(self, nodes: list[dict[str, Any]], node: dict[str, Any], reason: str, now: float, recover_now: bool = True) -> None:
        node_id = str(node["id"])
        if not self.config.quarantine_enabled:
            self._bump_statistic("actions", "suppressed")
            log_event("quarantine_suppressed", node_id=node_id, node_name=node.get("name"), reason=reason, quarantine_enabled=False)
            return
        state = self._state_for(node_id)
        if not self._can_quarantine(nodes, node_id):
            self._bump_statistic("actions", "suppressed")
            log_event("quarantine_suppressed", node_id=node_id, node_name=node.get("name"), reason=reason, minimum_healthy=self.config.min_healthy_nodes)
            return
        previous_state = dict(state)
        source = "passive" if not recover_now else "active"
        repeats = int(state.get("passive_degrade_repeats", 0))
        if source == "passive":
            repeats += 1
        scale = min(8, 2 ** max(0, repeats - 1)) if source == "passive" else 1
        if reason == "missing_thinking":
            scale = max(scale, 4)
        state.update({
            "active_soft_strikes": 0,
            "passive_soft_strikes": 0,
            "error_strikes": 0,
            "quarantined_until": now + self.config.quarantine_seconds * scale,
            "disabled_by_guard": True,
            "last_reason": reason,
            "quarantine_source": source,
            "passive_degrade_repeats": repeats if source == "passive" else int(state.get("passive_degrade_repeats", 0)),
        })
        # Persist ownership before changing backend scheduling state. A crash
        # after the API call can then be reconciled safely on restart.
        self._save()
        try:
            updated = self.api.set_enabled(node_id, False)
        except Exception as exc:
            state.clear()
            state.update(previous_state)
            self._save()
            log_event("quarantine_failed", node_id=node_id, node_name=node.get("name"), reason=reason, error_type=type(exc).__name__)
            return
        if updated != 1:
            state.clear()
            state.update(previous_state)
            self._save()
            log_event("quarantine_not_applied", node_id=node_id, node_name=node.get("name"), reason=reason, updated=updated)
            return
        node["enabled"] = False
        self._bump_statistic("actions", "quarantined")
        append_state_event(self.state, "node_quarantined", node_id=node_id, node_name=node.get("name"), reason=reason)
        self._save()
        log_event(
            "node_quarantined",
            node_id=node_id,
            node_name=node.get("name"),
            reason=reason,
            quarantine_seconds=self.config.quarantine_seconds,
            quarantine_hold_seconds=self.config.quarantine_seconds * scale,
            quarantine_source=source,
            degrade_repeats=repeats if source == "passive" else 0,
            recover_now=recover_now,
        )
        if recover_now:
            if reason == "buffered_burst":
                self._recover_quarantined(node, time.time(), rotate=self._should_rotate(str(node["id"]), "buffered_burst"), rotate_on_failure=True)
            elif self._should_rotate(node_id, reason):
                self._recover_quarantined(node, time.time(), rotate=True)
        elif self._should_rotate(node_id, reason):
            try:
                rotation = self.api.rotate_node(node_id, str(node.get("exitIp") or ""))
            except Exception as exc:
                state["rotation_failures"] = int(state.get("rotation_failures", 0)) + 1
                log_event("node_rotation_failed", node_id=node_id, node_name=node.get("name"), error_type=type(exc).__name__, trigger="passive_hold")
            else:
                state.update({
                    "last_rotation_at": time.time(),
                    "last_rotation_exit_ip": str(rotation.get("newExitIp") or ""),
                    "rotation_failures": 0,
                })
                append_state_event(self.state, "node_rotated", node_id=node_id, node_name=node.get("name"), exit_ip=str(rotation.get("newExitIp") or ""))
                self._save()
                log_event("node_rotated", node_id=node_id, node_name=node.get("name"), exit_ip=str(rotation.get("newExitIp") or ""), trigger="passive_hold")

    def _record_probe(self, node: dict[str, Any], result: dict[str, Any], classification: str, reason: str, now: float) -> None:
        node_id = str(node["id"])
        state = self._state_for(node_id)
        output_tokens = int(result.get("outputTokens") or result.get("visibleTokens") or 0)
        output_tps_value = result.get("outputTokensPerSecond")
        if output_tps_value is None:
            output_tps_value = result.get("visibleTokensPerSecond")
        output_tps = float(output_tps_value or 0.0)
        state["last_probe_at"] = now
        state.update({
            "last_observed_at": now,
            "last_source": "active",
            "last_classification": classification,
            "last_output_tps": round(output_tps, 3),
            "last_output_tokens": output_tokens,
            "last_reasoning_tokens": max(0, int(result.get("reasoningTokens") or result.get("reasoning_tokens") or 0)),
            "last_first_token_ms": int(result.get("firstTokenMs") or 0),
            "last_duration_ms": int(result.get("durationMs") or 0),
        })
        self._update_ttft_ewma(node_id, int(result.get("firstTokenMs") or 0))
        state["error_strikes"] = 0
        self._bump_statistic("active", classification)
        self._bump_statistic("active", "output_tokens", output_tokens)
        if classification == "healthy":
            state["active_soft_strikes"] = 0
            state["passive_soft_strikes"] = 0
        elif classification == "soft":
            state["active_soft_strikes"] = int(state.get("active_soft_strikes", 0)) + 1
        else:
            state["active_soft_strikes"] = self.config.consecutive_soft
        log_event(
            "quality_probe_completed",
            node_id=node_id,
            node_name=node.get("name"),
            classification=classification,
            reason=reason,
            output_tps=round(output_tps, 3),
            output_tokens=output_tokens,
            reasoning_tokens=max(0, int(result.get("reasoningTokens") or result.get("reasoning_tokens") or 0)),
            first_token_ms=int(result.get("firstTokenMs") or 0),
            duration_ms=int(result.get("durationMs") or 0),
            chunk_count=int(result.get("chunkCount") or 0),
            expected_matched=bool(result.get("expectedMatched")),
        )

    def _probe_active(self, nodes: list[dict[str, Any]], node: dict[str, Any], now: float, trigger: str = "scheduled") -> None:
        node_id = str(node["id"])
        state = self._state_for(node_id)
        if state.get("last_reason") == "probe_no_account" and now < float(state.get("quarantined_until", 0.0)):
            return
        self._bump_statistic("active", "total")
        try:
            result = self.api.quality_test(node_id)
        except Exception as exc:
            if self._probe_account_unavailable(exc):
                self._defer_no_account(state, node, now, "quality_probe_deferred", trigger=trigger)
                return
            self._bump_statistic("active", "errors")
            state["error_strikes"] = int(state.get("error_strikes", 0)) + 1
            state["last_probe_at"] = now
            log_event("quality_probe_failed", node_id=node_id, node_name=node.get("name"), trigger=trigger, error_type=type(exc).__name__, strikes=state["error_strikes"])
            if trigger == "scheduled" and state["error_strikes"] >= self.config.consecutive_errors:
                self._quarantine(nodes, node, "probe_errors", now)
            return
        classification, reason = classify_result(result, self.config)
        self._record_probe(node, result, classification, reason, now)
        if classification == "hard" or (
            classification == "soft" and self.config.fail_closed
        ) or int(state.get("active_soft_strikes", 0)) >= self.config.consecutive_soft:
            self._quarantine(nodes, node, reason, now)

    def _recover_quarantined(
        self,
        node: dict[str, Any],
        now: float,
        rotate: bool,
        rotate_on_failure: bool = False,
    ) -> None:
        node_id = str(node["id"])
        state = self._state_for(node_id)
        if rotate:
            try:
                rotation = self.api.rotate_node(node_id, str(node.get("exitIp") or ""))
            except Exception as exc:
                state["rotation_failures"] = int(state.get("rotation_failures", 0)) + 1
                state["quarantined_until"] = now + self.config.quarantine_seconds
                state["last_reason"] = "rotation_error"
                log_event("node_rotation_failed", node_id=node_id, node_name=node.get("name"), error_type=type(exc).__name__)
                return
            state.update({
                "last_rotation_at": time.time(),
                "last_rotation_exit_ip": str(rotation.get("newExitIp") or ""),
                "rotation_failures": 0,
            })
            append_state_event(
                self.state,
                "node_rotated",
                node_id=node_id,
                node_name=node.get("name"),
                exit_ip=str(rotation.get("newExitIp") or ""),
            )
            log_event("node_rotated", node_id=node_id, node_name=node.get("name"), exit_ip=str(rotation.get("newExitIp") or ""))
            self._save()
        try:
            try:
                connectivity = self.api.connectivity_test(node_id)
                connectivity_status = str(connectivity.get("status") or "unknown")
            except Exception as exc:
                connectivity_status = "error"
                log_event("recovery_connectivity_probe_failed", node_id=node_id, node_name=node.get("name"), error_type=type(exc).__name__)
            self._bump_statistic("active", "total")
            result = self.api.quality_test(node_id)
            classification, reason = classify_result(result, self.config)
            self._record_probe(node, result, classification, reason, now)
        except Exception as exc:
            if self._probe_account_unavailable(exc):
                self._defer_no_account(state, node, now, "recovery_probe_deferred")
                return
            self._bump_statistic("active", "errors")
            state["quarantined_until"] = now + self.config.quarantine_seconds
            state["last_reason"] = "recovery_probe_error"
            log_event("recovery_probe_failed", node_id=node_id, node_name=node.get("name"), error_type=type(exc).__name__)
            return
        if classification != "healthy":
            state["quarantined_until"] = now + self.config.quarantine_seconds
            state["last_reason"] = reason
            log_event("quarantine_extended", node_id=node_id, node_name=node.get("name"), reason=reason)
            # A probe is a real routed request too. Remove the account that
            # produced a degraded probe before selecting the next retry.
            self._force_probe_account_switch(result, reason, now)
            if rotate_on_failure and self._should_rotate(node_id, reason):
                self._recover_quarantined(node, time.time(), rotate=True)
            return
        after_passive = self._is_passive_quarantine(state)
        updated = self.api.set_enabled(node_id, True)
        if updated != 1:
            log_event("restore_not_applied", node_id=node_id, node_name=node.get("name"), updated=updated)
            return
        state.update({
            "active_soft_strikes": 0,
            "passive_soft_strikes": 0,
            "error_strikes": 0,
            "quarantined_until": 0.0,
            "disabled_by_guard": False,
            "last_reason": "",
            "quarantine_source": "",
        })
        node["enabled"] = True
        self._bump_statistic("actions", "restored")
        append_state_event(self.state, "node_restored", node_id=node_id, node_name=node.get("name"), reason="quality_probe_healthy")
        log_event(
            "node_restored",
            node_id=node_id,
            node_name=node.get("name"),
            connectivity_status=connectivity_status,
            reason="quality_probe_healthy",
            after_passive_hold=after_passive,
            expected_matched=bool(result.get("expectedMatched")),
        )

    @staticmethod
    def _is_passive_quarantine(state: dict[str, Any]) -> bool:
        source = str(state.get("quarantine_source") or "")
        if source == "passive":
            return True
        if source == "active":
            return False
        return str(state.get("last_source") or "") == "passive"

    def _restore_after_hold(self, node: dict[str, Any], now: float) -> None:
        node_id = str(node["id"])
        state = self._state_for(node_id)
        updated = self.api.set_enabled(node_id, True)
        if updated != 1:
            log_event("restore_not_applied", node_id=node_id, node_name=node.get("name"), updated=updated)
            return
        state.update({
            "active_soft_strikes": 0,
            "passive_soft_strikes": 0,
            "error_strikes": 0,
            "quarantined_until": 0.0,
            "disabled_by_guard": False,
            "last_reason": "",
            "quarantine_source": "",
        })
        node["enabled"] = True
        self._bump_statistic("actions", "restored")
        append_state_event(self.state, "node_restored", node_id=node_id, node_name=node.get("name"), reason="thinking_hold_expired")
        log_event(
            "node_restored",
            node_id=node_id,
            node_name=node.get("name"),
            reason="thinking_hold_expired",
            quality_probe_authoritative=False,
            at=now,
        )

    def _probe_quarantined(self, node: dict[str, Any], now: float) -> None:
        node_id = str(node["id"])
        state = self._state_for(node_id)
        if now < float(state.get("quarantined_until", 0.0)):
            return
        reason = str(state.get("last_reason") or "")
        # Every quarantine, including missing_thinking, must pass an
        # authoritative quality probe before the node is made schedulable.
        # A failed recovery probe stays quarantined and _recover_quarantined
        # rotates the sticky exit before retrying when the node is rotatable.
        passive = self._is_passive_quarantine(state)
        self._recover_quarantined(
            node,
            now,
            rotate=(not passive) and self._should_rotate(node_id, reason) and reason != "buffered_burst",
            rotate_on_failure=passive or reason == "buffered_burst",
        )

    def _prepare_nodes(self, now: float) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str]]:
        all_nodes = self.api.list_nodes()
        protected_node_ids = self.api.fixed_fallback_node_ids()
        previous_protected = set(str(value) for value in self.state.get("protected_node_ids", []))
        if protected_node_ids != previous_protected:
            self.state["protected_node_ids"] = sorted(protected_node_ids)
            for node_id in sorted(protected_node_ids - previous_protected):
                log_event("fixed_fallback_node_skipped", node_id=node_id)
        state_nodes = self.state.setdefault("nodes", {})
        # Making an enabled node a fixed fallback is an explicit operator
        # override. Relinquish stale guard ownership before eligibility checks
        # so strict mode cannot repeatedly attempt an invalid disable. A
        # protected node that is still disabled remains tracked until recovery.
        for node in all_nodes:
            node_id = str(node.get("id") or "")
            state = state_nodes.get(node_id) or {}
            if node_id not in protected_node_ids or not node.get("enabled") or not state.get("disabled_by_guard"):
                continue
            state.update({
                "active_soft_strikes": 0,
                "passive_soft_strikes": 0,
                "error_strikes": 0,
                "quarantined_until": 0.0,
                "disabled_by_guard": False,
                "last_reason": "",
            })
            log_event("fixed_fallback_guard_released", node_id=node_id, node_name=node.get("name"))
        if not self.config.node_ids:
            self._resolved_node_ids = [
                str(node["id"]) for node in all_nodes
                if node.get("id") and node.get("proxyConfigured") and str(node["id"]) not in protected_node_ids
            ]
        nodes = self._eligible_nodes(all_nodes, protected_node_ids)
        present_ids = {str(node.get("id")) for node in all_nodes if node.get("id")}
        managed_ids = {str(node.get("id")) for node in nodes if node.get("id")}
        for stale_id in list(state_nodes):
            tracked = bool((state_nodes.get(stale_id) or {}).get("disabled_by_guard"))
            if stale_id not in present_ids or (stale_id not in managed_ids and not tracked):
                del state_nodes[stale_id]
        skip_ids: set[str] = set()
        if not nodes:
            log_event("no_eligible_nodes")
            return all_nodes, [], skip_ids
        for node in nodes:
            node_id = str(node["id"])
            state = self._state_for(node_id)
            if not self.config.quarantine_enabled and state.get("disabled_by_guard"):
                state.update({
                    "active_soft_strikes": 0,
                    "passive_soft_strikes": 0,
                    "error_strikes": 0,
                    "quarantined_until": 0.0,
                    "disabled_by_guard": False,
                    "last_reason": "",
                    "quarantine_source": "",
                })
                self._save()
                log_event("quarantine_ownership_released", node_id=node_id, node_name=node.get("name"), quarantine_enabled=False)
            if state.get("disabled_by_guard") and node.get("enabled"):
                if self.config.fail_closed:
                    updated = self.api.set_enabled(node_id, False)
                    if updated == 1:
                        node["enabled"] = False
                        log_event("operator_reenable_requires_probe", node_id=node_id, node_name=node.get("name"))
                        if now >= float(state.get("quarantined_until", 0.0)):
                            reason = str(state.get("last_reason") or "")
                            passive = self._is_passive_quarantine(state)
                            self._recover_quarantined(
                                node,
                                now,
                                rotate=(not passive) and self._should_rotate(node_id, reason) and reason != "buffered_burst",
                                rotate_on_failure=passive or reason == "buffered_burst",
                            )
                    skip_ids.add(node_id)
                    continue
                state.update({
                    "active_soft_strikes": 0,
                    "passive_soft_strikes": 0,
                    "error_strikes": 0,
                    "quarantined_until": 0.0,
                    "disabled_by_guard": False,
                    "last_reason": "",
                })
                log_event("operator_reenabled_node", node_id=node_id, node_name=node.get("name"))
                skip_ids.add(node_id)
                continue
            if state.get("disabled_by_guard"):
                skip_ids.add(node_id)
                self._probe_quarantined(node, now)
        return all_nodes, nodes, skip_ids


    def _update_ttft_ewma(self, node_id: str, first_token_ms: int) -> None:
        if first_token_ms is None or int(first_token_ms) <= 0:
            return
        state = self._state_for(node_id)
        sample = float(first_token_ms)
        alpha = float(self.rank.get("ewma_alpha") or 0.3)
        prev = float(state.get("ewma_first_token_ms") or 0.0)
        samples = int(state.get("ewma_samples") or 0)
        if samples <= 0 or prev <= 0:
            state["ewma_first_token_ms"] = sample
        else:
            state["ewma_first_token_ms"] = alpha * sample + (1.0 - alpha) * prev
        state["ewma_samples"] = samples + 1

    def _rank_eligible_nodes(
        self,
        nodes: list[dict[str, Any]],
        protected_node_ids: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        protected = protected_node_ids or set()
        configured = set(self.config.node_ids)
        min_samples = int(self.rank.get("min_samples") or 3)
        ranked: list[dict[str, Any]] = []
        for node in nodes:
            node_id = str(node.get("id") or "")
            if not node_id or not node.get("enabled") or not node.get("proxyConfigured"):
                continue
            if configured and node_id not in configured:
                continue
            if node_id in protected:
                continue
            state = self._state_for(node_id)
            if state.get("disabled_by_guard"):
                continue
            if float(state.get("quarantined_until") or 0) > time.time():
                continue
            samples = int(state.get("ewma_samples") or 0)
            ewma = float(state.get("ewma_first_token_ms") or 0.0)
            if ewma <= 0 and int(state.get("last_first_token_ms") or 0) > 0:
                ewma = float(state["last_first_token_ms"])
            soft = int(state.get("passive_soft_strikes") or 0) + int(state.get("active_soft_strikes") or 0)
            penalty = max(0.4, 1.0 - 0.15 * soft)
            if str(state.get("last_classification") or "") == "hard":
                penalty *= 0.5
            if samples < min_samples or ewma <= 0:
                score = 0.0
                under_sampled = True
            else:
                score = (1.0 / max(ewma, 1.0)) * penalty
                under_sampled = False
            current = int(node.get("assignedAccountCount") or 0)
            ranked.append({
                "node": node,
                "node_id": node_id,
                "name": node.get("name"),
                "ewma_ft": round(ewma, 1),
                "samples": samples,
                "score": score,
                "under_sampled": under_sampled,
                "penalty": round(penalty, 3),
                "current": current,
            })
        ranked.sort(key=lambda row: (-row["score"], row["ewma_ft"] if row["ewma_ft"] > 0 else 10**9, row["node_id"]))
        for idx, row in enumerate(ranked, start=1):
            row["position"] = idx
            st = self._state_for(row["node_id"])
            st["rank_position"] = idx
            st["rank_score"] = round(float(row["score"]), 8)
        return ranked

    def _compute_targets(self, ranked: list[dict[str, Any]], total_auto: int) -> dict[str, int]:
        n = len(ranked)
        if n == 0 or total_auto <= 0:
            for row in ranked:
                row["target"] = 0
                row["share"] = 0.0
                row["delta"] = -int(row.get("current") or 0)
            return {row["node_id"]: 0 for row in ranked}
        floor_share = float(self.rank.get("floor_share") or 0.03)
        max_share = float(self.rank.get("max_share") or 0.18)
        floor_share = min(floor_share, 0.9 / n)
        max_share = max(max_share, floor_share)
        scored = [row for row in ranked if not row["under_sampled"] and row["score"] > 0]
        score_sum = sum(row["score"] for row in scored) or 0.0
        residual = max(0.0, 1.0 - floor_share * n)
        raw_shares: dict[str, float] = {}
        for row in ranked:
            base = floor_share
            if score_sum > 0 and not row["under_sampled"] and row["score"] > 0:
                base += residual * (row["score"] / score_sum)
            elif score_sum <= 0:
                base = 1.0 / n
            raw_shares[row["node_id"]] = min(base, max_share)
        share_sum = sum(raw_shares.values()) or 1.0
        for node_id in raw_shares:
            raw_shares[node_id] = raw_shares[node_id] / share_sum
        exact = {node_id: total_auto * share for node_id, share in raw_shares.items()}
        targets = {node_id: int(value) for node_id, value in exact.items()}
        remain = total_auto - sum(targets.values())
        order = sorted(exact.keys(), key=lambda nid: (exact[nid] - targets[nid]), reverse=True)
        for node_id in order:
            if remain <= 0:
                break
            targets[node_id] += 1
            remain -= 1
        cap = max(1, int(total_auto * max_share))
        overflow = 0
        for node_id in list(targets):
            if targets[node_id] > cap:
                overflow += targets[node_id] - cap
                targets[node_id] = cap
        if overflow:
            for row in ranked:
                if overflow <= 0:
                    break
                nid = row["node_id"]
                room = cap - targets[nid]
                if room <= 0:
                    continue
                take = min(room, overflow)
                targets[nid] += take
                overflow -= take
        for row in ranked:
            nid = row["node_id"]
            share = targets.get(nid, 0) / total_auto if total_auto else 0.0
            row["target"] = targets.get(nid, 0)
            row["share"] = round(share, 4)
            row["delta"] = int(row["target"]) - int(row["current"])
            st = self._state_for(nid)
            st["target_accounts"] = int(row["target"])
            st["target_share"] = float(row["share"])
            st["last_rank_at"] = time.time()
        return targets

    def _admin_client(self) -> AdminApiClient | None:
        if self._admin is not None:
            return self._admin
        user = str(self.rank.get("admin_username") or "")
        password = str(self.rank.get("admin_password") or "")
        if not user or not password:
            return None
        client = AdminApiClient(
            base_url=self.config.base_url,
            username=user,
            password=password,
            timeout_seconds=min(60, self.config.request_timeout_seconds),
            ssl_context=self.api.ssl_context,
        )
        client.login()
        self._admin = client
        return client

    def _plan_moves(
        self,
        ranked: list[dict[str, Any]],
        by_node: dict[str, list[str]],
    ) -> list[dict[str, str]]:
        donors: list[tuple[str, list[str]]] = []
        receivers: list[tuple[str, int]] = []
        for row in ranked:
            nid = row["node_id"]
            delta = int(row.get("delta") or 0)
            ids = list(by_node.get(nid) or [])
            if delta < 0 and ids:
                donors.append((nid, ids[: max(0, -delta)]))
            elif delta > 0:
                receivers.append((nid, delta))
        moves: list[dict[str, str]] = []
        di = 0
        donor_pos = 0
        for recv_id, need in receivers:
            while need > 0 and di < len(donors):
                src_id, bag = donors[di]
                if donor_pos >= len(bag):
                    di += 1
                    donor_pos = 0
                    continue
                aid = bag[donor_pos]
                donor_pos += 1
                moves.append({"account_id": aid, "from": src_id, "to": recv_id})
                need -= 1
            if di < len(donors) and donor_pos >= len(donors[di][1]):
                di += 1
                donor_pos = 0
        max_moves = int(self.rank.get("max_moves") or 30)
        if max_moves <= 0:
            return []
        total_auto = sum(len(v) for v in by_node.values())
        pct_cap = int(total_auto * (float(self.rank.get("max_move_pct") or 5.0) / 100.0))
        cap = max_moves
        if pct_cap > 0:
            cap = min(cap, max(1, pct_cap))
        return moves[:cap]

    def _apply_moves(self, moves: list[dict[str, str]], dry_run: bool) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        if not moves:
            return results
        if dry_run:
            for move in moves:
                log_event("rank_move_planned", **move)
                results.append({**move, "status": "planned"})
            return results
        admin = self._admin_client()
        if admin is None:
            log_event("rank_skipped", reason="no_admin_credentials")
            for move in moves:
                results.append({**move, "status": "skipped_no_admin"})
            return results
        batches: dict[str, list[str]] = {}
        meta: dict[str, list[dict[str, str]]] = {}
        for move in moves:
            batches.setdefault(move["to"], []).append(move["account_id"])
            meta.setdefault(move["to"], []).append(move)
        for dest, ids in batches.items():
            try:
                for offset in range(0, len(ids), 50):
                    chunk = ids[offset:offset + 50]
                    result = admin.assign_accounts(dest, chunk, mode="auto")
                    assigned = int(result.get("assigned") or len(chunk))
                    for move in meta[dest][offset:offset + len(chunk)]:
                        log_event("rank_move_applied", **move, assigned=assigned)
                        results.append({**move, "status": "applied"})
            except Exception as exc:
                for move in meta[dest]:
                    log_event("rank_move_failed", **move, error_type=type(exc).__name__)
                    results.append({**move, "status": "failed", "error": type(exc).__name__})
        return results

    def run_rank_cycle(self, nodes: list[dict[str, Any]] | None = None) -> None:
        rank = self.rank
        if not rank.get("enabled"):
            return
        now = time.time()
        ranking_state = self.state.setdefault("ranking", {})
        last_run = float(ranking_state.get("last_run_at") or 0.0)
        interval = float(rank.get("interval_seconds") or 120)
        if last_run and now - last_run < interval:
            return
        try:
            all_nodes = nodes if nodes is not None else self.api.list_nodes()
        except Exception as exc:
            log_event("rank_skipped", reason="list_nodes_failed", error_type=type(exc).__name__)
            return
        try:
            protected = self.api.fixed_fallback_node_ids()
        except Exception:
            protected = set()
        ranked = self._rank_eligible_nodes(all_nodes, protected)
        if len(ranked) < 1:
            log_event("rank_skipped", reason="no_eligible_nodes")
            ranking_state["last_run_at"] = now
            self._save()
            return
        dry_run = bool(rank.get("dry_run", True))
        admin = None
        by_node: dict[str, list[str]] = {}
        try:
            admin = self._admin_client()
        except Exception as exc:
            log_event("rank_admin_login_failed", error_type=type(exc).__name__)
            admin = None
        if admin is not None:
            try:
                full = admin.list_auto_account_ids_by_node()
                eligible_ids = {row["node_id"] for row in ranked}
                by_node = {nid: ids for nid, ids in full.items() if nid in eligible_ids}
                for row in ranked:
                    row["current"] = len(by_node.get(row["node_id"]) or [])
            except Exception as exc:
                log_event("rank_list_accounts_failed", error_type=type(exc).__name__)
                by_node = {}
                admin = None
        total_auto = sum(int(row["current"]) for row in ranked)
        self._compute_targets(ranked, total_auto)
        table = []
        for row in ranked:
            table.append({
                "node_id": row["node_id"],
                "name": row.get("name"),
                "position": row.get("position"),
                "ewma_ft": row.get("ewma_ft"),
                "samples": row.get("samples"),
                "score": round(float(row.get("score") or 0.0), 8),
                "under_sampled": row.get("under_sampled"),
                "current": row.get("current"),
                "target": row.get("target"),
                "share": row.get("share"),
                "delta": row.get("delta"),
            })
        log_event(
            "rank_table",
            dry_run=dry_run or admin is None,
            total_auto=total_auto,
            node_count=len(table),
            table=table,
        )
        if admin is None:
            summary = []
            for row in ranked:
                delta = int(row.get("delta") or 0)
                if delta:
                    summary.append({
                        "node_id": row["node_id"],
                        "name": row.get("name"),
                        "delta": delta,
                        "current": row.get("current"),
                        "target": row.get("target"),
                    })
            if summary:
                log_event("rank_move_planned", mode="count_only", changes=summary, reason="no_admin")
            applied: list[dict[str, Any]] = [{"status": "planned_count_only", **item} for item in summary]
        else:
            moves = self._plan_moves(ranked, by_node)
            applied = self._apply_moves(moves, dry_run=dry_run)
        ranking_state["last_run_at"] = now
        ranking_state["dry_run"] = dry_run or admin is None
        ranking_state["last_table"] = table
        ranking_state["last_moves"] = applied[:100]
        self._save()

    def run_active_cycle(self) -> None:
        now = time.time()
        all_nodes, nodes, skip_ids = self._prepare_nodes(now)
        for node in nodes:
            node_id = str(node["id"])
            state = self._state_for(node_id)
            if node_id not in skip_ids and node.get("enabled") and not state.get("disabled_by_guard"):
                self._probe_active(all_nodes, node, now)
            self._save()
        self.state["last_active_cycle_at"] = time.time()
        self._save()
        try:
            self.run_rank_cycle(all_nodes)
        except Exception as exc:
            log_event("rank_cycle_failed", error_type=type(exc).__name__, trigger="active")

    def _fetch_new_audits(self) -> list[dict[str, Any]]:
        known = set(str(value) for value in self.state.get("seen_audit_ids", []))
        fetched_ids: list[str] = []
        collected: list[dict[str, Any]] = []
        cursor = ""
        reached_known = False
        for _page in range(self.config.passive_max_pages):
            page = self.api.list_audits(cursor)
            items = list(page.get("items") or [])
            if not items:
                break
            for item in items:
                audit_id = str(item.get("id") or item.get("requestId") or "")
                if not audit_id:
                    continue
                fetched_ids.append(audit_id)
                if audit_id in known:
                    reached_known = True
                    break
                collected.append(item)
            if reached_known or not page.get("hasMore"):
                break
            cursor = str(page.get("nextCursor") or "")
            if not cursor:
                break

        combined = []
        seen = set()
        for audit_id in [*fetched_ids, *self.state.get("seen_audit_ids", [])]:
            audit_id = str(audit_id)
            if audit_id and audit_id not in seen:
                seen.add(audit_id)
                combined.append(audit_id)
            if len(combined) >= 2000:
                break
        self.state["seen_audit_ids"] = combined
        if not self.state.get("passive_initialized"):
            self.state["passive_initialized"] = True
            log_event("passive_baseline_initialized", audit_count=len(fetched_ids))
            return []
        if collected and not reached_known and known:
            log_event("passive_audit_gap", collected=len(collected), max_pages=self.config.passive_max_pages)
        collected.reverse()
        return collected

    def _record_passive_audit(self, all_nodes: list[dict[str, Any]], node: dict[str, Any], audit_value: dict[str, Any], now: float) -> None:
        node_id = str(node["id"])
        state = self._state_for(node_id)
        classification, reason, speed, output_tokens = classify_audit(audit_value, self.config)
        if classification == "ignored":
            return
        self._bump_statistic("passive", "total")
        self._bump_statistic("passive", classification)
        self._bump_statistic("passive", "output_tokens", output_tokens)
        state.update({
            "last_observed_at": now,
            "last_source": "passive",
            "last_classification": classification,
            "last_output_tps": round(speed, 3),
            "last_output_tokens": output_tokens,
            "last_first_token_ms": int(audit_value.get("firstTokenMs") or 0),
            "last_duration_ms": int(audit_value.get("durationMs") or 0),
        })
        self._update_ttft_ewma(node_id, int(audit_value.get("firstTokenMs") or 0))
        if classification == "healthy":
            state["passive_soft_strikes"] = 0
            state["passive_degrade_repeats"] = 0
            return
        if classification == "soft":
            state["passive_soft_strikes"] = int(state.get("passive_soft_strikes", 0)) + 1
        else:
            state["passive_soft_strikes"] = self.config.consecutive_soft
        append_state_event(
            self.state,
            "passive_audit_anomaly",
            node_id=node_id,
            node_name=node.get("name"),
            reason=reason,
            classification=classification,
            output_tps=round(speed, 3),
        )
        log_event(
            "passive_audit_anomaly",
            request_id=audit_value.get("requestId"),
            node_id=node_id,
            node_name=node.get("name"),
            classification=classification,
            reason=reason,
            output_tps=round(speed, 3),
            output_tokens=output_tokens,
            first_token_ms=int(audit_value.get("firstTokenMs") or 0),
            duration_ms=int(audit_value.get("durationMs") or 0),
            strikes=int(state.get("passive_soft_strikes", 0)),
        )
        self._track_degraded_account(audit_value, reason, now)
        self._force_account_switch(audit_value, reason, now)
        # User-traffic degrade: isolate immediately and hold until quarantine_seconds.
        # Do not run the QUALITY_OK recovery probe in the same cycle — that was
        # restoring nodes a few seconds after a real user burst.
        log_event(
            "passive_immediate_quarantine",
            node_id=node_id,
            node_name=node.get("name"),
            classification=classification,
            reason=reason,
            output_tps=round(speed, 3),
        )
        self._quarantine(all_nodes, node, reason, now, recover_now=False)

    def run_passive_cycle(self) -> None:
        now = time.time()
        self.state["last_passive_poll_at"] = now
        self._restore_forced_account_switches(now)
        all_nodes, nodes, _skip_ids = self._prepare_nodes(now)
        node_by_id = {str(node["id"]): node for node in nodes}
        audits = self._fetch_new_audits()
        for value in audits:
            if bool(value.get("qualityProbe")):
                continue
            node = node_by_id.get(str(value.get("egressNodeId") or ""))
            if node is None or not node.get("enabled"):
                continue
            self._record_passive_audit(all_nodes, node, value, now)
        self._save()
        try:
            self.run_rank_cycle(all_nodes)
        except Exception as exc:
            log_event("rank_cycle_failed", error_type=type(exc).__name__, trigger="passive")

    # Backward-compatible name for callers that expect one active cycle.
    def run_cycle(self) -> None:
        self.run_active_cycle()


def acquire_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle = path.open("a+", encoding="utf-8")
    os.chmod(path, 0o600)
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise RuntimeError("another quality guard instance is already running")
    return handle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Active and passive quality guard for grok2api egress nodes")
    parser.add_argument("--once", action="store_true", help="run one cycle for each detector enabled by the selected mode")
    parser.add_argument("--check-config", action="store_true", help="validate config.yaml bootstrap and exit")
    args = parser.parse_args(argv)
    try:
        base_config = Config.from_bootstrap()
        reloader = RuntimeConfigReloader(base_config)
        config, _, runtime_error = reloader.reload(force=True)
        if runtime_error is not None:
            raise ValueError(str(runtime_error))
    except GuardDisabled as exc:
        print(str(exc))
        return 0
    except ValueError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if args.check_config:
        print("configuration is valid")
        return 0
    try:
        lock = acquire_lock(config.lock_file)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _ = lock
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    api = ApiClient(config)
    guard = Guard(config, api)
    if not config.enabled:
        guard.release_guard_owned_nodes()
    last_active_at = float(guard.state.get("last_active_cycle_at", 0.0))
    active_delay = max(0.0, last_active_at + config.active_interval_seconds - time.time())
    next_active = 0.0 if args.once else time.monotonic() + active_delay
    next_passive = 0.0
    log_event(
        "guard_started",
        mode=config.mode,
        active_interval_seconds=config.active_interval_seconds,
        passive_poll_seconds=config.passive_poll_seconds,
        node_count=len(config.node_ids),
        model=config.model,
        rank_scheduler_enabled=bool(guard.rank.get("enabled")),
        rank_dry_run=bool(guard.rank.get("dry_run")),
    )
    while not stopping:
        now = time.monotonic()
        next_config, changed, runtime_error = reloader.reload()
        if runtime_error is not None:
            log_event("runtime_config_rejected", error_type=type(runtime_error).__name__)
        elif changed:
            previous_mode = config.mode
            was_enabled = config.enabled
            config = next_config
            guard.config = config
            api.config = config
            guard._save()
            last_active_at = float(guard.state.get("last_active_cycle_at", 0.0))
            next_active = now + max(0.0, last_active_at + config.active_interval_seconds - time.time())
            next_passive = now
            log_event("runtime_config_reloaded", previous_mode=previous_mode, mode=config.mode)
            if was_enabled and not config.enabled:
                guard.release_guard_owned_nodes()
        active_enabled = config.enabled and config.mode in {"active", "hybrid"}
        passive_enabled = config.enabled and config.mode in {"passive", "hybrid"}
        if passive_enabled and now >= next_passive:
            try:
                guard.run_passive_cycle()
            except Exception as exc:
                log_event("passive_cycle_failed", error_type=type(exc).__name__)
            next_passive = time.monotonic() + config.passive_poll_seconds
        if active_enabled and now >= next_active:
            try:
                guard.run_active_cycle()
            except Exception as exc:
                log_event("active_cycle_failed", error_type=type(exc).__name__)
            jitter = random.uniform(-config.jitter_seconds, config.jitter_seconds)
            next_active = time.monotonic() + max(60.0, config.active_interval_seconds + jitter)
        if args.once:
            break
        deadlines = []
        if passive_enabled:
            deadlines.append(next_passive)
        if active_enabled:
            deadlines.append(next_active)
        delay = max(0.1, min(deadlines) - time.monotonic()) if deadlines else 1.0
        time.sleep(min(1.0, delay))
    log_event("guard_stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
