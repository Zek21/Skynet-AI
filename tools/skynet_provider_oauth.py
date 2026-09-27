#!/usr/bin/env python3
"""Read-only, token-safe OAuth availability inventory for Skynet providers.

The probe never verifies JWT signatures and never performs a provider network
request. JWT payloads are decoded only for non-secret expiry and plan metadata.
Credential values never enter a returned result, rendered table, or exception
message.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import sqlite3
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

PROVIDERS = ("codex", "codex_lane2", "claude", "antigravity")
GATE_BLOCKED = 2
EXPIRY_SOON_SECONDS = 60 * 60
UTC = dt.UTC


def _utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def _iso_utc(value: dt.datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_epoch(value: Any) -> dt.datetime | None:
    """Parse epoch seconds or milliseconds without confusing the two units."""
    if value is None or isinstance(value, bool):
        return None
    try:
        epoch = float(value)
    except (TypeError, ValueError):
        return None
    if abs(epoch) >= 100_000_000_000:
        epoch /= 1000.0
    try:
        return dt.datetime.fromtimestamp(epoch, tz=UTC)
    except (OSError, OverflowError, ValueError):
        return None


def _expiry_fields(
    expires_at: dt.datetime | None,
    now: dt.datetime,
) -> tuple[str | None, bool | None, bool | None]:
    if expires_at is None:
        return None, None, None
    remaining = (expires_at - now).total_seconds()
    return _iso_utc(expires_at), remaining <= 0, 0 < remaining < EXPIRY_SOON_SECONDS


def _read_json(path: Path) -> Mapping[str, Any] | None:
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("credential_store_root_not_object")
    return data


def _jwt_payload(token: Any) -> Mapping[str, Any]:
    """Decode only a JWT payload. Errors are deliberately content-free."""
    if not isinstance(token, str):
        return {}
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    try:
        payload = parts[1] + ("=" * (-len(parts[1]) % 4))
        decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
        value = json.loads(decoded.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _find_claim(value: Any, names: set[str]) -> Any:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in names and child not in (None, ""):
                return child
        for child in value.values():
            found = _find_claim(child, names)
            if found not in (None, ""):
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_claim(child, names)
            if found not in (None, ""):
                return found
    return None


def _opaque_hint(value: Any) -> str | None:
    text = str(value or "").strip()
    return text[-6:] if text else None


def _base_result(provider: str) -> dict[str, Any]:
    return {
        "provider": provider,
        "ok": True,
        "present": False,
        "auth_mode": "none",
        "expires_at": None,
        "expired": None,
        "expires_soon": None,
        "subscription": None,
        "plan": None,
        "account_hint": None,
        "status": "missing",
        "usable_oauth": False,
        "oauth_present": False,
        "api_key_configured": False,
        "prefer_oauth_violation": False,
    }


def _exception_result(provider: str, exc: BaseException) -> dict[str, Any]:
    result = _base_result(provider)
    result.update(
        {
            "ok": False,
            "status": "probe_exception",
            "error": type(exc).__name__,
        }
    )
    return result


def _codex_auth_mode(raw_mode: Any, oauth_present: bool, api_key_present: bool) -> str:
    normalized = str(raw_mode or "").strip().lower().replace("-", "_")
    if normalized in {"api_key", "apikey"}:
        return "api_key"
    if normalized in {"chatgpt", "oauth"} and oauth_present:
        return "oauth"
    if oauth_present:
        return "oauth"
    if api_key_present:
        return "api_key"
    return "none"


def probe_codex(
    provider: str,
    auth_file: Path,
    *,
    now: dt.datetime | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    now = now or _utc_now()
    environ = os.environ if environ is None else environ
    try:
        store = _read_json(auth_file)
        result = _base_result(provider)
        api_key_present = bool(environ.get("OPENAI_API_KEY"))
        if store is None:
            result["api_key_configured"] = api_key_present
            if api_key_present:
                result.update(
                    present=True,
                    auth_mode="api_key",
                    status="api_key_only",
                )
            return result

        tokens_raw = store.get("tokens")
        tokens = tokens_raw if isinstance(tokens_raw, dict) else {}
        access_token = tokens.get("access_token")
        id_token = tokens.get("id_token")
        refresh_token = tokens.get("refresh_token")
        oauth_present = any(
            isinstance(value, str) and bool(value)
            for value in (access_token, id_token, refresh_token)
        )
        api_key_present = api_key_present or bool(store.get("OPENAI_API_KEY"))
        access_claims = _jwt_payload(access_token)
        id_claims = _jwt_payload(id_token)
        expiry_value = _find_claim(access_claims, {"exp"})
        if expiry_value is None:
            expiry_value = _find_claim(id_claims, {"exp"})
        expires_at = parse_epoch(expiry_value)
        expires_iso, expired, expires_soon = _expiry_fields(expires_at, now)
        plan = _find_claim(
            id_claims,
            {"chatgpt_plan_type", "plan_type", "subscription_type"},
        )
        mode = _codex_auth_mode(store.get("auth_mode"), oauth_present, api_key_present)
        usable_oauth = oauth_present and expired is False
        result.update(
            present=oauth_present or api_key_present,
            auth_mode=mode,
            expires_at=expires_iso,
            expired=expired,
            expires_soon=expires_soon,
            plan=str(plan) if plan not in (None, "") else None,
            account_hint=_opaque_hint(tokens.get("account_id")),
            usable_oauth=usable_oauth,
            oauth_present=oauth_present,
            api_key_configured=api_key_present,
            prefer_oauth_violation=usable_oauth and mode == "api_key",
        )
        if mode == "api_key":
            result["status"] = (
                "api_key_selected_with_oauth"
                if usable_oauth
                else "api_key_only"
            )
        elif not oauth_present:
            result["status"] = "missing"
        elif expired is True:
            result["status"] = "expired"
        elif expired is None:
            result["status"] = "unknown_expiry"
        else:
            result["status"] = "usable"
        return result
    except Exception as exc:  # noqa: BLE001 - each provider must fail closed.
        return _exception_result(provider, exc)


def _claude_auth_mode(
    store: Mapping[str, Any],
    blob: Mapping[str, Any],
    oauth_present: bool,
    api_key_present: bool,
) -> str:
    raw_mode = blob.get("auth_mode") or blob.get("authMode") or store.get("auth_mode")
    normalized = str(raw_mode or "").strip().lower().replace("-", "_")
    if normalized in {"api_key", "apikey"}:
        return "api_key"
    if normalized == "oauth" and oauth_present:
        return "oauth"
    if api_key_present:
        return "api_key"
    if oauth_present:
        return "oauth"
    return "none"


def probe_claude(
    credentials_file: Path,
    *,
    now: dt.datetime | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    now = now or _utc_now()
    environ = os.environ if environ is None else environ
    try:
        store = _read_json(credentials_file)
        result = _base_result("claude")
        api_key_present = bool(environ.get("ANTHROPIC_API_KEY"))
        if store is None:
            result["api_key_configured"] = api_key_present
            if api_key_present:
                result.update(
                    present=True,
                    auth_mode="api_key",
                    status="api_key_only",
                )
            return result

        blob_raw = store.get("claudeAiOauth")
        blob = blob_raw if isinstance(blob_raw, dict) else {}
        oauth_present = bool(blob.get("accessToken") or blob.get("refreshToken"))
        api_key_present = api_key_present or bool(
            store.get("ANTHROPIC_API_KEY") or blob.get("apiKey")
        )
        expires_at = parse_epoch(blob.get("expiresAt"))
        expires_iso, expired, expires_soon = _expiry_fields(expires_at, now)
        mode = _claude_auth_mode(store, blob, oauth_present, api_key_present)
        usable_oauth = oauth_present and expired is False
        subscription = blob.get("subscriptionType")
        plan = blob.get("rateLimitTier")
        account_id = blob.get("accountId") or blob.get("account_id")
        result.update(
            present=oauth_present or api_key_present,
            auth_mode=mode,
            expires_at=expires_iso,
            expired=expired,
            expires_soon=expires_soon,
            subscription=str(subscription) if subscription not in (None, "") else None,
            plan=str(plan) if plan not in (None, "") else None,
            account_hint=_opaque_hint(account_id),
            usable_oauth=usable_oauth,
            oauth_present=oauth_present,
            api_key_configured=api_key_present,
            prefer_oauth_violation=usable_oauth and mode == "api_key",
        )
        if mode == "api_key":
            result["status"] = (
                "api_key_selected_with_oauth"
                if usable_oauth
                else "api_key_only"
            )
        elif not oauth_present:
            result["status"] = "missing"
        elif expired is True:
            result["status"] = "expired"
        elif expired is None:
            result["status"] = "unknown_expiry"
        else:
            result["status"] = "usable"
        return result
    except Exception as exc:  # noqa: BLE001 - each provider must fail closed.
        return _exception_result("claude", exc)


def _antigravity_tail(path: Path | None, limit: int = 200) -> list[str]:
    if path is None or not path.is_file():
        return []
    try:
        return path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()[-limit:]
    except OSError:
        return []


def _latest_antigravity_log(log_root: Path, name: str) -> Path | None:
    if not log_root.is_dir():
        return None
    try:
        matches = sorted(
            log_root.glob(f"**/{name}"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return None
    return matches[0] if matches else None


def _antigravity_sql_value(state_db: Path, key: str) -> str | None:
    if not state_db.is_file():
        return None
    try:
        connection = sqlite3.connect(str(state_db))
        try:
            row = connection.cursor().execute(
                "select value from ItemTable where key=?",
                (key,),
            ).fetchone()
            return row[0] if row else None
        finally:
            connection.close()
    except (OSError, sqlite3.Error):
        return None


def _decode_antigravity_state(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        text = base64.b64decode(raw).decode("utf-8", errors="ignore")
    except (ValueError, TypeError):
        return {}
    match = re.search(r"(\{.*\})", text)
    if not match:
        return {}
    try:
        decoded = json.loads(match.group(1))
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _default_antigravity_status() -> Mapping[str, Any]:
    fixture_path = os.environ.get("SKYNET_ANTIGRAVITY_STATUS_FILE")
    if fixture_path:
        status = _read_json(Path(fixture_path))
        return status or {}

    app_data = Path(
        os.environ.get("APPDATA")
        or Path.home() / "AppData" / "Roaming"
    )
    log_root = app_data / "Antigravity" / "logs"
    state_db = (
        app_data
        / "Antigravity"
        / "User"
        / "globalStorage"
        / "state.vscdb"
    )
    auth_lines = _antigravity_tail(
        _latest_antigravity_log(log_root, "auth.log")
    )
    language_server_lines = _antigravity_tail(
        _latest_antigravity_log(log_root, "ls-main.log")
    )
    oauth_raw = _antigravity_sql_value(
        state_db,
        "antigravityUnifiedStateSync.oauthToken",
    )
    decoded = _decode_antigravity_state(oauth_raw)
    runtime_state = None
    for line in reversed(auth_lines):
        match = re.search(
            r"Auth state changed to:\s+([A-Za-z0-9_]+)",
            line,
        )
        if match:
            runtime_state = match.group(1)
            break
    token_refresh_observed = any(
        "OAuth token changed" in line for line in auth_lines
    )
    backend_observed = any(
        host in line
        for line in language_server_lines
        for host in (
            "daily-cloudcode-pa.googleapis.com",
            "cloudcode-pa.googleapis.com",
        )
    )
    oauth_state = decoded.get("state")
    return {
        "auth_log_present": bool(auth_lines),
        "ls_log_present": bool(language_server_lines),
        "runtime_auth_state": runtime_state,
        "state_store": {
            "exists": state_db.is_file(),
            "oauth_token_present": bool(oauth_raw),
            "oauth_state": oauth_state,
        },
        "effective_authenticated": bool(
            runtime_state == "signedIn"
            and (token_refresh_observed or backend_observed)
        ),
        "store_signed_in": oauth_state == "signedIn",
    }


def probe_antigravity(
    *,
    status_reader: Callable[[], Mapping[str, Any]] = _default_antigravity_status,
    now: dt.datetime | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    now = now or _utc_now()
    environ = os.environ if environ is None else environ
    try:
        status = status_reader()
        if not isinstance(status, Mapping):
            raise ValueError("antigravity_status_not_object")
        result = _base_result("antigravity")
        api_key_present = bool(
            environ.get("GEMINI_API_KEY") or environ.get("GOOGLE_API_KEY")
        )
        state_store_raw = status.get("state_store")
        state_store = state_store_raw if isinstance(state_store_raw, Mapping) else {}
        runtime_state = str(status.get("runtime_auth_state") or "")
        oauth_state = str(state_store.get("oauth_state") or "")
        oauth_present = bool(
            status.get("effective_authenticated")
            or status.get("store_signed_in")
            or runtime_state == "signedIn"
            or oauth_state == "signedIn"
            or status.get("oauth_present")
        )
        readable_evidence = bool(
            status.get("auth_log_present")
            or status.get("ls_log_present")
            or state_store.get("exists")
            or "readable" in status
        )
        explicitly_unreadable = status.get("readable") is False
        expires_at = parse_epoch(status.get("expires_at") or status.get("expiresAt"))
        expires_iso, expired, expires_soon = _expiry_fields(expires_at, now)
        usable_oauth = oauth_present and expired is not True
        configured_mode = str(status.get("auth_mode") or "").lower().replace("-", "_")
        mode = "oauth" if oauth_present else "none"
        if configured_mode in {"api_key", "apikey"} or (api_key_present and not oauth_present):
            mode = "api_key"
        result.update(
            present=oauth_present or api_key_present,
            auth_mode=mode,
            expires_at=expires_iso,
            expired=expired,
            expires_soon=expires_soon,
            subscription=status.get("subscription"),
            plan=status.get("plan"),
            account_hint=_opaque_hint(
                status.get("account_id") or status.get("accountId")
            ),
            usable_oauth=usable_oauth,
            oauth_present=oauth_present,
            api_key_configured=api_key_present,
            prefer_oauth_violation=usable_oauth and mode == "api_key",
        )
        if explicitly_unreadable or (not readable_evidence and not oauth_present):
            result["status"] = "unknown"
        elif mode == "api_key":
            result["status"] = (
                "api_key_selected_with_oauth"
                if usable_oauth
                else "api_key_only"
            )
        elif oauth_present and expired is True:
            result["status"] = "expired"
        elif oauth_present:
            result["status"] = "usable"
        else:
            result["status"] = "missing"
        return result
    except Exception as exc:  # noqa: BLE001 - each provider must fail closed.
        return _exception_result("antigravity", exc)


def _default_paths(environ: Mapping[str, str]) -> dict[str, Path]:
    user_home = Path(environ.get("USERPROFILE") or Path.home())
    local_app_data = Path(environ.get("LOCALAPPDATA") or user_home / "AppData" / "Local")
    codex_home = Path(environ.get("CODEX_HOME") or user_home / ".codex")
    claude_home = Path(environ.get("CLAUDE_CONFIG_DIR") or user_home / ".claude")
    return {
        "codex": Path(
            environ.get("SKYNET_CODEX_AUTH_FILE") or codex_home / "auth.json"
        ),
        "codex_lane2": Path(
            environ.get("SKYNET_CODEX_LANE2_AUTH_FILE")
            or local_app_data / "Skynet" / "codex_lanes" / "codex_lane_2" / "auth.json"
        ),
        "claude": Path(
            environ.get("SKYNET_CLAUDE_CREDENTIALS_FILE")
            or claude_home / ".credentials.json"
        ),
    }


def collect_status(
    *,
    now: dt.datetime | None = None,
    environ: Mapping[str, str] | None = None,
    paths: Mapping[str, Path] | None = None,
    antigravity_reader: Callable[[], Mapping[str, Any]] = _default_antigravity_status,
) -> dict[str, Any]:
    now = now or _utc_now()
    environ = os.environ if environ is None else environ
    resolved_paths = dict(paths or _default_paths(environ))
    providers = {
        "codex": probe_codex(
            "codex", resolved_paths["codex"], now=now, environ=environ
        ),
        "codex_lane2": probe_codex(
            "codex_lane2",
            resolved_paths["codex_lane2"],
            now=now,
            environ=environ,
        ),
        "claude": probe_claude(
            resolved_paths["claude"], now=now, environ=environ
        ),
        "antigravity": probe_antigravity(
            status_reader=antigravity_reader,
            now=now,
            environ=environ,
        ),
    }
    return {
        "tool": "skynet_provider_oauth",
        "timestamp_utc": _iso_utc(now),
        "ok": all(row.get("ok") is True for row in providers.values()),
        "providers": providers,
    }


def evaluate_assertions(
    report: Mapping[str, Any],
    *,
    required: Sequence[str],
    prefer_oauth: bool,
    gate: bool,
) -> tuple[int, list[dict[str, str]]]:
    providers = report.get("providers")
    if not isinstance(providers, Mapping):
        return GATE_BLOCKED, [{"provider": "*", "reason": "invalid_report"}]
    failures: list[dict[str, str]] = []
    for name, row_raw in providers.items():
        row = row_raw if isinstance(row_raw, Mapping) else {}
        if row.get("ok") is not True:
            failures.append({"provider": str(name), "reason": "probe_exception"})
        if prefer_oauth and row.get("prefer_oauth_violation") is True:
            failures.append(
                {"provider": str(name), "reason": "api_key_selected_with_valid_oauth"}
            )
    if gate:
        for name in required:
            row_raw = providers.get(name)
            row = row_raw if isinstance(row_raw, Mapping) else {}
            if row.get("auth_mode") != "oauth" or row.get("usable_oauth") is not True:
                failures.append(
                    {"provider": name, "reason": str(row.get("status") or "oauth_unusable")}
                )
    return (GATE_BLOCKED if failures else 0), failures


def _render_table(report: Mapping[str, Any]) -> str:
    providers = report["providers"]
    columns = (
        ("provider", 15),
        ("present", 7),
        ("auth_mode", 9),
        ("status", 28),
        ("expires_at", 20),
        ("plan", 15),
        ("account_hint", 12),
    )
    lines = ["  ".join(name.ljust(width) for name, width in columns)]
    lines.append("  ".join(("-" * width) for _, width in columns))
    for name in PROVIDERS:
        row = providers[name]
        values = {
            "provider": name,
            "present": str(row["present"]).lower(),
            "auth_mode": str(row["auth_mode"]),
            "status": str(row["status"]),
            "expires_at": str(row["expires_at"] or "-"),
            "plan": str(row["subscription"] or row["plan"] or "-"),
            "account_hint": str(row["account_hint"] or "-"),
        }
        lines.append(
            "  ".join(values[column].ljust(width) for column, width in columns)
        )
    return "\n".join(lines)


def _flatten_required(groups: Sequence[Sequence[str]] | None) -> list[str]:
    return list(dict.fromkeys(name for group in (groups or []) for name in group))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Report usable provider OAuth without exposing credential values."
    )
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument(
        "--gate",
        action="store_true",
        help="exit 2 when a provider named by --require lacks usable OAuth",
    )
    parser.add_argument(
        "--require",
        action="append",
        nargs="+",
        choices=PROVIDERS,
        metavar="PROVIDER",
        help="provider(s) required by --gate; repeatable",
    )
    parser.add_argument(
        "--prefer-oauth",
        action="store_true",
        help="exit 2 when an API key is selected despite valid OAuth",
    )
    args = parser.parse_args(argv)

    report = collect_status()
    required = _flatten_required(args.require)
    exit_code, failures = evaluate_assertions(
        report,
        required=required,
        prefer_oauth=args.prefer_oauth,
        gate=args.gate,
    )
    report["assertions"] = {
        "gate": args.gate,
        "required": required,
        "prefer_oauth": args.prefer_oauth,
        "failures": failures,
        "ok": not failures,
    }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_render_table(report))
        if failures:
            print("\nOAuth assertion failures:", file=sys.stderr)
            for failure in failures:
                print(
                    f"  {failure['provider']}: {failure['reason']}",
                    file=sys.stderr,
                )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
