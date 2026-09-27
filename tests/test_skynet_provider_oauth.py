from __future__ import annotations

import base64
import datetime as dt
import json
from pathlib import Path

from tools import skynet_provider_oauth as oauth

UTC = dt.UTC
NOW = dt.datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def _fake_jwt(payload: dict[str, object], marker: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header}.{body}.{marker}"


def _write_json(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _paths(tmp_path: Path) -> dict[str, Path]:
    return {
        "codex": tmp_path / "codex" / "auth.json",
        "codex_lane2": tmp_path / "codex2" / "auth.json",
        "claude": tmp_path / "claude" / ".credentials.json",
    }


def test_claude_epoch_milliseconds_and_seconds_parse_same_instant(tmp_path: Path) -> None:
    instant = dt.datetime(2026, 8, 4, 12, 39, tzinfo=UTC)
    for index, epoch in enumerate(
        (int(instant.timestamp()), int(instant.timestamp() * 1000))
    ):
        credentials = _write_json(
            tmp_path / str(index) / ".credentials.json",
            {
                "claudeAiOauth": {
                    "accessToken": f"synthetic-access-{index}",
                    "refreshToken": f"synthetic-refresh-{index}",
                    "expiresAt": epoch,
                    "subscriptionType": "pro",
                }
            },
        )
        result = oauth.probe_claude(credentials, now=NOW, environ={})
        assert result["expires_at"] == "2026-08-04T12:39:00Z"
        assert result["expired"] is False
        assert result["auth_mode"] == "oauth"


def test_expired_claude_blocks_required_gate(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    _write_json(
        paths["claude"],
        {
            "claudeAiOauth": {
                "accessToken": "synthetic-expired-access",
                "refreshToken": "synthetic-expired-refresh",
                "expiresAt": int((NOW - dt.timedelta(minutes=1)).timestamp() * 1000),
            }
        },
    )
    report = oauth.collect_status(
        now=NOW,
        environ={},
        paths=paths,
        antigravity_reader=lambda: {"readable": False},
    )
    assert report["providers"]["claude"]["expired"] is True
    exit_code, failures = oauth.evaluate_assertions(
        report,
        required=["claude"],
        prefer_oauth=False,
        gate=True,
    )
    assert exit_code == 2
    assert failures == [{"provider": "claude", "reason": "expired"}]


def test_api_key_selected_with_valid_oauth_blocks_preference(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    exp = int((NOW + dt.timedelta(days=1)).timestamp())
    _write_json(
        paths["codex"],
        {
            "auth_mode": "api_key",
            "OPENAI_API_KEY": "synthetic-api-key-never-output",
            "tokens": {
                "access_token": _fake_jwt({"exp": exp}, "access-signature"),
                "refresh_token": "placeholder-refresh-token",
                "account_id": "acct_synthetic_123456",
            },
        },
    )
    report = oauth.collect_status(
        now=NOW,
        environ={},
        paths=paths,
        antigravity_reader=lambda: {"readable": False},
    )
    row = report["providers"]["codex"]
    assert row["usable_oauth"] is True
    assert row["auth_mode"] == "api_key"
    exit_code, failures = oauth.evaluate_assertions(
        report,
        required=[],
        prefer_oauth=True,
        gate=False,
    )
    assert exit_code == 2
    assert failures == [
        {"provider": "codex", "reason": "api_key_selected_with_valid_oauth"}
    ]


def test_unreadable_or_absent_antigravity_keyring_is_unknown() -> None:
    result = oauth.probe_antigravity(
        status_reader=lambda: {"readable": False},
        now=NOW,
        environ={},
    )
    assert result["ok"] is True
    assert result["status"] == "unknown"
    assert result["auth_mode"] == "none"


def test_no_token_substring_appears_in_json_output(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    exp = int((NOW + dt.timedelta(days=1)).timestamp())
    secrets = (
        "syntheticCodexAccessNeverExpose",
        "syntheticCodexRefreshNeverExpose",
        "syntheticClaudeAccessNeverExpose",
        "syntheticClaudeRefreshNeverExpose",
    )
    _write_json(
        paths["codex"],
        {
            "auth_mode": "chatgpt",
            "tokens": {
                "access_token": _fake_jwt(
                    {"exp": exp, "scope": secrets[0]},
                    secrets[0],
                ),
                "refresh_token": secrets[1],
                "account_id": "acct_synthetic_654321",
            },
        },
    )
    _write_json(
        paths["claude"],
        {
            "claudeAiOauth": {
                "accessToken": secrets[2],
                "refreshToken": secrets[3],
                "expiresAt": exp * 1000,
                "subscriptionType": "pro",
            }
        },
    )
    report = oauth.collect_status(
        now=NOW,
        environ={},
        paths=paths,
        antigravity_reader=lambda: {"readable": False},
    )
    rendered = json.dumps(report, sort_keys=True)
    for secret in secrets:
        assert secret not in rendered
        assert secret[:8] not in rendered


def test_exception_inside_probe_is_fail_closed(tmp_path: Path) -> None:
    broken = tmp_path / "auth.json"
    broken.write_text("{", encoding="utf-8")
    result = oauth.probe_codex("codex", broken, now=NOW, environ={})
    assert result["ok"] is False
    assert result["status"] == "probe_exception"
    assert result["usable_oauth"] is False
    assert result["error"] == "JSONDecodeError"


def test_expiry_soon_is_strictly_less_than_sixty_minutes(tmp_path: Path) -> None:
    credentials = tmp_path / ".credentials.json"
    _write_json(
        credentials,
        {
            "claudeAiOauth": {
                "accessToken": "synthetic",
                "expiresAt": int((NOW + dt.timedelta(minutes=59)).timestamp()),
            }
        },
    )
    assert oauth.probe_claude(credentials, now=NOW, environ={})["expires_soon"] is True
    _write_json(
        credentials,
        {
            "claudeAiOauth": {
                "accessToken": "synthetic",
                "expiresAt": int((NOW + dt.timedelta(minutes=60)).timestamp()),
            }
        },
    )
    assert oauth.probe_claude(credentials, now=NOW, environ={})["expires_soon"] is False
