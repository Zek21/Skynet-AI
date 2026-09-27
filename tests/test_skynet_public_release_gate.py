from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "tools" / "skynet_public_release_gate.py"
)
SPEC = importlib.util.spec_from_file_location("skynet_public_release_gate", MODULE_PATH)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def write_allowlist(root: Path, content: dict | None = None) -> Path:
    path = root / "allowlist.json"
    path.write_text(json.dumps(content or {}), encoding="utf-8")
    return path


def scan_file(
    tmp_path: Path,
    content: str,
    *,
    allowlist: dict | None = None,
) -> dict:
    candidate = tmp_path / "candidate.txt"
    candidate.write_text(content, encoding="utf-8")
    return GATE.scan_paths(
        repo_root=tmp_path,
        paths=[candidate],
        allowlist_path=write_allowlist(tmp_path, allowlist),
    )


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def init_clean_repo(repo: Path) -> None:
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Release Gate Test")
    (repo / "README.md").write_text("clean\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-qm", "fixture")


@pytest.mark.parametrize(
    "secret",
    [
        "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
        "sk-proj-A1b2C3d4E5f6G7h8I9j0",
    ],
)
def test_real_looking_tokens_block(secret: str, tmp_path: Path) -> None:
    result = scan_file(tmp_path, f"credential={secret}\n")

    assert result["ok"] is False
    assert result["counts"]["BLOCK"] == 1
    assert result["findings"][0]["severity"] == "BLOCK"


def test_private_d_prospects_path_blocks(tmp_path: Path) -> None:
    result = scan_file(
        tmp_path,
        "repo = " + r'"D:\Prospects\ScreenMemory\private.txt"' + "\n",
    )

    assert result["ok"] is False
    assert {item["rule"] for item in result["findings"]} == {
        "private_path_d_prospects"
    }


def test_owner_email_warns_without_blocking(tmp_path: Path) -> None:
    result = scan_file(tmp_path, "owner=exzil.calanza@wvsu.edu.ph\n")

    assert result["ok"] is True
    assert result["counts"] == {"BLOCK": 0, "WARN": 1}
    assert result["findings"][0]["rule"] == "owner_email"


@pytest.mark.parametrize(
    "email",
    [
        "contact@exzilcalanza.info",
        "exzilcalanza@gmail.com",
        "rogiebase7@gmail.com",
    ],
)
def test_owner_domain_and_known_accounts_warn_without_blocking(
    email: str,
    tmp_path: Path,
) -> None:
    result = scan_file(tmp_path, f"owner={email}\n")

    assert result["ok"] is True
    assert result["counts"] == {"BLOCK": 0, "WARN": 1}
    assert result["findings"][0]["rule"] == "owner_email"


@pytest.mark.parametrize(
    "asset",
    [
        "logo@2x.png",
        "photo@3x.webp",
        "icon@retina.svg",
        "cover@dark.avif",
    ],
)
def test_asset_suffixes_are_not_email_findings(
    asset: str,
    tmp_path: Path,
) -> None:
    result = scan_file(tmp_path, f"src={asset}\n")

    assert result["ok"] is True
    assert result["findings"] == []


@pytest.mark.parametrize(
    "email",
    [
        "x@y.com",
        "me@site.com",
        "me@x.com",
        "name@company.com",
        "owner@real-company.org",
        "user@service.dev",
        "fixture@example.test",
    ],
)
def test_obvious_placeholder_addresses_do_not_block(
    email: str,
    tmp_path: Path,
) -> None:
    result = scan_file(tmp_path, f"fixture={email}\n")

    assert result["ok"] is True
    assert result["findings"] == []


@pytest.mark.parametrize(
    "email",
    [
        "recruiting@alephtalent.com",
        "hiring@teamsbydesign.com",
        "careers@avvantvirtual.com",
        "recruitment@dash10.ph",
        "jobs@crawlbase.com",
        "recruiter@company.com",
        "me@alephtalent.com",
    ],
)
def test_real_company_shaped_addresses_still_block(
    email: str,
    tmp_path: Path,
) -> None:
    result = scan_file(tmp_path, f"recipient={email}\n")

    assert result["ok"] is False
    assert result["counts"]["BLOCK"] == 1
    assert result["findings"][0]["rule"] == "third_party_email"


def test_third_party_email_blocks_but_example_domain_does_not(
    tmp_path: Path,
) -> None:
    result = scan_file(
        tmp_path,
        "private=person@real-company.org safe=fixture@example.com\n",
    )

    assert result["ok"] is False
    assert result["counts"]["BLOCK"] == 1
    assert result["findings"][0]["rule"] == "third_party_email"


def test_allowlisted_finding_is_suppressed(tmp_path: Path) -> None:
    secret = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    result = scan_file(
        tmp_path,
        f"credential={secret}\n",
        allowlist={
            "candidate.txt": {
                "rule": "github_pat",
                "reason": "Synthetic scanner fixture.",
            }
        },
    )

    assert result["ok"] is True
    assert result["counts"]["BLOCK"] == 0
    assert result["findings"] == []
    assert result["suppressed_count"] == 1
    assert result["stale_allowlist"] == []


def test_absent_allowlist_is_zero_suppressions_and_scan_proceeds(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate.txt"
    candidate.write_text("clean\n", encoding="utf-8")

    result = GATE.scan_paths(
        repo_root=tmp_path,
        paths=[candidate],
        allowlist_path=tmp_path / "missing-allowlist.json",
    )

    assert result["ok"] is True
    assert result["findings"] == []
    assert result["suppressed_count"] == 0
    assert result["scan_performed"] is True
    assert result["candidate_file_count"] == 1
    assert result["scanned_file_count"] == 1


def test_absent_allowlist_clean_worktree_exits_zero(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    init_clean_repo(tmp_path)
    receipt = tmp_path / "receipt.json"

    exit_code = GATE.main(
        [
            "--repo-root",
            str(tmp_path),
            "--allowlist",
            str(tmp_path / "missing-allowlist.json"),
            "--receipt",
            str(receipt),
            "--json",
            "--gate",
        ]
    )
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert report["ok"] is True
    assert report["findings"] == []
    assert report["scan_performed"] is True
    assert report["candidate_file_count"] == 0
    assert report["scanned_file_count"] == 0


def test_malformed_present_allowlist_blocks_after_honest_scan(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    candidate = tmp_path / "candidate.txt"
    candidate.write_text("clean\n", encoding="utf-8")
    allowlist = tmp_path / "allowlist.json"
    allowlist.write_text("{", encoding="utf-8")

    exit_code = GATE.main(
        [
            "--repo-root",
            str(tmp_path),
            "--paths",
            str(candidate),
            "--allowlist",
            str(allowlist),
            "--receipt",
            str(tmp_path / "receipt.json"),
            "--json",
            "--gate",
        ]
    )
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert report["ok"] is False
    assert report["findings"][0]["rule"] == "invalid_allowlist"
    assert report["scan_performed"] is True
    assert report["candidate_file_count"] == 1
    assert report["scanned_file_count"] == 1


def test_present_non_file_allowlist_is_invalid(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.txt"
    candidate.write_text("clean\n", encoding="utf-8")
    allowlist = tmp_path / "allowlist.json"
    allowlist.mkdir()

    result = GATE.scan_paths(
        repo_root=tmp_path,
        paths=[candidate],
        allowlist_path=allowlist,
    )

    assert result["ok"] is False
    assert result["counts"]["BLOCK"] == 1
    assert result["findings"][0]["rule"] == "invalid_allowlist"
    assert result["scan_performed"] is True
    assert result["scanned_file_count"] == 1


def test_empty_allowlist_reason_is_a_block(tmp_path: Path) -> None:
    result = scan_file(
        tmp_path,
        "clean\n",
        allowlist={"candidate.txt": {"rule": "github_pat", "reason": ""}},
    )

    assert result["ok"] is False
    assert result["counts"]["BLOCK"] == 1
    assert result["findings"][0]["rule"] == "invalid_allowlist_entry"
    assert GATE.gate_exit_code(result, gate=True) == 2


def test_stale_allowlist_is_report_only(tmp_path: Path) -> None:
    result = scan_file(
        tmp_path,
        "clean\n",
        allowlist={
            "candidate.txt": {
                "rule": "github_pat",
                "reason": "Former synthetic fixture.",
            }
        },
    )

    assert result["ok"] is True
    assert len(result["stale_allowlist"]) == 1


def test_json_output_never_contains_full_secret(tmp_path: Path) -> None:
    secret = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    result = scan_file(tmp_path, f"credential={secret}\n")
    rendered = json.dumps(result)

    assert secret not in rendered
    assert result["findings"][0]["redacted_excerpt"].startswith(secret[:6])
    assert f"len={len(secret)}" in rendered


def test_reader_exception_fails_closed_as_unreadable_file(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.txt"
    candidate.write_text("clean\n", encoding="utf-8")

    def explode(_path: Path) -> bytes:
        raise RuntimeError("fixture exploded")

    result = GATE.scan_paths(
        repo_root=tmp_path,
        paths=[candidate],
        allowlist_path=write_allowlist(tmp_path),
        read_bytes=explode,
    )

    assert result["ok"] is False
    assert result["counts"]["BLOCK"] == 1
    assert result["findings"][0]["rule"] == "unreadable_file"


def test_unexpected_scan_exception_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def explode(**_kwargs) -> dict:
        raise RuntimeError("unexpected fixture failure")

    monkeypatch.setattr(GATE, "scan_paths", explode)
    result = GATE.run_release_gate(
        repo_root=tmp_path,
        paths=[tmp_path / "candidate.txt"],
        allowlist_path=write_allowlist(tmp_path),
    )

    assert result["ok"] is False
    assert result["counts"]["BLOCK"] == 1
    assert result["findings"][0]["rule"] == "unexpected_exception"


@pytest.mark.parametrize(
    ("report_ok", "gate_enabled", "expected"),
    [
        (False, True, 2),
        (True, True, 0),
        (False, False, 0),
    ],
)
def test_gate_exit_code_mapping(
    report_ok: bool,
    gate_enabled: bool,
    expected: int,
) -> None:
    assert GATE.gate_exit_code({"ok": report_ok}, gate=gate_enabled) == expected


def test_binary_is_recorded_and_not_scanned(tmp_path: Path) -> None:
    binary = tmp_path / "artifact.bin"
    binary.write_bytes(b"prefix\x00ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")

    result = GATE.scan_paths(
        repo_root=tmp_path,
        paths=[binary],
        allowlist_path=write_allowlist(tmp_path),
    )

    assert result["ok"] is True
    assert result["skipped_binary"] == ["artifact.bin"]
    assert result["skipped_binary_count"] == 1
