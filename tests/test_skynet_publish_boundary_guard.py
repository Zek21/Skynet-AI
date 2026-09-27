from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tools import skynet_publish_boundary_guard as guard


def write_surface(
    root: Path,
    entries: list[dict[str, str]],
) -> Path:
    path = root / "surface.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "policy": "curated-public",
                "baseline": "origin/master",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )
    return path


def clean_release(
    _repo_root: Path,
    candidates: list[guard.Candidate],
) -> dict:
    return {
        "ok": True,
        "counts": {"BLOCK": 0, "WARN": 0},
        "findings": [],
        "scanned_files": [candidate.path for candidate in candidates],
        "scanned_file_count": len(candidates),
        "skipped_binary": [],
        "skipped_binary_count": 0,
    }


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


def init_repo(repo: Path) -> None:
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Boundary Test")


def test_private_internal_tool_blocks_with_named_violation(tmp_path: Path) -> None:
    surface = write_surface(
        tmp_path,
        [{"pattern": "README.md", "reason": "Public documentation."}],
    )
    report = guard.run_boundary_guard(
        repo_root=tmp_path,
        candidates=[guard.Candidate("tools/internal.py", "worktree")],
        scope="fixture",
        allowlist_path=surface,
        release_scanner=clean_release,
        environ={},
    )

    assert report["ok"] is False
    assert guard.gate_exit_code(report) == 2
    assert report["counts"]["WOULD_PUBLISH_PRIVATE"] == 1
    assert report["violations"][0] == {
        "code": "WOULD_PUBLISH_PRIVATE",
        "path": "tools/internal.py",
        "detail": "path is not covered by data/skynet_public_surface.json",
    }


def test_canonical_manifest_excludes_private_fleet_tool() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    surface = repo_root / "data" / "skynet_public_surface.json"
    entries = guard.load_public_surface(surface)

    assert guard.public_surface_match("tools/fleet.py", entries) is None
    report = guard.run_boundary_guard(
        repo_root=repo_root,
        candidates=[guard.Candidate("tools/fleet.py", "worktree")],
        scope="fixture",
        allowlist_path=surface,
        release_scanner=clean_release,
        environ={},
    )

    assert guard.gate_exit_code(report) == 2
    assert report["counts"]["WOULD_PUBLISH_PRIVATE"] == 1
    assert report["violations"][0]["path"] == "tools/fleet.py"


def test_manifest_public_tools_have_explicit_public_release_reasons() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    entries = guard.load_public_surface(
        repo_root / "data" / "skynet_public_surface.json"
    )
    public_tools = [
        entry
        for entry in entries
        if entry.pattern.startswith("tools/") and entry.pattern.endswith(".py")
    ]

    assert public_tools
    assert all("intended for public release" in entry.reason.lower() for entry in public_tools)


def test_only_allowlisted_paths_pass(tmp_path: Path) -> None:
    surface = write_surface(
        tmp_path,
        [{"pattern": "README.md", "reason": "Public documentation."}],
    )
    report = guard.run_boundary_guard(
        repo_root=tmp_path,
        candidates=[guard.Candidate("README.md", "worktree")],
        scope="fixture",
        allowlist_path=surface,
        release_scanner=clean_release,
        environ={},
    )

    assert report["ok"] is True
    assert guard.gate_exit_code(report) == 0
    assert report["violations"] == []


def test_directory_glob_matches_direct_and_nested_paths(tmp_path: Path) -> None:
    surface = write_surface(
        tmp_path,
        [{"pattern": "public/**", "reason": "Explicit public directory."}],
    )
    entries = guard.load_public_surface(surface)

    assert guard.public_surface_match("public/direct.txt", entries) is not None
    assert (
        guard.public_surface_match("public/deep/nested/file.txt", entries)
        is not None
    )
    assert guard.public_surface_match("publicity/file.txt", entries) is None


@pytest.mark.parametrize(
    "entry",
    [
        {"pattern": "README.md"},
        {"pattern": "README.md", "reason": ""},
    ],
)
def test_empty_or_missing_reason_fails_closed(
    tmp_path: Path,
    entry: dict[str, str],
) -> None:
    surface = write_surface(tmp_path, [entry])
    report = guard.run_boundary_guard(
        repo_root=tmp_path,
        candidates=[guard.Candidate("README.md", "worktree")],
        scope="fixture",
        allowlist_path=surface,
        release_scanner=clean_release,
        environ={},
    )

    assert report["ok"] is False
    assert guard.gate_exit_code(report) == 2
    assert report["counts"]["GUARD_FAILURE"] == 1


def test_release_gate_block_fails_even_for_allowlisted_path(tmp_path: Path) -> None:
    surface = write_surface(
        tmp_path,
        [{"pattern": "README.md", "reason": "Public documentation."}],
    )

    def blocked_release(
        _repo_root: Path,
        _candidates: list[guard.Candidate],
    ) -> dict:
        return {
            "ok": False,
            "counts": {"BLOCK": 1, "WARN": 0},
            "findings": [
                {
                    "path": "README.md",
                    "line": 7,
                    "rule": "private_path_d_prospects",
                    "severity": "BLOCK",
                    "redacted_excerpt": "D:\\Pro…txt (len=31)",
                }
            ],
        }

    report = guard.run_boundary_guard(
        repo_root=tmp_path,
        candidates=[guard.Candidate("README.md", "worktree")],
        scope="fixture",
        allowlist_path=surface,
        release_scanner=blocked_release,
        environ={},
    )

    assert report["ok"] is False
    assert report["counts"]["WOULD_PUBLISH_PRIVATE"] == 0
    assert report["counts"]["RELEASE_GATE_BLOCK"] == 1
    assert report["violations"][0]["code"] == "RELEASE_GATE_BLOCK"


def test_new_branch_all_zero_remote_scans_entire_tip_tree(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / "README.md").write_text("public\n", encoding="utf-8")
    private = tmp_path / "tools" / "internal.py"
    private.parent.mkdir()
    private.write_text("PRIVATE = True\n", encoding="utf-8")
    git(tmp_path, "add", "README.md", "tools/internal.py")
    git(tmp_path, "commit", "-qm", "fixture")
    tip = git(tmp_path, "rev-parse", "HEAD")
    surface = write_surface(
        tmp_path,
        [{"pattern": "README.md", "reason": "Public documentation."}],
    )

    candidates = guard.resolve_ref_update(
        tmp_path,
        local_sha=tip,
        remote_sha="0" * 40,
    )
    report = guard.run_boundary_guard(
        repo_root=tmp_path,
        candidates=candidates,
        scope="pre-push",
        allowlist_path=surface,
        release_scanner=clean_release,
        environ={},
    )

    assert {candidate.path for candidate in candidates} == {
        "README.md",
        "tools/internal.py",
    }
    assert report["ok"] is False
    assert report["counts"]["WOULD_PUBLISH_PRIVATE"] == 1


def test_curated_ref_update_passes(tmp_path: Path) -> None:
    init_repo(tmp_path)
    readme = tmp_path / "README.md"
    readme.write_text("first\n", encoding="utf-8")
    git(tmp_path, "add", "README.md")
    git(tmp_path, "commit", "-qm", "base")
    base = git(tmp_path, "rev-parse", "HEAD")
    readme.write_text("second\n", encoding="utf-8")
    git(tmp_path, "add", "README.md")
    git(tmp_path, "commit", "-qm", "tip")
    tip = git(tmp_path, "rev-parse", "HEAD")
    surface = write_surface(
        tmp_path,
        [{"pattern": "README.md", "reason": "Public documentation."}],
    )

    report = guard.run_boundary_guard(
        repo_root=tmp_path,
        candidates=guard.resolve_ref_update(
            tmp_path,
            local_sha=tip,
            remote_sha=base,
        ),
        scope="pre-push",
        allowlist_path=surface,
        release_scanner=clean_release,
        environ={},
    )

    assert guard.gate_exit_code(report) == 0
    assert report["candidate_paths"] == ["README.md"]


def test_noop_ref_update_passes_with_zero_candidates(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / "README.md").write_text("public\n", encoding="utf-8")
    git(tmp_path, "add", "README.md")
    git(tmp_path, "commit", "-qm", "fixture")
    tip = git(tmp_path, "rev-parse", "HEAD")
    surface = write_surface(
        tmp_path,
        [{"pattern": "README.md", "reason": "Public documentation."}],
    )

    candidates = guard.resolve_ref_update(
        tmp_path,
        local_sha=tip,
        remote_sha=tip,
    )
    report = guard.run_boundary_guard(
        repo_root=tmp_path,
        candidates=candidates,
        scope="pre-push",
        allowlist_path=surface,
        release_scanner=clean_release,
        environ={},
    )

    assert candidates == []
    assert report["candidate_path_count"] == 0
    assert guard.gate_exit_code(report) == 0


@pytest.mark.parametrize(
    "mode",
    ["worktree", "staged", "ref-range", "pre-push", "explicit"],
)
def test_empty_candidate_set_passes_in_every_selection_mode(
    tmp_path: Path,
    mode: str,
) -> None:
    init_repo(tmp_path)
    (tmp_path / "README.md").write_text("public\n", encoding="utf-8")
    git(tmp_path, "add", "README.md")
    git(tmp_path, "commit", "-qm", "fixture")
    tip = git(tmp_path, "rev-parse", "HEAD")
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    updates_file = tmp_path / "updates.txt"
    updates_file.write_text(
        f"refs/heads/master {tip} refs/heads/master {tip}\n",
        encoding="utf-8",
    )
    kwargs = {
        "repo_root": tmp_path,
        "staged": mode == "staged",
        "paths": [empty_dir] if mode == "explicit" else None,
        "ref_range": f"{tip}..{tip}" if mode == "ref-range" else None,
        "pre_push": mode == "pre-push",
        "updates_file": updates_file if mode == "pre-push" else None,
    }

    scope, candidates = guard._selector_candidates(**kwargs)
    report = guard.run_boundary_guard(
        repo_root=tmp_path,
        candidates=candidates,
        scope=scope,
        allowlist_path=tmp_path / "missing-public-surface.json",
        environ={},
    )

    assert candidates == []
    assert report["ok"] is True
    assert report["candidate_path_count"] == 0
    assert report["counts"] == {
        "WOULD_PUBLISH_PRIVATE": 0,
        "RELEASE_GATE_BLOCK": 0,
        "GUARD_FAILURE": 0,
    }
    assert report["release_gate"]["scan_performed"] is False
    assert report["release_gate"]["scan_skipped_reason"] == "no_candidates"
    assert guard.gate_exit_code(report) == 0


def test_empty_pre_push_stream_is_a_noop(tmp_path: Path) -> None:
    assert guard.parse_pre_push_updates(tmp_path, "") == []


def test_remote_tracking_source_ref_is_supported(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / "README.md").write_text("public\n", encoding="utf-8")
    git(tmp_path, "add", "README.md")
    git(tmp_path, "commit", "-qm", "fixture")
    tip = git(tmp_path, "rev-parse", "HEAD")
    update = f"refs/remotes/origin/master {tip} refs/heads/master {tip}\n"

    assert guard.parse_pre_push_updates(tmp_path, update) == []


def test_selector_resolution_error_names_failure_and_exits_two(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_selector(**_kwargs: object) -> tuple[str, list[guard.Candidate]]:
        raise guard.BoundaryGuardError(
            "remote selector refs/remotes/origin/missing did not resolve"
        )

    monkeypatch.setattr(guard, "_selector_candidates", fail_selector)

    assert guard.main(["--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["violations"][0]["path"] == "candidate-selection"
    assert "<guard>" not in report["violations"][0]["path"]
    assert "refs/remotes/origin/missing" in report["violations"][0]["detail"]


def test_real_git_error_names_not_a_repository_and_exits_two(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert guard.main(["--repo-root", str(tmp_path), "--json"]) == 2
    report = json.loads(capsys.readouterr().out)

    assert report["ok"] is False
    assert report["counts"]["GUARD_FAILURE"] == 1
    assert report["violations"][0]["path"] == "candidate-selection"
    assert "not a git repository" in report["violations"][0]["detail"].lower()


def test_unparseable_allowlist_and_scanner_exception_fail_closed(
    tmp_path: Path,
) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    unparseable = guard.run_boundary_guard(
        repo_root=tmp_path,
        candidates=[guard.Candidate("README.md", "worktree")],
        scope="fixture",
        allowlist_path=broken,
        release_scanner=clean_release,
        environ={},
    )
    assert unparseable["ok"] is False
    assert unparseable["counts"]["GUARD_FAILURE"] == 1

    surface = write_surface(
        tmp_path,
        [{"pattern": "README.md", "reason": "Public documentation."}],
    )

    def explode(
        _repo_root: Path,
        _candidates: list[guard.Candidate],
    ) -> dict:
        raise RuntimeError("fixture failure")

    exception = guard.run_boundary_guard(
        repo_root=tmp_path,
        candidates=[guard.Candidate("README.md", "worktree")],
        scope="fixture",
        allowlist_path=surface,
        release_scanner=explode,
        environ={},
    )
    assert exception["ok"] is False
    assert guard.gate_exit_code(exception) == 2
    assert exception["counts"]["GUARD_FAILURE"] == 1


def test_allow_publish_override_names_every_private_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    surface = write_surface(
        tmp_path,
        [{"pattern": "README.md", "reason": "Public documentation."}],
    )
    report = guard.run_boundary_guard(
        repo_root=tmp_path,
        candidates=[
            guard.Candidate("tools/one.py", "worktree"),
            guard.Candidate("core/two.py", "worktree"),
        ],
        scope="fixture",
        allowlist_path=surface,
        release_scanner=clean_release,
        environ={"SKYNET_ALLOW_PUBLISH": "1"},
    )
    assert report["ok"] is True
    assert report["overridden"] is True
    assert guard.gate_exit_code(report) == 0

    monkeypatch.setattr(
        guard,
        "_selector_candidates",
        lambda **_kwargs: ("fixture", []),
    )
    monkeypatch.setattr(
        guard,
        "run_boundary_guard",
        lambda **_kwargs: report,
    )
    assert guard.main(["--json"]) == 0
    captured = capsys.readouterr()
    assert "SKYNET_ALLOW_PUBLISH=1 OVERRIDE IS ACTIVE" in captured.err
    assert "tools/one.py" in captured.err
    assert "core/two.py" in captured.err


def test_hook_install_is_idempotent_and_preserves_existing_hook(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)
    hooks = tmp_path / ".git" / "hooks"
    existing = hooks / "pre-push"
    original = b"#!/bin/sh\nexit 0\n"
    existing.write_bytes(original)

    installed = guard.install_hook(tmp_path)
    assert installed["action"] == "installed_preserved_existing"
    assert guard.MANAGED_HOOK_MARKER in existing.read_text(encoding="utf-8")
    backup = hooks / str(installed["preserved_hook"])
    assert backup.read_bytes() == original

    again = guard.install_hook(tmp_path)
    assert again["action"] == "already_installed"
    assert again["preserved_hook"] == installed["preserved_hook"]

    removed = guard.uninstall_hook(tmp_path)
    assert removed["action"] == "uninstalled_restored_existing"
    assert existing.read_bytes() == original
    assert not backup.exists()


def test_delete_ref_update_publishes_no_paths(tmp_path: Path) -> None:
    init_repo(tmp_path)
    candidates = guard.resolve_ref_update(
        tmp_path,
        local_sha="0" * 40,
        remote_sha="1" * 40,
    )
    assert candidates == []
