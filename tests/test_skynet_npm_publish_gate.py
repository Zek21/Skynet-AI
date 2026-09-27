from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "tools" / "skynet_npm_publish_gate.py"
)
REPO_ROOT = MODULE_PATH.parents[1]
SPEC = importlib.util.spec_from_file_location("skynet_npm_publish_gate", MODULE_PATH)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def completed(
    returncode: int,
    *,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["fake"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def test_secret_scanner_catches_private_repo_path(tmp_path: Path) -> None:
    shipped = tmp_path / "package" / "bin" / "skynet.js"
    shipped.parent.mkdir(parents=True)
    shipped.write_text(
        r'const root = "D:\Prospects\ScreenMemory";',
        encoding="utf-8",
    )

    result = GATE.scan_shipped_text(tmp_path)

    assert result["ok"] is False
    assert {
        (hit["file"], hit["line"], hit["rule"])
        for hit in result["hits"]
    } >= {
        ("package/bin/skynet.js", 1, "private_path_d_prospects"),
        ("package/bin/skynet.js", 1, "absolute_windows_drive_path"),
    }


def test_secret_scanner_catches_owner_domain_string(tmp_path: Path) -> None:
    shipped = tmp_path / "package" / "README.md"
    shipped.parent.mkdir(parents=True)
    shipped.write_text(
        "homepage=https://exzilcalanza.info/private\n",
        encoding="utf-8",
    )

    result = GATE.scan_shipped_text(tmp_path)

    assert result["ok"] is False
    assert {hit["rule"] for hit in result["hits"]} >= {"owner_domain_string"}


def test_secret_scanner_catches_token_and_email(tmp_path: Path) -> None:
    shipped = tmp_path / "package" / "README.md"
    shipped.parent.mkdir(parents=True)
    shipped.write_text(
        "token=sk-ant-exampleSecret12345\ncontact=owner@example.test\n",
        encoding="utf-8",
    )

    result = GATE.scan_shipped_text(tmp_path)
    rules = {hit["rule"] for hit in result["hits"]}

    assert result["ok"] is False
    assert "openai_or_anthropic_token" in rules
    assert "email_address" in rules


def test_secret_scanner_allows_clean_fixture(tmp_path: Path) -> None:
    package = tmp_path / "package"
    package.mkdir()
    (package / "package.json").write_text(
        '{"name":"@skynet/cli","homepage":"https://example.test/project"}',
        encoding="utf-8",
    )
    (package / "LICENSE").write_text("MIT License\n", encoding="utf-8")

    result = GATE.scan_shipped_text(tmp_path)

    assert result["ok"] is True
    assert result["hits"] == []
    assert result["scanned_files"] == ["package/LICENSE", "package/package.json"]


def test_smoke_fails_when_version_stdout_mismatches() -> None:
    result = GATE.evaluate_smoke(
        completed(0, stdout="0.2.4\n"),
        completed(0, stdout="usage: skynet\n"),
        completed(
            GATE.EX_CONFIG,
            stderr="Set SKYNET_REPO_ROOT to the repository checkout.\n",
        ),
        expected_version="0.2.5",
    )

    assert result["ok"] is False
    assert "version_stdout_mismatch" in result["failures"]


def test_exception_inside_check_fails_closed() -> None:
    def explode() -> dict:
        raise RuntimeError("fixture exploded")

    result = GATE.guarded_check("fixture", explode)

    assert result["ok"] is False
    assert result["reason"] == "exception"
    assert result["exception"] == "RuntimeError: fixture exploded"


@pytest.mark.parametrize(
    ("overall_ok", "gate_enabled", "expected"),
    [
        (True, True, 0),
        (False, True, 2),
        (True, False, 0),
        (False, False, 0),
    ],
)
def test_gate_exit_code_mapping(
    overall_ok: bool,
    gate_enabled: bool,
    expected: int,
) -> None:
    assert GATE.gate_exit_code({"ok": overall_ok}, gate=gate_enabled) == expected


def test_registry_version_exists_fails_gate(tmp_path: Path) -> None:
    def fake_runner(*_args, **_kwargs) -> subprocess.CompletedProcess[str]:
        return completed(0, stdout='"0.2.5"\n')

    result = GATE.registry_preflight(
        package_name="@skynet/cli",
        version="0.2.5",
        npm_path="npm",
        runner=fake_runner,
        cwd=tmp_path,
        env={},
        offline=False,
    )

    assert result["ok"] is False
    assert result["status"] == "version_exists"
    assert GATE.gate_exit_code({"ok": result["ok"]}, gate=True) == 2


def test_registry_offline_is_non_blocking_without_runner_call(
    tmp_path: Path,
) -> None:
    def forbidden_runner(*_args, **_kwargs) -> subprocess.CompletedProcess[str]:
        raise AssertionError("offline preflight must not invoke npm")

    result = GATE.registry_preflight(
        package_name="@skynet/cli",
        version="0.2.5",
        npm_path="npm",
        runner=forbidden_runner,
        cwd=tmp_path,
        env={},
        offline=True,
    )

    assert result["ok"] is True
    assert result["status"] == "unknown_offline"
    assert result["skipped"] is True


def test_registry_e404_means_unpublished(tmp_path: Path) -> None:
    def fake_runner(*_args, **_kwargs) -> subprocess.CompletedProcess[str]:
        return completed(1, stderr="npm ERR! code E404\n404 Not Found\n")

    result = GATE.registry_preflight(
        package_name="@skynet/cli",
        version="0.2.5",
        npm_path="npm",
        runner=fake_runner,
        cwd=tmp_path,
        env={},
        offline=False,
    )

    assert result["ok"] is True
    assert result["status"] == "unpublished"


def test_links_normalize_git_url_and_accept_reachable_links(
    tmp_path: Path,
) -> None:
    package_json = tmp_path / "package.json"
    package_json.write_text(
        json.dumps(
            {
                "homepage": "https://github.com/Zek21/Skynet-AI",
                "repository": {
                    "url": "git+https://github.com/Zek21/Skynet-AI.git"
                },
                "bugs": {"url": "https://github.com/Zek21/Skynet-AI/issues"},
            }
        ),
        encoding="utf-8",
    )
    probed: list[str] = []

    def fake_probe(url: str) -> dict:
        probed.append(url)
        return {"url": url, "ok": True, "status_code": 200, "reason": None}

    result = GATE.links_preflight(package_json, offline=False, probe=fake_probe)

    assert result["ok"] is True
    assert result["status"] == "reachable"
    assert probed == [
        "https://github.com/Zek21/Skynet-AI",
        "https://github.com/Zek21/Skynet-AI",
        "https://github.com/Zek21/Skynet-AI/issues",
    ]


def test_links_definitive_404_fails(tmp_path: Path) -> None:
    package_json = tmp_path / "package.json"
    package_json.write_text(
        json.dumps(
            {
                "homepage": "https://example.test/project",
                "repository": {"url": "https://example.test/project"},
                "bugs": {"url": "https://example.test/project/issues"},
            }
        ),
        encoding="utf-8",
    )

    def fake_probe(url: str) -> dict:
        return {
            "url": url,
            "ok": not url.endswith("/issues"),
            "status_code": 404 if url.endswith("/issues") else 200,
            "reason": "http_404" if url.endswith("/issues") else None,
        }

    result = GATE.links_preflight(package_json, offline=False, probe=fake_probe)

    assert result["ok"] is False
    assert result["reason"] == "dead_or_invalid_link"
    assert result["status"] == "failed"


def test_links_offline_is_non_blocking_without_probe(tmp_path: Path) -> None:
    def forbidden_probe(_url: str) -> dict:
        raise AssertionError("offline link check must not probe")

    result = GATE.links_preflight(
        tmp_path / "missing.json",
        offline=True,
        probe=forbidden_probe,
    )

    assert result["ok"] is True
    assert result["status"] == "unknown_offline"
    assert result["skipped"] is True


def test_offline_links_check_skips_even_without_packed_context() -> None:
    result = GATE._links_check(offline=True, context={})

    assert result["ok"] is True
    assert result["status"] == "unknown_offline"
    assert result["skipped"] is True


def _write_runtime_fixture(root: Path) -> None:
    source_dir = root / "tools"
    runtime_dir = root / "Skynet" / "cli" / "runtime"
    source_dir.mkdir(parents=True)
    runtime_dir.mkdir(parents=True)
    hashes: dict[str, str] = {}
    for name in GATE.RUNTIME_TOOL_FILES:
        content = f"# {name}\n"
        (source_dir / name).write_text(content, encoding="utf-8")
        (runtime_dir / name).write_text(content, encoding="utf-8")
        hashes[name] = GATE.sha256_file(source_dir / name)
    (runtime_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "algorithm": "sha256",
                "files": hashes,
            }
        ),
        encoding="utf-8",
    )


def test_bundled_copy_sha_mismatch_fails_gate(tmp_path: Path) -> None:
    _write_runtime_fixture(tmp_path)
    bundled = (
        tmp_path
        / "Skynet"
        / "cli"
        / "runtime"
        / GATE.RUNTIME_TOOL_FILES[0]
    )
    bundled.write_text("# stale bundled copy\n", encoding="utf-8")

    result = GATE.runtime_bundle_parity(tmp_path)

    assert result["ok"] is False
    assert result["reason"] == "runtime_bundle_drift"
    assert {
        (failure["file"], failure["reason"])
        for failure in result["failures"]
    } >= {
        (
            GATE.RUNTIME_TOOL_FILES[0],
            "source_bundle_sha256_mismatch",
        )
    }


def test_runtime_manifest_lists_exactly_four_existing_tools() -> None:
    runtime_dir = REPO_ROOT / "Skynet" / "cli" / "runtime"
    manifest = json.loads(
        (runtime_dir / "manifest.json").read_text(encoding="utf-8")
    )

    assert set(manifest["files"]) == set(GATE.RUNTIME_TOOL_FILES)
    assert len(manifest["files"]) == 4
    assert all((runtime_dir / name).is_file() for name in manifest["files"])


def test_package_files_include_runtime() -> None:
    package = json.loads(
        (REPO_ROOT / "Skynet" / "cli" / "package.json").read_text(
            encoding="utf-8"
        )
    )

    assert "runtime/" in package["files"]
