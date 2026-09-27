#!/usr/bin/env python3
"""Fail-closed npm publish gate -- catch unsafe or off-repo-broken packages.

The failure class closed here is a tarball that looks publishable from inside
the source repository but leaks private material or cannot bootstrap after a
clean-room install. The gate packs the real npm artifact, scans its extracted
contents, installs it outside the repository, exercises the installed command,
and optionally checks whether the exact registry version already exists.

No code path publishes, logs in to npm, or mutates the registry.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

EX_CONFIG = 78
GATE_BLOCKED = 2
COMMAND_TIMEOUT_SECONDS = 300
LINK_TIMEOUT_SECONDS = 6
TOOL_NAME = "skynet_npm_publish_gate"
RUNTIME_TOOL_FILES = (
    "skynet_provider_oauth.py",
    "skynet_public_release_gate.py",
    "skynet_npm_publish_gate.py",
    "skynet_publish_boundary_guard.py",
)
BUNDLED_HELP_COMMANDS = (
    "release-gate",
    "publish-gate",
    "boundary-guard",
)

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
CheckAction = Callable[[], dict[str, Any]]

_SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_path_d_prospects",
        re.compile(r"D:(?:\\\\|\\|/)Prospects(?:\\\\|\\|/)", re.IGNORECASE),
    ),
    (
        "private_path_c_users_exzil",
        re.compile(r"C:(?:\\\\|\\|/)Users(?:\\\\|\\|/)exzil(?:\\\\|\\|/)", re.IGNORECASE),
    ),
    (
        "owner_domain_string",
        re.compile("exzil" + "calanza", re.IGNORECASE),
    ),
    (
        "email_address",
        re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w.-])"),
    ),
    (
        "openai_or_anthropic_token",
        re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{8,}\b", re.IGNORECASE),
    ),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{8,}\b", re.IGNORECASE)),
    ("bearer_header", re.compile(r"\bBearer\s+\S+", re.IGNORECASE)),
    (
        "refresh_token_value",
        re.compile(
            r"""\brefresh_token\b\s*["']?\s*[:=]\s*["'][A-Za-z0-9._~+/=-]{8,}""",
            re.IGNORECASE,
        ),
    ),
    (
        "access_token_value",
        re.compile(
            r"""\baccess_token\b\s*["']?\s*[:=]\s*["'][A-Za-z0-9._~+/=-]{8,}""",
            re.IGNORECASE,
        ),
    ),
    (
        "absolute_windows_drive_path",
        re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/][^\s\"'<>|]+)"),
    ),
)

_NETWORK_ERROR_MARKERS = (
    "eai_again",
    "enetunreach",
    "econnrefused",
    "etimedout",
    "enotfound",
    "network",
    "offline",
    "socket hang up",
)


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _default_runner(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: int = COMMAND_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=str(cwd),
        env=dict(env),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def scrub_runtime_env(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return an environment without repository or interpreter overrides."""
    source = source or os.environ
    blocked = {"SKYNET_REPO_ROOT", "SKYNET_PYTHON"}
    clean = {key: value for key, value in source.items() if key.upper() not in blocked}
    clean["npm_config_audit"] = "false"
    clean["npm_config_fund"] = "false"
    clean["npm_config_update_notifier"] = "false"
    return clean


def resolve_npm() -> str | None:
    """Resolve npm with the Windows command shim first."""
    candidates = ("npm.cmd", "npm.exe", "npm") if os.name == "nt" else ("npm",)
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def guarded_check(name: str, action: CheckAction) -> dict[str, Any]:
    """Run one check and convert every ordinary exception into a failed result."""
    try:
        result = action()
        if not isinstance(result, dict):
            raise TypeError(f"{name} returned {type(result).__name__}, expected dict")
        result.setdefault("ok", False)
        result.setdefault("reason", None if result["ok"] else "unspecified_failure")
        return result
    except Exception as exc:  # noqa: BLE001 - fail-closed boundary is intentional.
        return {
            "ok": False,
            "reason": "exception",
            "exception": f"{type(exc).__name__}: {exc}",
        }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def runtime_bundle_parity(repo_root: Path) -> dict[str, Any]:
    """Require the bundled public runtime to exactly match its source files."""
    source_dir = repo_root / "tools"
    runtime_dir = repo_root / "Skynet" / "cli" / "runtime"
    manifest_path = runtime_dir / "manifest.json"
    failures: list[dict[str, str]] = []

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {
            "ok": False,
            "reason": "runtime_manifest_missing",
            "failures": [{"file": "manifest.json", "reason": "missing"}],
        }
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {
            "ok": False,
            "reason": "runtime_manifest_invalid",
            "failures": [{"file": "manifest.json", "reason": "unreadable_or_invalid"}],
        }

    manifest_files = manifest.get("files") if isinstance(manifest, dict) else None
    expected_names = set(RUNTIME_TOOL_FILES)
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != 1
        or manifest.get("algorithm") != "sha256"
        or not isinstance(manifest_files, dict)
        or set(manifest_files) != expected_names
    ):
        failures.append({"file": "manifest.json", "reason": "unexpected_inventory"})
        manifest_files = manifest_files if isinstance(manifest_files, dict) else {}

    bundled_python = (
        {path.name for path in runtime_dir.glob("*.py")}
        if runtime_dir.is_dir()
        else set()
    )
    if bundled_python != expected_names:
        failures.append({"file": "runtime/", "reason": "unexpected_python_inventory"})

    entries: dict[str, dict[str, str | None]] = {}
    for name in RUNTIME_TOOL_FILES:
        source = source_dir / name
        bundled = runtime_dir / name
        source_hash = sha256_file(source) if source.is_file() else None
        bundled_hash = sha256_file(bundled) if bundled.is_file() else None
        manifest_hash = manifest_files.get(name)
        entries[name] = {
            "source_sha256": source_hash,
            "bundled_sha256": bundled_hash,
            "manifest_sha256": (
                manifest_hash if isinstance(manifest_hash, str) else None
            ),
        }
        if source_hash is None:
            failures.append({"file": name, "reason": "source_missing"})
        if bundled_hash is None:
            failures.append({"file": name, "reason": "bundled_missing"})
        if (
            source_hash is not None
            and bundled_hash is not None
            and source_hash != bundled_hash
        ):
            failures.append({"file": name, "reason": "source_bundle_sha256_mismatch"})
        if (
            source_hash is not None
            and (
                not isinstance(manifest_hash, str)
                or manifest_hash != source_hash
            )
        ):
            failures.append({"file": name, "reason": "manifest_sha256_mismatch"})

    return {
        "ok": not failures,
        "reason": None if not failures else "runtime_bundle_drift",
        "files": entries,
        "failures": failures,
    }


def _safe_member_path(member_name: str) -> PurePosixPath:
    member_path = PurePosixPath(member_name)
    if (
        member_path.is_absolute()
        or ".." in member_path.parts
        or re.match(r"^[A-Za-z]:", member_name)
    ):
        raise ValueError(f"unsafe tar member path: {member_name!r}")
    return member_path


def list_tarball_files(tarball: Path) -> list[str]:
    with tarfile.open(tarball, mode="r:gz") as archive:
        files = []
        for member in archive.getmembers():
            _safe_member_path(member.name)
            if member.isfile():
                files.append(member.name)
            elif not member.isdir():
                raise ValueError(
                    f"unsupported tar member type for {member.name!r}"
                )
    return sorted(files)


def extract_tarball_safely(tarball: Path, destination: Path) -> None:
    """Extract only regular files and directories without trusting tar paths."""
    destination.mkdir(parents=True, exist_ok=True)
    destination_resolved = destination.resolve()
    with tarfile.open(tarball, mode="r:gz") as archive:
        for member in archive.getmembers():
            member_path = _safe_member_path(member.name)
            target = (destination / Path(*member_path.parts)).resolve()
            if not target.is_relative_to(destination_resolved):
                raise ValueError(f"tar member escapes extraction root: {member.name!r}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ValueError(
                    f"unsupported tar member type for {member.name!r}"
                )
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"could not read tar member: {member.name!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def scan_shipped_text(root: Path) -> dict[str, Any]:
    """Scan all non-binary extracted files for private paths and secret shapes."""
    hits: list[dict[str, Any]] = []
    scanned_files: list[str] = []
    for file_path in sorted(path for path in root.rglob("*") if path.is_file()):
        raw = file_path.read_bytes()
        if b"\x00" in raw:
            continue
        text = raw.decode("utf-8", errors="replace")
        relative = file_path.relative_to(root).as_posix()
        scanned_files.append(relative)
        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule_name, pattern in _SECRET_RULES:
                for _match in pattern.finditer(line):
                    hits.append(
                        {
                            "file": relative,
                            "line": line_number,
                            "rule": rule_name,
                        }
                    )
    return {
        "ok": not hits,
        "reason": None if not hits else "secret_or_private_path_detected",
        "scanned_files": scanned_files,
        "hits": hits,
    }


def assert_clean_room_isolated(
    installed_package_root: Path,
    repo_root: Path,
    *,
    search_levels: int = 6,
) -> list[str]:
    """Model the JS upward marker search and reject a reachable repository."""
    repo_resolved = repo_root.resolve()
    candidate = installed_package_root.resolve()
    checked: list[str] = []
    for _ in range(search_levels):
        checked.append(str(candidate))
        if candidate == repo_resolved:
            raise ValueError("clean room is within the CLI upward repo search range")
        if (candidate / "Skynet").exists() and (candidate / "tools").exists():
            raise ValueError(f"clean room can discover repository markers at {candidate}")
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent
    return checked


def _process_detail(
    process: subprocess.CompletedProcess[str],
) -> dict[str, Any]:
    return {
        "exit_code": process.returncode,
        "stdout": process.stdout or "",
        "stderr": process.stderr or "",
    }


def evaluate_smoke(
    version_result: subprocess.CompletedProcess[str],
    help_result: subprocess.CompletedProcess[str],
    repo_result: subprocess.CompletedProcess[str],
    *,
    expected_version: str,
    auth_result: subprocess.CompletedProcess[str] | None = None,
    bundled_help_results: Mapping[
        str, subprocess.CompletedProcess[str]
    ] | None = None,
) -> dict[str, Any]:
    """Evaluate clean-room command results without launching subprocesses."""
    failures: list[str] = []
    version_stdout = (version_result.stdout or "").strip()
    help_stdout = help_result.stdout or ""
    repo_stderr = repo_result.stderr or ""

    if version_result.returncode != 0:
        failures.append("version_exit_code")
    if version_stdout != expected_version:
        failures.append("version_stdout_mismatch")
    if help_result.returncode != 0:
        failures.append("help_exit_code")
    if not help_stdout.strip():
        failures.append("help_stdout_empty")
    for command in ("auth-status", *BUNDLED_HELP_COMMANDS):
        if command not in help_stdout:
            failures.append(f"help_missing_{command}")
    if repo_result.returncode != EX_CONFIG:
        failures.append("repo_command_exit_code")
    if "SKYNET_REPO_ROOT" not in repo_stderr:
        failures.append("repo_guidance_missing")
    if re.search(
        r"(?im)^\s+at\s+|\bnode:internal[\\/]|stack trace",
        repo_stderr,
    ):
        failures.append("repo_command_stack_trace")

    commands: dict[str, Any] = {
        "version": _process_detail(version_result),
        "help": _process_detail(help_result),
        "repo_required": _process_detail(repo_result),
    }
    if auth_result is not None:
        commands["auth_status"] = _process_detail(auth_result)
        if auth_result.returncode != 0:
            failures.append("auth_status_exit_code")
        try:
            auth_report = json.loads(auth_result.stdout or "")
        except json.JSONDecodeError:
            failures.append("auth_status_json_invalid")
        else:
            providers = auth_report.get("providers")
            required_providers = {
                "codex",
                "codex_lane2",
                "claude",
                "antigravity",
            }
            if (
                not isinstance(providers, dict)
                or not required_providers.issubset(providers)
            ):
                failures.append("auth_status_provider_inventory_missing")
        if re.search(
            r"\b(?:sk-(?:ant-)?[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,})\b",
            auth_result.stdout or "",
            re.IGNORECASE,
        ):
            failures.append("auth_status_unredacted_credential")

    for command, result in (bundled_help_results or {}).items():
        commands[command.replace("-", "_")] = _process_detail(result)
        if result.returncode != 0:
            failures.append(f"{command}_help_exit_code")
        if not (result.stdout or "").strip():
            failures.append(f"{command}_help_stdout_empty")
        if re.search(
            r"(?im)^\s+at\s+|\bnode:internal[\\/]|stack trace",
            f"{result.stdout or ''}\n{result.stderr or ''}",
        ):
            failures.append(f"{command}_help_stack_trace")

    return {
        "ok": not failures,
        "reason": None if not failures else "smoke_failed",
        "failures": failures,
        "commands": commands,
    }


def registry_preflight(
    *,
    package_name: str,
    version: str,
    npm_path: str,
    runner: CommandRunner,
    cwd: Path,
    env: Mapping[str, str],
    offline: bool,
) -> dict[str, Any]:
    if offline:
        return {
            "ok": True,
            "reason": None,
            "status": "unknown_offline",
            "skipped": True,
        }

    target = f"{package_name}@{version}"
    result = runner(
        [npm_path, "view", target, "version", "--json"],
        cwd=cwd,
        env=env,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    output = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
    detail = _process_detail(result)
    if result.returncode == 0:
        return {
            "ok": False,
            "reason": "version_exists",
            "status": "version_exists",
            "target": target,
            "command": detail,
        }
    if "e404" in output or "404 not found" in output:
        return {
            "ok": True,
            "reason": None,
            "status": "unpublished",
            "target": target,
            "command": detail,
        }
    if any(marker in output for marker in _NETWORK_ERROR_MARKERS):
        return {
            "ok": True,
            "reason": None,
            "status": "unknown_offline",
            "target": target,
            "command": detail,
        }
    return {
        "ok": False,
        "reason": "registry_probe_failed",
        "status": "unknown_error",
        "target": target,
        "command": detail,
    }


def normalize_browsable_url(url: str) -> str:
    """Convert an npm git transport URL into its equivalent browser URL."""
    normalized = url.strip()
    if normalized.startswith("git+https://"):
        normalized = normalized[4:]
    if normalized.startswith("https://") and normalized.endswith(".git"):
        normalized = normalized[:-4]
    return normalized


def _probe_link(url: str, *, timeout: int = LINK_TIMEOUT_SECONDS) -> dict[str, Any]:
    headers = {"User-Agent": "skynet-npm-publish-gate/1"}
    for method in ("HEAD", "GET"):
        request = urllib.request.Request(url, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = int(response.status)
                return {
                    "url": url,
                    "method": method,
                    "status_code": status,
                    "ok": 200 <= status < 400,
                    "reason": None if 200 <= status < 400 else "http_error",
                }
        except urllib.error.HTTPError as exc:
            if exc.code in {405, 501} and method == "HEAD":
                continue
            return {
                "url": url,
                "method": method,
                "status_code": exc.code,
                "ok": False,
                "reason": "http_404" if exc.code == 404 else "http_error",
            }
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return {
                "url": url,
                "method": method,
                "status_code": None,
                "ok": True,
                "reason": None,
                "status": "unknown_offline",
                "exception": f"{type(exc).__name__}: {exc}",
            }
    raise RuntimeError(f"link probe exhausted methods for {url}")


def links_preflight(
    packed_package_json: Path,
    *,
    offline: bool,
    probe: Callable[[str], dict[str, Any]] = _probe_link,
) -> dict[str, Any]:
    """Validate public package links without making network access mandatory."""
    if offline:
        return {
            "ok": True,
            "reason": None,
            "status": "unknown_offline",
            "skipped": True,
            "links": [],
        }

    metadata = json.loads(packed_package_json.read_text(encoding="utf-8"))
    raw_links = {
        "homepage": metadata.get("homepage"),
        "repository": (
            metadata.get("repository", {}).get("url")
            if isinstance(metadata.get("repository"), dict)
            else metadata.get("repository")
        ),
        "bugs": (
            metadata.get("bugs", {}).get("url")
            if isinstance(metadata.get("bugs"), dict)
            else metadata.get("bugs")
        ),
    }
    missing = [name for name, value in raw_links.items() if not isinstance(value, str)]
    if missing:
        return {
            "ok": False,
            "reason": "missing_package_links",
            "missing": missing,
            "links": [],
        }

    results: list[dict[str, Any]] = []
    for name, raw_url in raw_links.items():
        url = normalize_browsable_url(raw_url)
        if not url.startswith(("https://", "http://")):
            results.append(
                {
                    "name": name,
                    "url": url,
                    "ok": False,
                    "reason": "unsupported_url",
                    "status_code": None,
                }
            )
            continue
        result = probe(url)
        results.append({"name": name, **result})

    failures = [result for result in results if not result.get("ok")]
    offline_results = [
        result for result in results if result.get("status") == "unknown_offline"
    ]
    status = (
        "failed"
        if failures
        else "unknown_offline"
        if offline_results
        else "reachable"
    )
    return {
        "ok": not failures,
        "reason": "dead_or_invalid_link" if failures else None,
        "status": status,
        "links": results,
    }


def gate_exit_code(report: Mapping[str, Any], *, gate: bool) -> int:
    return GATE_BLOCKED if gate and not report.get("ok", False) else 0


def _pack_check(
    *,
    npm_path: str,
    package_dir: Path,
    pack_dir: Path,
    runner: CommandRunner,
    env: Mapping[str, str],
    context: dict[str, Any],
) -> dict[str, Any]:
    result = runner(
        [npm_path, "pack", "--pack-destination", str(pack_dir), "--json"],
        cwd=package_dir,
        env=env,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        return {
            "ok": False,
            "reason": "npm_pack_failed",
            "command": _process_detail(result),
        }
    tarballs = sorted(pack_dir.glob("*.tgz"))
    if len(tarballs) != 1:
        return {
            "ok": False,
            "reason": "unexpected_tarball_count",
            "tarball_count": len(tarballs),
            "command": _process_detail(result),
        }
    tarball = tarballs[0]
    files = list_tarball_files(tarball)
    digest = sha256_file(tarball)
    context["tarball"] = tarball
    context["tarball_sha256"] = digest
    context["tarball_size"] = tarball.stat().st_size
    context["files"] = files
    return {
        "ok": True,
        "reason": None,
        "tarball": tarball.name,
        "sha256": digest,
        "size_bytes": tarball.stat().st_size,
        "files": files,
        "command": _process_detail(result),
    }


def _scan_check(
    *,
    extract_dir: Path,
    context: dict[str, Any],
) -> dict[str, Any]:
    tarball = context.get("tarball")
    if not isinstance(tarball, Path):
        return {"ok": False, "reason": "blocked_by_pack"}
    extract_tarball_safely(tarball, extract_dir)
    context["extract_dir"] = extract_dir
    return scan_shipped_text(extract_dir)


def _links_check(
    *,
    offline: bool,
    context: dict[str, Any],
) -> dict[str, Any]:
    if offline:
        return links_preflight(Path(), offline=True)
    extract_dir = context.get("extract_dir")
    if not isinstance(extract_dir, Path):
        return {"ok": False, "reason": "blocked_by_pack"}
    return links_preflight(
        extract_dir / "package" / "package.json",
        offline=offline,
    )


def _clean_room_check(
    *,
    npm_path: str,
    clean_dir: Path,
    repo_root: Path,
    runner: CommandRunner,
    env: Mapping[str, str],
    context: dict[str, Any],
) -> dict[str, Any]:
    tarball = context.get("tarball")
    if not isinstance(tarball, Path):
        return {"ok": False, "reason": "blocked_by_pack"}
    # Derive the install path from the manifest name. Hard-coding a scope makes
    # the gate silently unable to find the package the moment it is renamed,
    # which reads as a broken package rather than a broken check.
    package_name = context.get("package_name")
    if not isinstance(package_name, str) or not package_name:
        return {"ok": False, "reason": "package_name_unresolved"}
    package_root = clean_dir.joinpath("node_modules", *package_name.split("/"))
    searched_roots = assert_clean_room_isolated(package_root, repo_root)
    result = runner(
        [npm_path, "install", str(tarball), "--no-audit", "--no-fund"],
        cwd=clean_dir,
        env=env,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        return {
            "ok": False,
            "reason": "npm_install_failed",
            "searched_roots": searched_roots,
            "command": _process_detail(result),
        }
    cli_path = package_root / "bin" / "skynet.js"
    if not cli_path.is_file():
        return {
            "ok": False,
            "reason": "installed_cli_missing",
            "searched_roots": searched_roots,
            "command": _process_detail(result),
        }
    shim_name = "skynet.cmd" if os.name == "nt" else "skynet"
    shim_path = clean_dir / "node_modules" / ".bin" / shim_name
    if not shim_path.is_file():
        return {
            "ok": False,
            "reason": "installed_command_shim_missing",
            "searched_roots": searched_roots,
            "command": _process_detail(result),
        }
    context["clean_dir"] = clean_dir
    context["installed_cli"] = cli_path
    context["installed_shim"] = shim_path
    return {
        "ok": True,
        "reason": None,
        "install_dir": str(clean_dir),
        "installed_cli": str(cli_path),
        "installed_command": str(shim_path),
        "searched_roots": searched_roots,
        "skynet_repo_root_scrubbed": not any(
            key.upper() == "SKYNET_REPO_ROOT" for key in env
        ),
        "command": _process_detail(result),
    }


def _smoke_check(
    *,
    runner: CommandRunner,
    env: Mapping[str, str],
    version: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    clean_dir = context.get("clean_dir")
    installed_shim = context.get("installed_shim")
    if not isinstance(clean_dir, Path) or not isinstance(installed_shim, Path):
        return {"ok": False, "reason": "blocked_by_clean_room_install"}

    def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
        command = [str(installed_shim), *args]
        if os.name == "nt":
            command_processor = os.environ.get("COMSPEC") or shutil.which("cmd.exe")
            if not command_processor:
                raise FileNotFoundError("Windows command processor not found")
            command = [
                command_processor,
                "/d",
                "/s",
                "/c",
                subprocess.list2cmdline([str(installed_shim), *args]),
            ]
        return runner(
            command,
            cwd=clean_dir,
            env=env,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )

    return evaluate_smoke(
        run_cli("--version"),
        run_cli("--help"),
        run_cli("health"),
        expected_version=version,
        auth_result=run_cli("auth-status", "--json"),
        bundled_help_results={
            command: run_cli(command, "--help")
            for command in BUNDLED_HELP_COMMANDS
        },
    )


def _cleanup_temp_dirs(temp_dirs: list[Path]) -> list[str]:
    errors: list[str] = []
    for temp_dir in reversed(temp_dirs):
        try:
            shutil.rmtree(temp_dir)
        except FileNotFoundError:
            continue
        except Exception as exc:  # noqa: BLE001 - cleanup must be reported.
            errors.append(f"{temp_dir}: {type(exc).__name__}: {exc}")
    return errors


def run_publish_gate(
    *,
    repo_root: Path | None = None,
    offline: bool = False,
    runner: CommandRunner = _default_runner,
    npm_path: str | None = None,
) -> dict[str, Any]:
    repo_root = (repo_root or Path(__file__).resolve().parents[1]).resolve()
    package_dir = repo_root / "Skynet" / "cli"
    checks: dict[str, dict[str, Any]] = {}
    context: dict[str, Any] = {}
    temp_dirs: list[Path] = []
    package_name = "unknown"
    version = "unknown"

    try:
        metadata = json.loads(
            (package_dir / "package.json").read_text(encoding="utf-8")
        )
        package_name = str(metadata["name"])
        version = str(metadata["version"])
        context["package_name"] = package_name
        checks["runtime_bundle"] = guarded_check(
            "runtime_bundle",
            lambda: runtime_bundle_parity(repo_root),
        )
        resolved_npm = npm_path or resolve_npm()
        if not checks["runtime_bundle"]["ok"]:
            checks["pack"] = {
                "ok": False,
                "reason": "blocked_by_runtime_bundle_drift",
            }
            checks["secret_scan"] = {"ok": False, "reason": "blocked_by_pack"}
            checks["links"] = (
                links_preflight(Path(), offline=True)
                if offline
                else {"ok": False, "reason": "blocked_by_pack"}
            )
            checks["clean_room_install"] = {
                "ok": False,
                "reason": "blocked_by_pack",
            }
            checks["smoke"] = {
                "ok": False,
                "reason": "blocked_by_clean_room_install",
            }
            checks["registry_preflight"] = {
                "ok": False,
                "reason": "blocked_by_runtime_bundle_drift",
                "status": "unknown_error",
            }
        elif not resolved_npm:
            checks["pack"] = {"ok": False, "reason": "npm_not_found"}
            checks["secret_scan"] = {"ok": False, "reason": "blocked_by_pack"}
            checks["links"] = (
                links_preflight(Path(), offline=True)
                if offline
                else {"ok": False, "reason": "blocked_by_pack"}
            )
            checks["clean_room_install"] = {
                "ok": False,
                "reason": "blocked_by_pack",
            }
            checks["smoke"] = {
                "ok": False,
                "reason": "blocked_by_clean_room_install",
            }
            checks["registry_preflight"] = {
                "ok": False,
                "reason": "npm_not_found",
                "status": "unknown_error",
            }
        else:
            pack_dir = Path(tempfile.mkdtemp(prefix="skynet-npm-pack-"))
            temp_dirs.append(pack_dir)
            extract_dir = Path(tempfile.mkdtemp(prefix="skynet-npm-extract-"))
            temp_dirs.append(extract_dir)
            clean_dir = Path(tempfile.mkdtemp(prefix="skynet-npm-cleanroom-"))
            temp_dirs.append(clean_dir)
            env = scrub_runtime_env()

            checks["pack"] = guarded_check(
                "pack",
                lambda: _pack_check(
                    npm_path=resolved_npm,
                    package_dir=package_dir,
                    pack_dir=pack_dir,
                    runner=runner,
                    env=env,
                    context=context,
                ),
            )
            checks["secret_scan"] = guarded_check(
                "secret_scan",
                lambda: _scan_check(
                    extract_dir=extract_dir,
                    context=context,
                ),
            )
            checks["links"] = guarded_check(
                "links",
                lambda: _links_check(
                    offline=offline,
                    context=context,
                ),
            )
            checks["clean_room_install"] = guarded_check(
                "clean_room_install",
                lambda: _clean_room_check(
                    npm_path=resolved_npm,
                    clean_dir=clean_dir,
                    repo_root=repo_root,
                    runner=runner,
                    env=env,
                    context=context,
                ),
            )
            checks["smoke"] = guarded_check(
                "smoke",
                lambda: _smoke_check(
                    runner=runner,
                    env=env,
                    version=version,
                    context=context,
                ),
            )
            checks["registry_preflight"] = guarded_check(
                "registry_preflight",
                lambda: registry_preflight(
                    package_name=package_name,
                    version=version,
                    npm_path=resolved_npm,
                    runner=runner,
                    cwd=package_dir,
                    env=env,
                    offline=offline,
                ),
            )
    except Exception as exc:  # noqa: BLE001 - top-level fail-closed boundary.
        checks.setdefault(
            "configuration",
            {
                "ok": False,
                "reason": "exception",
                "exception": f"{type(exc).__name__}: {exc}",
            },
        )
    finally:
        cleanup_errors = _cleanup_temp_dirs(temp_dirs)
        checks["cleanup"] = {
            "ok": not cleanup_errors,
            "reason": None if not cleanup_errors else "cleanup_failed",
            "errors": cleanup_errors,
            "temp_dirs_removed": len(temp_dirs) - len(cleanup_errors),
            "temp_dirs_created": len(temp_dirs),
        }

    return {
        "tool": TOOL_NAME,
        "timestamp_utc": _utc_now(),
        "repo_root": str(repo_root),
        "package": {"name": package_name, "version": version},
        "checks": checks,
        "tarball": {
            "sha256": context.get("tarball_sha256"),
            "size_bytes": context.get("tarball_size"),
            "files": context.get("files", []),
        },
        "offline": offline,
        "ok": bool(checks) and all(check.get("ok") is True for check in checks.values()),
    }


def _default_receipt_path(repo_root: Path) -> Path:
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    return repo_root / "data" / "runs" / "npm_publish_gate" / stamp / "receipt.json"


def write_receipt(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _render_text(report: Mapping[str, Any], receipt: Path) -> str:
    lines = [
        f"package: {report['package']['name']}@{report['package']['version']}",
        f"tarball sha256: {report['tarball']['sha256'] or 'unavailable'}",
    ]
    for name, result in report["checks"].items():
        status = "PASS" if result.get("ok") else "FAIL"
        reason = result.get("reason")
        lines.append(f"{name}: {status}" + (f" ({reason})" if reason else ""))
    lines.append(f"receipt: {receipt}")
    lines.append(f"overall: {'PASS' if report.get('ok') else 'FAIL'}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed publish-readiness gate for @zek21/skynet-cli"
    )
    parser.add_argument("--json", action="store_true", help="print one JSON object")
    parser.add_argument(
        "--repo-root",
        type=Path,
        help="ScreenMemory/Skynet source root (default: source script repository)",
    )
    parser.add_argument(
        "--gate",
        action="store_true",
        help="exit 2 when any check fails",
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        help="receipt path (default: data/runs/npm_publish_gate/<utc>/receipt.json)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="skip npm registry lookup without weakening local checks",
    )
    args = parser.parse_args(argv)

    repo_root = (
        args.repo_root.resolve()
        if args.repo_root
        else Path(__file__).resolve().parents[1]
    )
    report = run_publish_gate(repo_root=repo_root, offline=args.offline)
    receipt = args.receipt or _default_receipt_path(repo_root)
    report["receipt"] = str(receipt)
    try:
        write_receipt(receipt, report)
    except Exception as exc:  # noqa: BLE001 - receipt failure blocks the gate.
        report["checks"]["receipt"] = {
            "ok": False,
            "reason": "receipt_write_failed",
            "exception": f"{type(exc).__name__}: {exc}",
        }
        report["ok"] = False

    if args.json or args.gate:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_render_text(report, receipt))
    return gate_exit_code(report, gate=args.gate)


if __name__ == "__main__":
    raise SystemExit(main())
