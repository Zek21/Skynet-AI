#!/usr/bin/env python3
"""Fail-closed enforcement for ScreenMemory's curated public Git surface.

The manifest baseline is the already-published ``origin/master`` tree. Never
derive publication permission from ``git ls-files`` or another working-branch
inventory: tracked private implementation is intentionally broader than the
public surface.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_RELEASE_GATE_PATH = Path(__file__).with_name("skynet_public_release_gate.py")
_RELEASE_GATE_SPEC = importlib.util.spec_from_file_location(
    "_skynet_public_release_gate_runtime",
    _RELEASE_GATE_PATH,
)
if _RELEASE_GATE_SPEC is None or _RELEASE_GATE_SPEC.loader is None:
    raise ImportError(f"unable to load bundled release gate: {_RELEASE_GATE_PATH.name}")
release_gate = importlib.util.module_from_spec(_RELEASE_GATE_SPEC)
_RELEASE_GATE_SPEC.loader.exec_module(release_gate)

GATE_BLOCKED = 2
TOOL_NAME = "skynet_publish_boundary_guard"
PUBLIC_SURFACE_BASELINE = "origin/master"
ZERO_SHA_RE = re.compile(r"^0{40,64}$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
MANAGED_HOOK_MARKER = "# skynet-publish-boundary-guard:v1"
PRESERVED_HOOK_PREFIX = "pre-push.skynet-preserved"
PRESERVED_HOOK_RE = re.compile(r"^# preserved-hook: (?P<name>[^\r\n]+)$", re.MULTILINE)


class BoundaryGuardError(RuntimeError):
    """A condition that must block rather than silently degrade."""


@dataclass(frozen=True)
class PublicSurfaceEntry:
    pattern: str
    reason: str
    regex: re.Pattern[str]


@dataclass(frozen=True)
class Candidate:
    path: str
    source: str
    revision: str | None = None
    git_mode: str | None = None
    object_id: str | None = None

    @property
    def identity(self) -> tuple[str, str, str | None]:
        return (self.path, self.source, self.revision)


def _normalize_repo_path(raw_path: str | os.PathLike[str]) -> str:
    value = os.fspath(raw_path).replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    if (
        not value
        or value.startswith("/")
        or re.match(r"^[A-Za-z]:", value)
        or "\x00" in value
    ):
        raise BoundaryGuardError(f"invalid repository path: {value!r}")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise BoundaryGuardError(f"non-canonical repository path: {value!r}")
    return value


def _compile_public_glob(pattern: str) -> re.Pattern[str]:
    """Compile a slash-aware glob where ``**`` spans zero or more directories."""
    index = 0
    expression = ""
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                index += 2
                if index < len(pattern) and pattern[index] == "/":
                    expression += "(?:.*/)?"
                    index += 1
                else:
                    expression += ".*"
                continue
            expression += "[^/]*"
        elif char == "?":
            expression += "[^/]"
        else:
            expression += re.escape(char)
        index += 1
    return re.compile(rf"^{expression}$")


def load_public_surface(path: Path) -> list[PublicSurfaceEntry]:
    """Load and strictly validate the canonical public-surface manifest."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BoundaryGuardError("public-surface allowlist is unreadable") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise BoundaryGuardError("public-surface allowlist schema_version must be 1")
    if raw.get("policy") != "curated-public":
        raise BoundaryGuardError("public-surface allowlist policy must be curated-public")
    if raw.get("baseline") != PUBLIC_SURFACE_BASELINE:
        raise BoundaryGuardError(
            "public-surface allowlist baseline must be origin/master"
        )
    raw_entries = raw.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise BoundaryGuardError("public-surface allowlist entries must be a non-empty list")

    entries: list[PublicSurfaceEntry] = []
    seen: set[str] = set()
    for position, item in enumerate(raw_entries):
        if not isinstance(item, dict):
            raise BoundaryGuardError(f"allowlist entry {position} must be an object")
        pattern_value = item.get("pattern")
        reason_value = item.get("reason")
        if not isinstance(pattern_value, str) or not pattern_value.strip():
            raise BoundaryGuardError(f"allowlist entry {position} has no pattern")
        if not isinstance(reason_value, str) or not reason_value.strip():
            raise BoundaryGuardError(
                f"allowlist entry {position} has an empty or missing reason"
            )
        pattern = pattern_value.strip().replace("\\", "/")
        if (
            pattern.startswith("/")
            or re.match(r"^[A-Za-z]:", pattern)
            or "\x00" in pattern
            or any(part in {"", ".", ".."} for part in pattern.split("/"))
        ):
            raise BoundaryGuardError(
                f"allowlist entry {position} has a non-canonical pattern"
            )
        if pattern in seen:
            raise BoundaryGuardError(f"duplicate allowlist pattern: {pattern}")
        seen.add(pattern)
        entries.append(
            PublicSurfaceEntry(
                pattern=pattern,
                reason=reason_value.strip(),
                regex=_compile_public_glob(pattern),
            )
        )
    return entries


def public_surface_match(
    path: str,
    entries: Sequence[PublicSurfaceEntry],
) -> PublicSurfaceEntry | None:
    normalized = _normalize_repo_path(path)
    return next((entry for entry in entries if entry.regex.fullmatch(normalized)), None)


def _run_git(
    repo_root: Path,
    args: Sequence[str],
    *,
    input_bytes: bytes | None = None,
) -> bytes:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=repo_root,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BoundaryGuardError(f"git {args[0]} could not run: {exc}") from exc
    if result.returncode != 0:
        output = (result.stderr or result.stdout).decode(
            "utf-8",
            errors="replace",
        )
        cause = next(
            (line.strip() for line in output.splitlines() if line.strip()),
            "no diagnostic output",
        )
        raise BoundaryGuardError(
            f"git {args[0]} failed with exit {result.returncode}: {cause}"
        )
    return result.stdout


def _resolve_commit(repo_root: Path, revision: str) -> str:
    if not revision or revision.startswith("-"):
        raise BoundaryGuardError("invalid Git revision")
    output = _run_git(
        repo_root,
        ["rev-parse", "--verify", f"{revision}^{{commit}}"],
    )
    resolved = output.decode("ascii", errors="strict").strip()
    if not SHA_RE.fullmatch(resolved):
        raise BoundaryGuardError("Git revision did not resolve to a commit")
    return resolved.lower()


def _parse_index_record(record: bytes, *, source: str) -> Candidate:
    try:
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_id, stage = metadata.decode("ascii").split()
    except (ValueError, UnicodeError) as exc:
        raise BoundaryGuardError("malformed Git index record") from exc
    if stage != "0":
        raise BoundaryGuardError("unmerged index entry cannot be published")
    path = _normalize_repo_path(os.fsdecode(raw_path))
    return Candidate(
        path=path,
        source=source,
        git_mode=mode,
        object_id=object_id,
    )


def default_candidates(repo_root: Path) -> list[Candidate]:
    names = [
        _normalize_repo_path(os.fsdecode(name))
        for name in _run_git(
            repo_root,
            [
                "diff",
                "--name-only",
                "-z",
                "--diff-filter=ACMRTUXB",
                "HEAD",
                "--",
            ],
        ).split(b"\0")
        if name
    ]
    if not names:
        return []
    records = [
        record
        for record in _run_git(repo_root, ["ls-files", "-s", "-z"]).split(b"\0")
        if record
    ]
    if not records:
        raise BoundaryGuardError("git ls-files returned no tracked paths")
    tracked = {
        candidate.path: candidate
        for candidate in (
            _parse_index_record(record, source="worktree") for record in records
        )
    }
    candidates: list[Candidate] = []
    for path in names:
        candidate = tracked.get(path)
        if candidate is None:
            raise BoundaryGuardError(f"changed path has no tracked entry: {path}")
        candidates.append(candidate)
    return candidates


def staged_candidates(repo_root: Path) -> list[Candidate]:
    names = [
        _normalize_repo_path(os.fsdecode(name))
        for name in _run_git(
            repo_root,
            [
                "diff",
                "--cached",
                "--name-only",
                "-z",
                "--diff-filter=ACMRTUXB",
                "--",
            ],
        ).split(b"\0")
        if name
    ]
    if not names:
        return []

    candidates: list[Candidate] = []
    for path in names:
        records = [
            record
            for record in _run_git(
                repo_root, ["ls-files", "-s", "-z", "--", path]
            ).split(b"\0")
            if record
        ]
        if len(records) != 1:
            raise BoundaryGuardError(f"staged path has no unique index entry: {path}")
        candidates.append(_parse_index_record(records[0], source="index"))
    return candidates


def explicit_candidates(repo_root: Path, raw_paths: Sequence[Path]) -> list[Candidate]:
    if not raw_paths:
        return []
    root = repo_root.resolve()
    candidates: list[Candidate] = []
    for raw_path in raw_paths:
        path = raw_path if raw_path.is_absolute() else root / raw_path
        try:
            resolved = path.resolve(strict=True)
            relative = resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            raise BoundaryGuardError(f"explicit path is unavailable: {raw_path}") from exc
        if resolved.is_dir():
            files = sorted(
                (item for item in resolved.rglob("*") if item.is_file()),
                key=lambda item: item.as_posix().lower(),
            )
            for item in files:
                candidates.append(
                    Candidate(
                        path=_normalize_repo_path(item.relative_to(root).as_posix()),
                        source="worktree",
                    )
                )
        else:
            candidates.append(
                Candidate(
                    path=_normalize_repo_path(relative.as_posix()),
                    source="worktree",
                )
            )
    return _deduplicate_candidates(candidates)


def _parse_tree_record(record: bytes, *, revision: str) -> Candidate:
    try:
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split()
    except (ValueError, UnicodeError) as exc:
        raise BoundaryGuardError("malformed Git tree record") from exc
    return Candidate(
        path=_normalize_repo_path(os.fsdecode(raw_path)),
        source="commit",
        revision=revision,
        git_mode=mode,
        object_id=object_id if object_type == "commit" else None,
    )


def _candidate_at_commit(repo_root: Path, revision: str, path: str) -> Candidate:
    records = [
        record
        for record in _run_git(
            repo_root, ["ls-tree", "-z", revision, "--", path]
        ).split(b"\0")
        if record
    ]
    if len(records) != 1:
        raise BoundaryGuardError(f"path is not uniquely readable at {revision}: {path}")
    return _parse_tree_record(records[0], revision=revision)


def resolve_ref_update(
    repo_root: Path,
    *,
    local_sha: str,
    remote_sha: str,
) -> list[Candidate]:
    """Resolve one pre-push ref update to every path that becomes public."""
    if not SHA_RE.fullmatch(local_sha) or not SHA_RE.fullmatch(remote_sha):
        raise BoundaryGuardError("pre-push update contains an invalid object id")
    if ZERO_SHA_RE.fullmatch(local_sha):
        return []

    local_commit = _resolve_commit(repo_root, local_sha)
    if local_sha.lower() == remote_sha.lower():
        return []
    if ZERO_SHA_RE.fullmatch(remote_sha):
        records = [
            record
            for record in _run_git(
                repo_root, ["ls-tree", "-r", "-z", local_commit]
            ).split(b"\0")
            if record
        ]
        return [
            _parse_tree_record(record, revision=local_commit) for record in records
        ]

    remote_commit = _resolve_commit(repo_root, remote_sha)
    names = [
        _normalize_repo_path(os.fsdecode(name))
        for name in _run_git(
            repo_root,
            [
                "diff",
                "--name-only",
                "-z",
                "--diff-filter=ACMRTUXB",
                remote_commit,
                local_commit,
                "--",
            ],
        ).split(b"\0")
        if name
    ]
    return [
        _candidate_at_commit(repo_root, local_commit, path) for path in names
    ]


def ref_range_candidates(repo_root: Path, ref_range: str) -> list[Candidate]:
    if ref_range.count("..") != 1 or "..." in ref_range:
        raise BoundaryGuardError("ref range must use the BASE..TIP form")
    base, tip = ref_range.split("..", 1)
    if not base or not tip:
        raise BoundaryGuardError("ref range must include both BASE and TIP")
    base_commit = _resolve_commit(repo_root, base)
    tip_commit = _resolve_commit(repo_root, tip)
    return resolve_ref_update(
        repo_root,
        local_sha=tip_commit,
        remote_sha=base_commit,
    )


def parse_pre_push_updates(
    repo_root: Path,
    text: str,
) -> list[Candidate]:
    """Parse Git's documented four-field pre-push stdin protocol."""
    candidates: list[Candidate] = []
    saw_update = False
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line.strip():
            continue
        saw_update = True
        fields = raw_line.split()
        if len(fields) != 4:
            raise BoundaryGuardError(
                f"malformed pre-push update on line {line_number}"
            )
        _local_ref, local_sha, _remote_ref, remote_sha = fields
        candidates.extend(
            resolve_ref_update(
                repo_root,
                local_sha=local_sha.lower(),
                remote_sha=remote_sha.lower(),
            )
        )
    if not saw_update:
        # Git invokes pre-push with an empty update stream when a selector is
        # already identical to the remote. Nothing can become public.
        return []
    return _deduplicate_candidates(candidates)


def _deduplicate_candidates(candidates: Sequence[Candidate]) -> list[Candidate]:
    unique: dict[tuple[str, str, str | None], Candidate] = {}
    for candidate in candidates:
        unique[candidate.identity] = candidate
    return sorted(
        unique.values(),
        key=lambda item: (item.path.lower(), item.source, item.revision or ""),
    )


def _read_candidate(repo_root: Path, candidate: Candidate) -> bytes:
    if candidate.git_mode == "160000":
        if not candidate.object_id:
            raise BoundaryGuardError(f"gitlink has no object id: {candidate.path}")
        return (candidate.object_id + "\n").encode("ascii")
    if candidate.source == "worktree":
        path = repo_root / Path(candidate.path)
        if candidate.git_mode == "120000" and path.is_symlink():
            return os.fsencode(os.readlink(path))
        return path.read_bytes()
    if candidate.source == "index":
        return _run_git(repo_root, ["show", f":{candidate.path}"])
    if candidate.source == "commit" and candidate.revision:
        return _run_git(
            repo_root,
            ["show", f"{candidate.revision}:{candidate.path}"],
        )
    raise BoundaryGuardError(f"unsupported candidate source: {candidate.source}")


def _run_release_gate_for_candidates(
    repo_root: Path,
    candidates: Sequence[Candidate],
) -> dict[str, Any]:
    """Run the existing privacy gate over exactly the same candidate bytes."""
    findings: list[dict[str, Any]] = []
    scanned: list[str] = []
    skipped_binary: list[str] = []
    for candidate in candidates:
        try:
            raw = _read_candidate(repo_root, candidate)
            if b"\x00" in raw[:4096]:
                skipped_binary.append(candidate.path)
                continue
            findings.extend(
                release_gate.scan_text(
                    candidate.path,
                    raw.decode("utf-8", errors="replace"),
                )
            )
            scanned.append(candidate.path)
        except Exception:  # noqa: BLE001 - unreadable publish bytes must block.
            findings.append(
                {
                    "path": candidate.path,
                    "line": 0,
                    "rule": "unreadable_file",
                    "severity": "BLOCK",
                    "redacted_excerpt": "<redacted len=30>",
                }
            )

    release_allowlist_path = (
        repo_root / "data" / "skynet_public_release_allowlist.json"
    )
    release_allowlist, invalid = release_gate.load_allowlist(
        release_allowlist_path
    )
    findings.extend(invalid)
    allowed_keys = {
        (entry["path"], entry["rule"]) for entry in release_allowlist
    }
    surviving = [
        item
        for item in findings
        if (item["path"], item["rule"]) not in allowed_keys
    ]
    counts = {
        severity: sum(
            1 for item in surviving if item.get("severity") == severity
        )
        for severity in ("BLOCK", "WARN")
    }
    return {
        "ok": counts["BLOCK"] == 0,
        "counts": counts,
        "findings": surviving,
        "scanned_files": sorted(set(scanned)),
        "scanned_file_count": len(scanned),
        "skipped_binary": sorted(set(skipped_binary)),
        "skipped_binary_count": len(skipped_binary),
    }


def _failure_report(
    scope: str,
    message: str,
    *,
    subject: str,
) -> dict[str, Any]:
    return {
        "tool": TOOL_NAME,
        "scope": scope,
        "ok": False,
        "overridden": False,
        "candidate_paths": [],
        "candidate_path_count": 0,
        "counts": {
            "WOULD_PUBLISH_PRIVATE": 0,
            "RELEASE_GATE_BLOCK": 0,
            "GUARD_FAILURE": 1,
        },
        "violations": [
            {
                "code": "GUARD_FAILURE",
                "path": subject,
                "detail": message,
            }
        ],
        "release_gate": None,
    }


ReleaseScanner = Callable[[Path, Sequence[Candidate]], Mapping[str, Any]]


def run_boundary_guard(
    *,
    repo_root: Path,
    candidates: Sequence[Candidate],
    scope: str,
    allowlist_path: Path | None = None,
    release_scanner: ReleaseScanner | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Evaluate publication candidates and return one fail-closed report."""
    try:
        selected = _deduplicate_candidates(candidates)
        if not selected:
            return {
                "tool": TOOL_NAME,
                "scope": scope,
                "ok": True,
                "overridden": False,
                "candidate_paths": [],
                "candidate_path_count": 0,
                "counts": {
                    "WOULD_PUBLISH_PRIVATE": 0,
                    "RELEASE_GATE_BLOCK": 0,
                    "GUARD_FAILURE": 0,
                },
                "violations": [],
                "release_gate": {
                    "ok": True,
                    "counts": {"BLOCK": 0, "WARN": 0},
                    "findings": [],
                    "scan_performed": False,
                    "scan_skipped_reason": "no_candidates",
                    "scanned_files": [],
                    "scanned_file_count": 0,
                    "skipped_binary": [],
                    "skipped_binary_count": 0,
                },
            }
        entries = load_public_surface(
            allowlist_path
            or repo_root / "data" / "skynet_public_surface.json"
        )
        private_paths = sorted(
            {
                candidate.path
                for candidate in selected
                if public_surface_match(candidate.path, entries) is None
            }
        )
        scanner = release_scanner or _run_release_gate_for_candidates
        release_report = dict(scanner(repo_root, selected))
        release_counts = release_report.get("counts")
        if not isinstance(release_counts, Mapping):
            raise BoundaryGuardError("release gate returned malformed counts")
        release_blocks = int(release_counts.get("BLOCK", 0))
        release_findings = release_report.get("findings")
        if not isinstance(release_findings, list):
            raise BoundaryGuardError("release gate returned malformed findings")

        violations: list[dict[str, Any]] = [
            {
                "code": "WOULD_PUBLISH_PRIVATE",
                "path": path,
                "detail": "path is not covered by data/skynet_public_surface.json",
            }
            for path in private_paths
        ]
        for finding in release_findings:
            if not isinstance(finding, Mapping):
                raise BoundaryGuardError("release gate returned malformed finding")
            if finding.get("severity") != "BLOCK":
                continue
            violations.append(
                {
                    "code": "RELEASE_GATE_BLOCK",
                    "path": str(finding.get("path") or "<unknown>"),
                    "rule": str(finding.get("rule") or "unknown"),
                    "line": int(finding.get("line") or 0),
                    "redacted_excerpt": str(
                        finding.get("redacted_excerpt") or "<redacted>"
                    ),
                }
            )
        if release_blocks != sum(
            1
            for finding in release_findings
            if isinstance(finding, Mapping)
            and finding.get("severity") == "BLOCK"
        ):
            raise BoundaryGuardError("release gate BLOCK count is inconsistent")

        environment = environ if environ is not None else os.environ
        override_requested = environment.get("SKYNET_ALLOW_PUBLISH") == "1"
        violating_paths = sorted(
            {
                str(item["path"])
                for item in violations
                if item.get("path") and item.get("path") != "<guard>"
            }
        )
        overridden = bool(violations and override_requested)
        report = {
            "tool": TOOL_NAME,
            "scope": scope,
            "ok": not violations or overridden,
            "overridden": overridden,
            "candidate_paths": sorted(
                {candidate.path for candidate in selected}
            ),
            "candidate_path_count": len(
                {candidate.path for candidate in selected}
            ),
            "counts": {
                "WOULD_PUBLISH_PRIVATE": len(private_paths),
                "RELEASE_GATE_BLOCK": release_blocks,
                "GUARD_FAILURE": 0,
            },
            "violations": violations,
            "release_gate": release_report,
        }
        if overridden:
            report["override_warning"] = {
                "environment": "SKYNET_ALLOW_PUBLISH=1",
                "private_paths_being_published": violating_paths,
            }
        return report
    except Exception as exc:  # noqa: BLE001 - top-level enforcement is fail-closed.
        return _failure_report(
            scope,
            f"{type(exc).__name__}: {exc}",
            subject="boundary-evaluation",
        )


def _hook_backup_path(hooks_dir: Path, existing: bytes) -> Path:
    candidate = hooks_dir / PRESERVED_HOOK_PREFIX
    suffix = 0
    while candidate.exists():
        try:
            if candidate.read_bytes() == existing:
                return candidate
        except OSError:
            pass
        suffix += 1
        candidate = hooks_dir / f"{PRESERVED_HOOK_PREFIX}.{suffix}"
    return candidate


def _hook_script(preserved_name: str | None) -> str:
    preserved = preserved_name or ""
    return f"""#!/bin/sh
{MANAGED_HOOK_MARKER}
# preserved-hook: {preserved}
set -u

repo_root="$(git rev-parse --show-toplevel)" || exit 2
hooks_dir="$(git rev-parse --git-path hooks)" || exit 2
updates_file="$hooks_dir/.skynet-pre-push-updates.$$"
trap 'rm -f "$updates_file"' EXIT HUP INT TERM
cat >"$updates_file" || exit 2

python "$repo_root/tools/skynet_publish_boundary_guard.py" \
  --pre-push --updates-file "$updates_file" --gate
guard_status=$?
if [ "$guard_status" -ne 0 ]; then
  exit "$guard_status"
fi

preserved_hook="{preserved}"
if [ -n "$preserved_hook" ] && [ -f "$hooks_dir/$preserved_hook" ]; then
  "$hooks_dir/$preserved_hook" "$@" <"$updates_file"
  exit $?
fi
exit 0
"""


def install_hook(repo_root: Path) -> dict[str, Any]:
    hooks_dir_raw = _run_git(repo_root, ["rev-parse", "--git-path", "hooks"])
    hooks_dir = Path(os.fsdecode(hooks_dir_raw).strip())
    if not hooks_dir.is_absolute():
        hooks_dir = repo_root / hooks_dir
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-push"
    preserved_name: str | None = None
    action = "installed"

    if hook_path.exists():
        existing = hook_path.read_bytes()
        existing_text = existing.decode("utf-8", errors="replace")
        if MANAGED_HOOK_MARKER in existing_text:
            match = PRESERVED_HOOK_RE.search(existing_text)
            preserved_name = (
                match.group("name").strip() if match and match.group("name").strip() else None
            )
            action = "already_installed"
        else:
            backup = _hook_backup_path(hooks_dir, existing)
            if not backup.exists():
                shutil.copy2(hook_path, backup)
            preserved_name = backup.name
            action = "installed_preserved_existing"

    expected = _hook_script(preserved_name).encode("utf-8")
    if not hook_path.exists() or hook_path.read_bytes() != expected:
        hook_path.write_bytes(expected)
        action = "updated" if action == "already_installed" else action
    current_mode = hook_path.stat().st_mode
    hook_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return {
        "ok": True,
        "action": action,
        "hook": str(hook_path),
        "preserved_hook": preserved_name,
    }


def uninstall_hook(repo_root: Path) -> dict[str, Any]:
    hooks_dir_raw = _run_git(repo_root, ["rev-parse", "--git-path", "hooks"])
    hooks_dir = Path(os.fsdecode(hooks_dir_raw).strip())
    if not hooks_dir.is_absolute():
        hooks_dir = repo_root / hooks_dir
    hook_path = hooks_dir / "pre-push"
    if not hook_path.exists():
        return {
            "ok": True,
            "action": "not_installed",
            "hook": str(hook_path),
            "restored_hook": None,
        }
    text = hook_path.read_text(encoding="utf-8", errors="replace")
    if MANAGED_HOOK_MARKER not in text:
        raise BoundaryGuardError("refusing to uninstall an unmanaged pre-push hook")
    match = PRESERVED_HOOK_RE.search(text)
    preserved_name = (
        match.group("name").strip() if match and match.group("name").strip() else ""
    )
    if preserved_name:
        if Path(preserved_name).name != preserved_name:
            raise BoundaryGuardError("managed hook contains an invalid preserved-hook path")
        backup = hooks_dir / preserved_name
        if not backup.is_file():
            raise BoundaryGuardError("preserved pre-push hook is missing")
        os.replace(backup, hook_path)
        action = "uninstalled_restored_existing"
        restored: str | None = str(hook_path)
    else:
        hook_path.unlink()
        action = "uninstalled"
        restored = None
    return {
        "ok": True,
        "action": action,
        "hook": str(hook_path),
        "restored_hook": restored,
    }


def _render_override_warning(report: Mapping[str, Any]) -> str:
    warning = report.get("override_warning")
    if not isinstance(warning, Mapping):
        return ""
    paths = warning.get("private_paths_being_published") or []
    lines = [
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
        "WARNING: SKYNET_ALLOW_PUBLISH=1 OVERRIDE IS ACTIVE",
        "PRIVATE PATHS BEING PUBLISHED:",
        *[f"  - {path}" for path in paths],
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
    ]
    return "\n".join(lines)


def _render_text(report: Mapping[str, Any]) -> str:
    if report.get("ok") and not report.get("overridden"):
        counts = report["counts"]
        return "\n".join(
            [
                "SKYNET PUBLISH BOUNDARY: PASS",
                f"scope: {report['scope']}",
                f"candidate paths: {report['candidate_path_count']}",
                f"release-gate BLOCK: {counts['RELEASE_GATE_BLOCK']}",
            ]
        )

    lines = [
        (
            "SKYNET PUBLISH BOUNDARY: OVERRIDDEN"
            if report.get("overridden")
            else "SKYNET PUBLISH BOUNDARY: REFUSED"
        ),
        f"scope: {report['scope']}",
        (
            "counts: "
            f"WOULD_PUBLISH_PRIVATE={report['counts']['WOULD_PUBLISH_PRIVATE']} "
            f"RELEASE_GATE_BLOCK={report['counts']['RELEASE_GATE_BLOCK']} "
            f"GUARD_FAILURE={report['counts']['GUARD_FAILURE']}"
        ),
    ]
    for violation in report.get("violations", []):
        code = violation.get("code", "GUARD_FAILURE")
        path = violation.get("path", "unknown")
        suffix = (
            f" ({violation.get('rule')})"
            if violation.get("rule")
            else ""
        )
        detail = (
            f" -- {violation.get('detail')}"
            if code == "GUARD_FAILURE" and violation.get("detail")
            else ""
        )
        lines.append(f"{code}: {path}{suffix}{detail}")
    if not report.get("overridden"):
        lines.extend(
            [
                "Push blocked: the listed paths are outside the curated public surface",
                "or failed the public release gate.",
                "Deliberate override only: SKYNET_ALLOW_PUBLISH=1 (all paths are named).",
            ]
        )
    return "\n".join(lines)


def _selector_candidates(
    *,
    repo_root: Path,
    staged: bool,
    paths: Sequence[Path] | None,
    ref_range: str | None,
    pre_push: bool,
    updates_file: Path | None,
) -> tuple[str, list[Candidate]]:
    selectors = sum(
        value
        for value in (
            staged,
            paths is not None,
            ref_range is not None,
            pre_push,
        )
    )
    if selectors > 1:
        raise BoundaryGuardError(
            "--staged, --paths, ref range, and --pre-push are mutually exclusive"
        )
    if pre_push:
        if updates_file:
            text = updates_file.read_text(encoding="utf-8")
        else:
            text = sys.stdin.read()
        scope = "pre-push"
        candidates = parse_pre_push_updates(repo_root, text)
    elif staged:
        scope = "staged"
        candidates = staged_candidates(repo_root)
    elif paths is not None:
        scope = "explicit"
        candidates = explicit_candidates(repo_root, paths)
    elif ref_range is not None:
        scope = f"ref-range:{ref_range}"
        candidates = ref_range_candidates(repo_root, ref_range)
    else:
        scope = "tracked-worktree"
        candidates = default_candidates(repo_root)
    return scope, _deduplicate_candidates(candidates)


def gate_exit_code(report: Mapping[str, Any]) -> int:
    return 0 if report.get("ok") else GATE_BLOCKED


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("range", nargs="?", help="Git ref range in BASE..TIP form")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="repository root (default: current directory)",
    )
    parser.add_argument("--ref-range", help="Git ref range in BASE..TIP form")
    parser.add_argument("--staged", action="store_true", help="check staged paths")
    parser.add_argument("--paths", nargs="+", type=Path, help="check explicit paths")
    parser.add_argument(
        "--pre-push",
        action="store_true",
        help="read documented pre-push ref updates from stdin",
    )
    parser.add_argument(
        "--updates-file",
        type=Path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument(
        "--gate",
        action="store_true",
        help="enforce exit 2 on any violation (also the default)",
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        help="alternate public-surface manifest for isolated validation",
    )
    parser.add_argument(
        "--install-hook",
        action="store_true",
        help="idempotently install the preserving pre-push hook",
    )
    parser.add_argument(
        "--uninstall-hook",
        action="store_true",
        help="uninstall the managed hook and restore any preserved hook",
    )
    args = parser.parse_args(argv)

    repo_root = args.repo_root.resolve()
    if args.install_hook and args.uninstall_hook:
        parser.error("--install-hook and --uninstall-hook are mutually exclusive")
    if args.range and args.ref_range:
        parser.error("use either positional range or --ref-range, not both")
    if args.updates_file and not args.pre_push:
        parser.error("--updates-file requires --pre-push")

    if args.install_hook or args.uninstall_hook:
        if any((args.range, args.ref_range, args.staged, args.paths, args.pre_push)):
            parser.error("hook lifecycle flags cannot be combined with guard selectors")
        try:
            result = (
                install_hook(repo_root)
                if args.install_hook
                else uninstall_hook(repo_root)
            )
            print(
                json.dumps(result, indent=2, sort_keys=True)
                if args.json
                else f"{result['action']}: {result['hook']}"
            )
            return 0
        except Exception as exc:  # noqa: BLE001 - lifecycle failures must be nonzero.
            result = {
                "ok": False,
                "action": "hook_lifecycle_failed",
                "error": f"{type(exc).__name__}: operation failed",
            }
            print(
                json.dumps(result, indent=2, sort_keys=True)
                if args.json
                else f"hook_lifecycle_failed: {type(exc).__name__}",
                file=sys.stderr,
            )
            return GATE_BLOCKED

    scope = "selector"
    try:
        scope, candidates = _selector_candidates(
            repo_root=repo_root,
            staged=args.staged,
            paths=args.paths,
            ref_range=args.ref_range or args.range,
            pre_push=args.pre_push,
            updates_file=args.updates_file,
        )
        report = run_boundary_guard(
            repo_root=repo_root,
            candidates=candidates,
            scope=scope,
            allowlist_path=args.allowlist,
        )
    except Exception as exc:  # noqa: BLE001 - selector failures are gate failures.
        report = _failure_report(
            scope,
            f"{type(exc).__name__}: {exc}",
            subject="candidate-selection",
        )

    override_warning = _render_override_warning(report)
    if override_warning:
        print(override_warning, file=sys.stderr)
    print(
        json.dumps(report, indent=2, sort_keys=True)
        if args.json
        else _render_text(report)
    )
    return gate_exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
