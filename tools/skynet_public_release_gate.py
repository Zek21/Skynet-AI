#!/usr/bin/env python3
"""Fail-closed leak gate for files destined for a public repository."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

GATE_BLOCKED = 2
TOOL_NAME = "skynet_public_release_gate"

# Keep all owner-specific identity policy here so it is easy to audit and edit.
OWNER_IDENTITIES = {
    "handles": frozenset({"exzil" + "calanza", "zek21"}),
    "domains": frozenset({"exzil" + "calanza.info"}),
    "emails": frozenset(
        {
            "exzil" + "calanza" + "@" + "gmail.com",
            "exzil.calanza" + "@" + "wvsu.edu.ph",
            "rogiebase7" + "@" + "gmail.com",
        }
    ),
}

EXAMPLE_EMAIL_DOMAINS = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "example.test",
        "test.local",
        "foo.bar",
    }
)
ASSET_FILE_SUFFIXES = frozenset(
    {"avif", "gif", "ico", "jpeg", "jpg", "png", "svg", "webp"}
)
GENERIC_EMAIL_LOCALS = frozenset({"me", "name", "owner", "user"})
GENERIC_DOMAIN_LABELS = frozenset(
    {"company", "domain", "example", "mail", "site", "test"}
)

_DIRECT_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "openai_or_anthropic_token",
        re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{12,}\b"),
    ),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35,}\b")),
    (
        "private_key_pem",
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "private_path_d_prospects",
        re.compile(
            r"D:(?:\\+|/)Prospects(?:\\+|/)[^\s\"'<>|,;)]*",
            re.IGNORECASE,
        ),
    ),
    (
        "private_path_c_users",
        re.compile(
            r"C:(?:\\+|/)Users(?:\\+|/)[^\\/\s\"'<>]+"
            r"(?:\\+|/)[^\s\"'<>|,;)]*",
            re.IGNORECASE,
        ),
    ),
)
_JSON_SECRET = re.compile(
    r"""["'](?P<key>refresh_token|access_token|id_token|client_secret)["']"""
    r"""\s*:\s*["'](?P<value>[^"'\\]*(?:\\.[^"'\\]*)*)["']""",
    re.IGNORECASE,
)
_EMAIL = re.compile(
    r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.(?:[A-Za-z]{2,}|invalid)"
    r"(?![\w.-])"
)

ReadBytes = Callable[[Path], bytes]


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _redact(value: str) -> str:
    if len(value) <= 9:
        return f"<redacted len={len(value)}>"
    return f"{value[:6]}…{value[-3:]} (len={len(value)})"


def _finding(
    path: str,
    line: int,
    rule: str,
    severity: str,
    value: str,
) -> dict[str, Any]:
    return {
        "path": path,
        "line": line,
        "rule": rule,
        "severity": severity,
        "redacted_excerpt": _redact(value),
    }


def _looks_real_secret_value(value: str) -> bool:
    normalized = value.strip().lower()
    if not normalized:
        return False
    placeholders = (
        "redacted",
        "placeholder",
        "example",
        "dummy",
        "changeme",
        "your_",
        "your-",
        "replace_me",
        "replace-me",
        "${",
        "{{",
        "<",
    )
    return normalized not in {"none", "null", "undefined"} and not any(
        marker in normalized for marker in placeholders
    )


def _is_example_email(email: str) -> bool:
    domain = email.rsplit("@", 1)[1].lower()
    return domain in EXAMPLE_EMAIL_DOMAINS or domain.endswith(".invalid")


def _is_asset_reference(email: str) -> bool:
    domain = email.rsplit("@", 1)[1].lower()
    suffix = domain.rsplit(".", 1)[-1]
    return suffix in ASSET_FILE_SUFFIXES


def _is_obvious_placeholder_email(email: str) -> bool:
    local, domain = email.lower().rsplit("@", 1)
    local = local.split("+", 1)[0]
    if local in {"owner", "user"}:
        return True
    labels = domain.split(".")
    if len(labels) != 2:
        return False
    generic_domain = (
        len(labels[0]) == 1 or labels[0] in GENERIC_DOMAIN_LABELS
    )
    generic_local = len(local) == 1 or local in GENERIC_EMAIL_LOCALS
    return generic_local and generic_domain


def scan_text(path: str, text: str) -> list[dict[str, Any]]:
    """Return privacy findings for one decoded text file."""
    findings: list[dict[str, Any]] = []
    owner_emails = OWNER_IDENTITIES["emails"]
    owner_domains = OWNER_IDENTITIES["domains"]
    owner_handles = OWNER_IDENTITIES["handles"]

    for line_number, line in enumerate(text.splitlines(), start=1):
        occupied_spans: list[tuple[int, int]] = []
        for rule, pattern in _DIRECT_RULES:
            for match in pattern.finditer(line):
                findings.append(
                    _finding(path, line_number, rule, "BLOCK", match.group(0))
                )
                occupied_spans.append(match.span())

        for match in _JSON_SECRET.finditer(line):
            value = match.group("value")
            if _looks_real_secret_value(value):
                findings.append(
                    _finding(
                        path,
                        line_number,
                        f"json_{match.group('key').lower()}",
                        "BLOCK",
                        value,
                    )
                )
                occupied_spans.append(match.span("value"))

        for match in _EMAIL.finditer(line):
            email = match.group(0)
            normalized = email.lower()
            domain = normalized.rsplit("@", 1)[1]
            occupied_spans.append(match.span())
            if _is_asset_reference(email):
                continue
            if normalized in owner_emails or domain in owner_domains:
                findings.append(
                    _finding(path, line_number, "owner_email", "WARN", email)
                )
            elif not (
                _is_example_email(email)
                or _is_obvious_placeholder_email(email)
            ):
                findings.append(
                    _finding(path, line_number, "third_party_email", "BLOCK", email)
                )

        lowered = line.lower()
        for handle in owner_handles:
            for match in re.finditer(re.escape(handle), lowered):
                if any(
                    start <= match.start() and match.end() <= end
                    for start, end in occupied_spans
                ):
                    continue
                findings.append(
                    _finding(
                        path,
                        line_number,
                        "owner_handle",
                        "WARN",
                        line[match.start() : match.end()],
                    )
                )
    return findings


def _display_path(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.name


def _expand_paths(repo_root: Path, paths: Sequence[Path]) -> list[Path]:
    expanded: set[Path] = set()
    for raw_path in paths:
        path = raw_path if raw_path.is_absolute() else repo_root / raw_path
        if path.is_dir():
            expanded.update(candidate for candidate in path.rglob("*") if candidate.is_file())
        else:
            expanded.add(path)
    return sorted(expanded, key=lambda candidate: candidate.as_posix().lower())


def _run_git(repo_root: Path, args: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        check=False,
        timeout=30,
    )


def git_candidate_paths(repo_root: Path, *, staged: bool = False) -> list[Path]:
    """Select staged paths or real worktree commit candidates without ignored files."""
    if staged:
        result = _run_git(
            repo_root,
            ["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRTUXB"],
        )
        if result.returncode != 0:
            raise RuntimeError("git staged-path selection failed")
        names = [name for name in result.stdout.split(b"\0") if name]
        return [repo_root / os.fsdecode(name) for name in names]

    result = _run_git(
        repo_root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )
    if result.returncode != 0:
        raise RuntimeError("git commit-candidate selection failed")

    records = result.stdout.split(b"\0")
    paths: list[Path] = []
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record:
            continue
        if len(record) < 4:
            raise ValueError("malformed git status record")
        status = os.fsdecode(record[:2])
        name = os.fsdecode(record[3:])
        if "R" in status or "C" in status:
            index += 1  # The following NUL record is the source path.
        if status == "!!" or "D" in status:
            continue
        paths.append(repo_root / name)
    return paths


def _normalize_allowlist_entry(
    path: str,
    value: Any,
) -> list[dict[str, str]]:
    values = value if isinstance(value, list) else [value]
    normalized: list[dict[str, str]] = []
    for entry in values:
        if not isinstance(entry, dict):
            normalized.append({"path": path, "rule": "", "reason": ""})
            continue
        normalized.append(
            {
                "path": path.replace("\\", "/"),
                "rule": str(entry.get("rule", "")).strip(),
                "reason": str(entry.get("reason", "")).strip(),
            }
        )
    return normalized


def load_allowlist(path: Path) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    if not path.exists() and not path.is_symlink():
        return [], []
    if not path.is_file():
        return [], [
            _finding(path.name, 0, "invalid_allowlist", "BLOCK", "unreadable allowlist")
        ]
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return [], [
            _finding(path.name, 0, "invalid_allowlist", "BLOCK", "unreadable allowlist")
        ]
    if not isinstance(raw, dict):
        return [], [
            _finding(path.name, 0, "invalid_allowlist", "BLOCK", "allowlist not object")
        ]

    entries: list[dict[str, str]] = []
    invalid: list[dict[str, Any]] = []
    for file_path, value in raw.items():
        if not isinstance(file_path, str) or not file_path.strip():
            invalid.append(
                _finding(
                    path.name,
                    0,
                    "invalid_allowlist_entry",
                    "BLOCK",
                    "empty allowlist path",
                )
            )
            continue
        for entry in _normalize_allowlist_entry(file_path, value):
            if not entry["rule"] or not entry["reason"]:
                invalid.append(
                    _finding(
                        entry["path"],
                        0,
                        "invalid_allowlist_entry",
                        "BLOCK",
                        "rule and reason are required",
                    )
                )
            else:
                entries.append(entry)
    return entries, invalid


def scan_paths(
    *,
    repo_root: Path,
    paths: Sequence[Path],
    allowlist_path: Path,
    read_bytes: ReadBytes | None = None,
) -> dict[str, Any]:
    """Scan explicit fixtures or selected repository paths."""
    reader = read_bytes or (lambda path: path.read_bytes())
    candidates = _expand_paths(repo_root, paths)
    findings: list[dict[str, Any]] = []
    skipped_binary: list[str] = []
    scanned: list[str] = []

    for path in candidates:
        display = _display_path(path, repo_root)
        try:
            raw = reader(path)
            if not isinstance(raw, bytes):
                raise TypeError("file reader must return bytes")
            if b"\x00" in raw[:4096]:
                skipped_binary.append(display)
                continue
            text = raw.decode("utf-8", errors="replace")
            scanned.append(display)
            findings.extend(scan_text(display, text))
        except Exception:  # noqa: BLE001 - unreadable candidates must block.
            findings.append(
                _finding(
                    display,
                    0,
                    "unreadable_file",
                    "BLOCK",
                    "file could not be read",
                )
            )

    allowlist, invalid_allowlist = load_allowlist(allowlist_path)
    findings.extend(invalid_allowlist)
    finding_keys = {(item["path"], item["rule"]) for item in findings}
    allowlist_keys = {(entry["path"], entry["rule"]) for entry in allowlist}
    surviving = [
        item
        for item in findings
        if (item["path"], item["rule"]) not in allowlist_keys
    ]
    suppressed = [
        item
        for item in findings
        if (item["path"], item["rule"]) in allowlist_keys
    ]
    stale = [
        entry
        for entry in allowlist
        if (entry["path"], entry["rule"]) not in finding_keys
    ]
    counts = {
        severity: sum(1 for item in surviving if item["severity"] == severity)
        for severity in ("BLOCK", "WARN")
    }
    return {
        "tool": TOOL_NAME,
        "timestamp_utc": _utc_now(),
        "ok": counts["BLOCK"] == 0,
        "counts": counts,
        "findings": surviving,
        "suppressed_count": len(suppressed),
        "stale_allowlist": stale,
        "scan_performed": True,
        "candidate_file_count": len(candidates),
        "scanned_files": scanned,
        "scanned_file_count": len(scanned),
        "skipped_binary": skipped_binary,
        "skipped_binary_count": len(skipped_binary),
    }


def _read_staged(repo_root: Path, path: Path) -> bytes:
    relative = path.resolve().relative_to(repo_root.resolve()).as_posix()
    result = _run_git(repo_root, ["show", f":{relative}"])
    if result.returncode != 0:
        raise OSError("could not read staged file")
    return result.stdout


def run_release_gate(
    *,
    repo_root: Path,
    paths: Sequence[Path] | None = None,
    staged: bool = False,
    allowlist_path: Path | None = None,
) -> dict[str, Any]:
    """Build one fail-closed public-release report."""
    allowlist = allowlist_path or repo_root / "data" / "skynet_public_release_allowlist.json"
    try:
        selected = list(paths) if paths is not None else git_candidate_paths(
            repo_root, staged=staged
        )
        reader = (
            (lambda path: _read_staged(repo_root, path))
            if staged and paths is None
            else None
        )
        report = scan_paths(
            repo_root=repo_root,
            paths=selected,
            allowlist_path=allowlist,
            read_bytes=reader,
        )
        report["scope"] = "explicit" if paths is not None else "staged" if staged else "commit_candidates"
        return report
    except Exception as exc:  # noqa: BLE001 - top-level gate is fail-closed.
        return {
            "tool": TOOL_NAME,
            "timestamp_utc": _utc_now(),
            "scope": "explicit" if paths is not None else "staged" if staged else "commit_candidates",
            "ok": False,
            "counts": {"BLOCK": 1, "WARN": 0},
            "findings": [
                _finding(
                    "<gate>",
                    0,
                    "unexpected_exception",
                    "BLOCK",
                    f"{type(exc).__name__}: scan failed",
                )
            ],
            "suppressed_count": 0,
            "stale_allowlist": [],
            "scan_performed": False,
            "candidate_file_count": 0,
            "scanned_files": [],
            "scanned_file_count": 0,
            "skipped_binary": [],
            "skipped_binary_count": 0,
        }


def gate_exit_code(report: Mapping[str, Any], *, gate: bool) -> int:
    return GATE_BLOCKED if gate and not report.get("ok", False) else 0


def _default_receipt_path(repo_root: Path) -> Path:
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    return repo_root / "data" / "runs" / "public_release_gate" / stamp / "receipt.json"


def write_receipt(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _render_text(report: Mapping[str, Any], receipt: Path) -> str:
    counts = report["counts"]
    return "\n".join(
        [
            f"scope: {report['scope']}",
            f"scan performed: {'yes' if report['scan_performed'] else 'no'}",
            f"candidate files: {report['candidate_file_count']}",
            f"scanned files: {report['scanned_file_count']}",
            f"skipped binaries: {report['skipped_binary_count']}",
            f"BLOCK: {counts['BLOCK']}",
            f"WARN: {counts['WARN']}",
            f"receipt: {receipt}",
            f"overall: {'PASS' if report.get('ok') else 'FAIL'}",
        ]
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed leak gate for public repository candidates"
    )
    parser.add_argument("--json", action="store_true", help="print one JSON object")
    parser.add_argument("--gate", action="store_true", help="exit 2 on BLOCK findings")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="repository root (default: current directory)",
    )
    parser.add_argument("--staged", action="store_true", help="scan staged files only")
    parser.add_argument("--paths", nargs="+", type=Path, help="explicit files/directories")
    parser.add_argument(
        "--allowlist",
        type=Path,
        help="release allowlist (default: <repo-root>/data/skynet_public_release_allowlist.json)",
    )
    parser.add_argument("--receipt", type=Path, help="receipt path")
    args = parser.parse_args(argv)
    if args.staged and args.paths:
        parser.error("--staged and --paths are mutually exclusive")

    repo_root = args.repo_root.resolve()
    report = run_release_gate(
        repo_root=repo_root,
        paths=args.paths,
        staged=args.staged,
        allowlist_path=args.allowlist,
    )
    receipt = args.receipt or _default_receipt_path(repo_root)
    report["receipt"] = _display_path(receipt, repo_root)
    try:
        write_receipt(receipt, report)
    except Exception:  # noqa: BLE001 - an unwritten receipt blocks release.
        report["ok"] = False
        report["counts"]["BLOCK"] += 1
        report["findings"].append(
            _finding(
                receipt.name,
                0,
                "receipt_write_failed",
                "BLOCK",
                "receipt could not be written",
            )
        )

    if args.json or args.gate:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_render_text(report, receipt))
    return gate_exit_code(report, gate=args.gate)


if __name__ == "__main__":
    raise SystemExit(main())
