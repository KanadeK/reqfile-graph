"""Static include inventory. Never fetch, install, expand variables or print URLs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path, PureWindowsPath
from typing import Any

from .lex import Statement, statements


def audit(
    entries: list[str | Path],
    *,
    root: str | Path,
    max_files: int = 512,
    max_depth: int = 64,
    max_file_bytes: int = 1_048_576,
    max_total_bytes: int = 16_777_216,
    max_findings: int = 1000,
    warnings_as_errors: bool = False,
) -> dict[str, Any]:
    """Audit explicit entry paths relative to cwd; include paths use their parent's directory.

    Paths in the result are relative to the canonical bundle root. Reparse points
    below that root are rejected, including links pointing back inside the root.
    A node may be visited as requirements and constraints independently. Each
    include sets the target context: -r requirements, -c constraints (as in pip).
    """
    for limit in (max_files, max_depth, max_file_bytes, max_total_bytes, max_findings):
        if type(limit) is not int or limit < 1:
            raise ValueError("Resource limits must be positive integers")
    if max_depth > 128:
        raise ValueError("max_depth must not exceed 128")
    nodes: dict[str, dict[str, Any]] = {}
    cache: dict[str, list[Statement]] = {}
    edges: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    active: list[str] = []
    visited: set[tuple[str, str]] = set()
    entry_names: list[str] = []
    error_count = warning_count = total_bytes = 0

    def add(code: str, *, severity: str = "error", **location: Any) -> None:
        nonlocal error_count, warning_count
        if severity == "error":
            error_count += 1
        else:
            warning_count += 1
        if len(findings) < max_findings:
            findings.append({"code": code, "severity": severity, **location})

    try:
        bundle = Path(root).resolve(strict=True)
        if not bundle.is_dir():
            raise OSError
    except (OSError, ValueError, RuntimeError):
        bundle = None
        add("invalid-root")

    def checked(path: Path, **location: Any) -> tuple[Path, str] | None:
        assert bundle is not None
        absolute = Path(os.path.abspath(path))
        try:
            relative = absolute.relative_to(bundle)
        except ValueError:
            add("outside-root", **location)
            return None
        cursor = bundle
        try:
            for part in relative.parts:
                cursor /= part
                info = cursor.lstat()
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    add("linked-path", **location)
                    return None
            absolute = absolute.resolve(strict=True)
            relative = absolute.relative_to(bundle)
            info = absolute.stat()
            if not stat.S_ISREG(info.st_mode):
                add("not-regular-file", **location)
                return None
        except (OSError, ValueError, RuntimeError):
            add("missing-file", **location)
            return None
        return absolute, relative.as_posix()

    def walk(path: Path, relative: str, context: str, depth: int) -> None:
        nonlocal total_bytes
        if relative in active:
            add("include-cycle", file=relative, chain=[*active[active.index(relative) :], relative])
            return
        if (relative, context) in visited:
            return
        if depth > max_depth:
            add("depth-limit", file=relative)
            return
        visited.add((relative, context))
        if relative not in cache:
            if len(nodes) >= max_files:
                add("file-limit", file=relative)
                return
            try:
                with path.open("rb") as stream:
                    raw = stream.read(min(max_file_bytes, max_total_bytes - total_bytes) + 1)
                if len(raw) > max_file_bytes or total_bytes + len(raw) > max_total_bytes:
                    add("byte-limit", file=relative)
                    return
                total_bytes += len(raw)
                text = raw.decode("utf-8-sig")
                first_lines = "\n".join(text.splitlines()[:2])
                coding = re.search(r"(?m)^[ \t\f]*#.*?coding[:=]\s*([-\w.]+)", first_lines)
                if coding and coding.group(1).lower().replace("_", "-") not in ("utf-8", "utf8"):
                    add("unsupported-encoding", file=relative)
                    return
                cache[relative] = statements(text)
            except (OSError, UnicodeError):
                add("unreadable-file", file=relative)
                return
            nodes[relative] = {
                "path": relative,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "contexts": [],
                "statement_count": sum(x.kind == "statement" for x in cache[relative]),
            }
        nodes[relative]["contexts"].append(context)
        active.append(relative)
        for statement in cache[relative]:
            location = {"file": relative, "line": statement.line, "context": context}
            if statement.problem:
                add(
                    statement.problem,
                    severity="warning" if statement.kind == "statement" else "error",
                    **location,
                )
            if statement.kind not in ("requirement", "constraint"):
                continue
            if len(edges) >= 10_000:
                add("edge-limit", **location)
                break
            target = statement.target
            edge = {
                "source": relative,
                "line": statement.line,
                "source_context": context,
                "kind": statement.kind,
                "target": None,
                "status": "blocked",
            }
            edges.append(edge)
            if not target or any(ord(c) < 32 for c in target):
                add("invalid-reference", **location)
                continue
            if "$" in target or re.search(r"%[^%]+%", target) or target.startswith("~"):
                add("dynamic-reference", **location)
                continue
            if (
                target.startswith(("/", "\\"))
                or Path(target).is_absolute()
                or PureWindowsPath(target).drive
            ):
                add("absolute-reference", **location)
                continue
            if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", target):
                add("remote-reference", **location)
                continue
            if "\\" in target or any(c in target for c in "*?[]"):
                add("nonportable-reference", **location)
                continue
            accepted = checked(path.parent / target, **location)
            if accepted is None:
                continue
            child_path, child_name = accepted
            edge["target"] = child_name
            edge["status"] = "local"
            walk(child_path, child_name, statement.kind, depth + 1)
        active.pop()

    if not entries:
        add("no-entries")
    elif bundle is not None:
        if len(entries) > max_files:
            add("entry-limit")
        else:
            for entry in entries:
                accepted = checked(Path(entry), file="(entry)", line=0)
                if accepted:
                    path, name = accepted
                    entry_names.append(name)
                    walk(path, name, "requirement", 0)
    total = error_count + warning_count
    return {
        "schema_version": 1,
        "ok": error_count == 0 and (warning_count == 0 or not warnings_as_errors),
        "complete": error_count == 0,
        "entries": entry_names,
        "files": [nodes[key] for key in sorted(nodes)],
        "edges": edges,
        "total_bytes": total_bytes,
        "error_count": error_count,
        "warning_count": warning_count,
        "finding_count": total,
        "findings_truncated": total > len(findings),
        "findings": findings,
    }


def to_dot(report: dict[str, Any]) -> str:
    """Render a Graphviz graph, escaping all filenames and omitting blocked targets."""

    def quote(value: str) -> str:
        return json.dumps(value, ensure_ascii=False)

    lines = ["digraph requirements {", '  rankdir="LR";']
    ids = {file["path"]: f"n{number}" for number, file in enumerate(report["files"])}
    for file in report["files"]:
        lines.append(f"  {ids[file['path']]} [label={quote(file['path'])}];")
    for number, edge in enumerate(report["edges"]):
        source = ids.get(edge["source"])
        if source is None:
            continue
        target = ids.get(edge["target"])
        if target is None:
            target = f"blocked{number}"
            lines.append(f'  {target} [label="unresolved", shape="box"];')
        label = f"{edge['kind']} :{edge['line']} ({edge['source_context']})"
        lines.append(f"  {source} -> {target} [label={quote(label)}];")
    lines.append("}")
    return "\n".join(lines)
