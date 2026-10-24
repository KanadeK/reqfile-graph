"""A documented lexical subset; this is not a pip requirement parser."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass


@dataclass(frozen=True)
class Statement:
    line: int
    kind: str
    target: str = ""
    problem: str = ""


def statements(text: str) -> list[Statement]:
    """Join physical lines, then strip pip-style whitespace-prefixed comments.

    Package specifications are deliberately not returned or interpreted. Include
    arguments are kept only internally until the root-containment policy checks.
    """
    result = []
    pieces = []
    start = 1

    def classify(source: str, number: int) -> Statement | None:
        line = re.sub(r"(^|\s)#.*", "", source).strip()
        if not line:
            return None
        if "\x00" in line:
            return Statement(number, "invalid", problem="nul-input")
        first = line.split(maxsplit=1)[0]
        include_prefix = first.startswith(("-r", "-c")) and not first.startswith("--")
        include_prefix |= first.startswith(("--requirement", "--constraint"))
        option_name = first.split("=", 1)[0]
        abbreviation = option_name.startswith("--") and any(
            full.startswith(option_name) for full in ("--requirement", "--constraint")
        )
        if include_prefix or abbreviation:
            if "\\" in line:
                return Statement(number, "invalid", problem="nonportable-reference")
            try:
                tokens = shlex.split(line, posix=True)
            except ValueError:
                return Statement(number, "invalid", problem="include-syntax")
            option = tokens[0]
            for short, long, kind in (
                ("-r", "--requirement", "requirement"),
                ("-c", "--constraint", "constraint"),
            ):
                if option in (short, long) and len(tokens) == 2:
                    return Statement(number, kind, tokens[1])
                if option.startswith(long + "=") and len(tokens) == 1:
                    return Statement(number, kind, option[len(long) + 1 :])
                if option.startswith(short) and not option.startswith("--") and len(tokens) == 1:
                    return Statement(number, kind, option[2:])
            return Statement(number, "invalid", problem="include-syntax")
        if re.search(r"(?:^|\s)(?:--requirement|--constraint|-r|-c)(?:\s|=|\S)", line):
            return Statement(number, "invalid", problem="combined-include")
        if (
            line.startswith(("-e", "--editable", "./", "../", "/", "~", "\\"))
            or re.match(r"^[A-Za-z]:", line)
            or "file:" in line
            or (
                not re.search(r"[A-Za-z][A-Za-z0-9+.-]*://", line)
                and re.match(r"^\S+\.(?:whl|zip|tar\.gz)(?:\s|$)", line)
            )
        ):
            return Statement(number, "statement", problem="local-install-statement")
        return Statement(number, "statement")

    for number, physical in enumerate(text.splitlines(), 1):
        comment = physical.lstrip().startswith("#")
        if not pieces:
            start = number
        if physical.endswith("\\") and not comment:
            if physical.endswith("\\\\"):
                result.append(Statement(start, "invalid", problem="ambiguous-continuation"))
                pieces = []
                continue
            pieces.append(physical[:-1])
            continue
        # A comment ends any pending continuation without swallowing its newline.
        pieces.append((" " if comment else "") + physical)
        statement = classify("".join(pieces), start)
        if statement is not None:
            result.append(statement)
        pieces = []
    if pieces:
        result.append(Statement(start, "invalid", problem="dangling-continuation"))
    return result
