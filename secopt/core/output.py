"""Report writers: Markdown tables, CSV, JSON and a little terminal colour."""

from __future__ import annotations

import csv
import json
import re
import os
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

_COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m",
           "low": "\033[36m", "info": "\033[2m", "malicious": "\033[1;31m",
           "suspicious": "\033[33m", "harmless": "\033[32m", "unknown": "\033[2m"}
_RESET = "\033[0m"


def color_enabled(stream: Any = None, disabled: bool = False) -> bool:
    stream = stream or sys.stdout
    if disabled or os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def paint(label: str, text: str, enabled: bool) -> str:
    code = _COLORS.get(label.lower())
    return f"{code}{text}{_RESET}" if enabled and code else text


def md_escape(value: Any) -> str:
    """Text for a table cell: pipes escaped, raw HTML neutralised, line breaks kept as <br>."""
    text = "" if value is None else str(value)
    text = _neutralise(text.replace("\\", "\\\\"))
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")


def _neutralise(text: str) -> str:
    """Stop text from being read as HTML, a link, an image or code. With no "<" left no tag can
    open; with "[" and "]" escaped no link or image can form; escaped backticks open no code span."""
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace("[", "\\[").replace("]", "\\]")
            .replace("`", "\\`"))


# Characters that start a block when they open a line: heading, quote, list, rule, code fence.
_BLOCK_START = re.compile(r"^(\s*)(?:([#>\-+*~=])|(\d+)([.)])(?=\s|$))")


def md_inline(value: Any) -> str:
    """Text for a heading or paragraph: one line, no raw HTML, no links or images. Names in these
    reports come from tenants and inventory files, so they are treated as untrusted."""
    text = _neutralise(" ".join(("" if value is None else str(value)).split()).replace("\\", "\\\\"))
    # The text may be placed at the start of a line, so it must not open a block of its own.
    return _BLOCK_START.sub(lambda m: m.group(1) + (f"\\{m.group(2)}" if m.group(2) else f"{m.group(3)}\\{m.group(4)}"),
                            text)


def md_table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    lines = ["| " + " | ".join(md_escape(h) for h in headers) + " |",
             "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(md_escape(c) for c in row) + " |")
    return "\n".join(lines)


def _json_default(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return str(obj)


def to_json(obj: Any) -> str:
    # allow_nan=False: NaN and Infinity are not JSON, and a report that other tools cannot parse is
    # worse than an error.
    return json.dumps(obj, indent=2, default=_json_default, ensure_ascii=False, allow_nan=False)


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)  # numbers (including negative ones) are data, not formulas
    if isinstance(value, (list, tuple, set, frozenset)):
        text = "; ".join(str(v) for v in (sorted(value, key=str) if isinstance(value, (set, frozenset)) else value))
    elif isinstance(value, dict):
        text = json.dumps(value, default=_json_default, ensure_ascii=False)
    else:
        text = str(value)
    # Neutralise spreadsheet formula injection: names from tenants and inventories end up in these files.
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return text


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fields: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: _cell(row.get(k)) for k in fields})


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")


def parse_formats(value: str, allowed: Sequence[str]) -> list[str]:
    formats = [f.strip().lower() for f in value.split(",") if f.strip()]
    bad = [f for f in formats if f not in allowed]
    if bad:
        raise ValueError(f"unknown format(s) {', '.join(bad)}; choose from {', '.join(allowed)}")
    if not formats:
        raise ValueError(f"no report format given; choose from {', '.join(allowed)}")
    return list(dict.fromkeys(formats))
